//! Secure channel between Kavach-protected services.
//!
//! Combines everything in kavach-pq into a single high-level API:
//! hybrid-encrypted transport (ML-KEM-768 + X25519 → ChaCha20-Poly1305),
//! hybrid signatures (ML-DSA-65 + Ed25519), and replay protection over
//! a per-channel nonce cache.
//!
//! # Two flows
//!
//! - [`SecureChannel::send_verdict`] / [`SecureChannel::receive_verdict`] —
//!   the original signed-verdict transport with action-name binding.
//! - [`SecureChannel::send_signed`] / [`SecureChannel::receive_signed`] —
//!   signed arbitrary byte payloads with caller-provided context binding.
//!   This is what the Python/Node SDKs expose since the SDK `Verdict` type
//!   is language-native; callers serialize their own payloads.
//! - [`SecureChannel::send_data`] / [`SecureChannel::receive_data`] —
//!   encryption-only transport (no signing, no replay protection).
//!
//! # Example
//!
//! ```ignore
//! use kavach_pq::{KavachKeyPair, SecureChannel};
//!
//! let gate_kp = KavachKeyPair::generate()?;
//! let handler_kp = KavachKeyPair::generate()?;
//!
//! // Each side establishes against the other's public bundle.
//! let gate_channel = SecureChannel::establish_from_bundle(&gate_kp, &handler_kp.public_keys());
//! let handler_channel = SecureChannel::establish_from_bundle(&handler_kp, &gate_kp.public_keys());
//!
//! let sealed = gate_channel.send_signed(b"{\"kind\":\"permit\"}", "issue_refund", "eval-123")?;
//! let plaintext = handler_channel.receive_signed(&sealed, "issue_refund")?;
//! ```

use crate::encrypt::{Decryptor, EncryptedPayload, Encryptor};
use crate::error::{PqError, Result};
use crate::hybrid::HybridKeyPair;
use crate::keys::{KavachKeyPair, PublicKeyBundle};
use crate::sign::{SignedPayload, Signer, Verifier};
use crate::verdict::{SignedVerdict, VerdictSigner, VerdictVerifier};
use kavach_core::verdict::Verdict;
use serde::{Deserialize, Serialize};

/// A sealed verdict: signed + encrypted for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedVerdict {
    /// The encrypted payload containing the signed verdict.
    pub encrypted: EncryptedPayload,

    /// Verdict kind (unencrypted, for routing without decryption).
    pub verdict_kind: String,
}

/// A signed byte payload bound to a caller-defined context id.
///
/// Produced by [`SecureChannel::send_signed`] (after encryption) and
/// validated by [`SecureChannel::receive_signed`]. The `context_id`
/// travels inside the encrypted envelope — it cannot be tampered with
/// on the wire — and is checked against the receiver's expected context
/// to prevent cross-context replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBytes {
    /// The signed byte payload.
    pub signed_payload: SignedPayload,

    /// The context the sender bound the message to (e.g. an action name).
    pub context_id: String,

    /// Correlation ID (e.g. an evaluation UUID) for audit/log joining.
    pub correlation_id: String,
}

/// An end-to-end secure channel between two Kavach services.
///
/// Provides:
/// - Hybrid encryption (ML-KEM-768 + X25519 → ChaCha20-Poly1305)
/// - Hybrid signatures (ML-DSA-65 + Ed25519)
/// - Replay protection via a per-channel nonce cache (shared across
///   verdict and bytes flows, so nothing can be cross-replayed)
pub struct SecureChannel {
    /// Signs outbound data.
    local_signer: VerdictSigner,

    /// Verifies inbound data from the remote party.
    remote_verifier: VerdictVerifier,

    /// Encrypts data for the remote party.
    remote_encryptor: Encryptor,

    /// Decrypts data from the remote party.
    local_decryptor: Decryptor,

    /// Local key id (signer + decryptor recipient).
    local_key_id: String,

    /// Remote key id (verifier + encryptor recipient).
    remote_key_id: String,
}

impl SecureChannel {
    /// Establish a secure channel between local and remote services.
    ///
    /// **Deprecated ergonomics:** this takes a full `HybridKeyPair` for the
    /// remote side even though only the public half is needed. Prefer
    /// [`SecureChannel::establish_from_bundle`] in new code — it accepts a
    /// [`PublicKeyBundle`] instead.
    pub fn establish(local: &HybridKeyPair, remote: &HybridKeyPair) -> Self {
        Self {
            local_signer: VerdictSigner::new(local.signer()),
            remote_verifier: VerdictVerifier::new(remote.verifier()),
            remote_encryptor: remote.encryptor(),
            local_decryptor: local.decryptor(),
            local_key_id: local.key_id().to_string(),
            remote_key_id: remote.key_id().to_string(),
        }
    }

    /// Establish a channel from the local keypair (secret side) and the
    /// remote party's public-key bundle. This is the recommended entry
    /// point — the remote's secret keys are not required and should not
    /// be asked for.
    ///
    /// Always hybrid (ML-DSA-65 + Ed25519 + ML-KEM-768 + X25519).
    pub fn establish_from_bundle(local: &KavachKeyPair, remote: &PublicKeyBundle) -> Self {
        let local_signer = VerdictSigner::new(Signer::from_keypair(local, true));
        let remote_verifier = VerdictVerifier::new(Verifier::from_bundle(remote, true));
        let remote_encryptor =
            Encryptor::new(remote.ml_kem_encapsulation_key.clone(), remote.id.clone())
                .with_x25519(remote.x25519_public_key.clone());
        let local_decryptor =
            Decryptor::new(local.ml_kem_decapsulation_key.clone(), local.id.clone())
                .with_x25519(local.x25519_secret_key.clone());

        Self {
            local_signer,
            remote_verifier,
            remote_encryptor,
            local_decryptor,
            local_key_id: local.id.clone(),
            remote_key_id: remote.id.clone(),
        }
    }

    /// Key id of the local (secret-holding) side.
    pub fn local_key_id(&self) -> &str {
        &self.local_key_id
    }

    /// Key id of the remote (public-key) side this channel targets.
    pub fn remote_key_id(&self) -> &str {
        &self.remote_key_id
    }

    /// Send a verdict: sign it, encrypt it, seal it.
    ///
    /// The sealed verdict can travel over any untrusted transport
    /// (HTTP, message queue, etc.) without risk of tampering.
    pub fn send_verdict(
        &self,
        verdict: &Verdict,
        action_name: &str,
        evaluation_id: &str,
    ) -> Result<SealedVerdict> {
        // 1. Sign the verdict
        let signed = self
            .local_signer
            .sign(verdict, action_name, evaluation_id)?;

        let verdict_kind = signed.verdict_kind.clone();

        // 2. Encrypt the signed verdict
        let signed_bytes =
            serde_json::to_vec(&signed).map_err(|e| PqError::Serialization(e.to_string()))?;
        let encrypted = self.remote_encryptor.encrypt(&signed_bytes)?;

        Ok(SealedVerdict {
            encrypted,
            verdict_kind,
        })
    }

    /// Receive a verdict: decrypt it, verify the signature, check for replay.
    ///
    /// Returns the verified verdict if everything checks out.
    /// Rejects if:
    /// - Decryption fails (wrong recipient or corrupted)
    /// - Signature is invalid (tampered)
    /// - Nonce was seen before (replay attack)
    /// - Action name doesn't match (cross-action replay)
    pub fn receive_verdict(
        &self,
        sealed: &SealedVerdict,
        expected_action: &str,
    ) -> Result<Verdict> {
        // 1. Decrypt
        let decrypted = self.local_decryptor.decrypt(&sealed.encrypted)?;

        // 2. Deserialize the signed verdict
        let signed: SignedVerdict = serde_json::from_slice(&decrypted)
            .map_err(|e| PqError::Serialization(e.to_string()))?;

        // 3. Verify signature + replay protection + action match
        self.remote_verifier.verify(&signed, expected_action)
    }

    /// Send a signed arbitrary byte payload with a caller-defined context.
    ///
    /// This is the SDK-friendly cousin of [`send_verdict`]: instead of
    /// taking a typed `Verdict`, it takes raw bytes (the caller serializes
    /// their own payload). The `context_id` (typically an action / tool
    /// name) is bound into the signature so that the receiver's
    /// `expected_context_id` check rejects cross-context replay.
    pub fn send_signed(
        &self,
        data: &[u8],
        context_id: &str,
        correlation_id: &str,
    ) -> Result<EncryptedPayload> {
        let signed_payload = self.local_signer.signer().sign(data)?;
        let wrapper = SignedBytes {
            signed_payload,
            context_id: context_id.to_string(),
            correlation_id: correlation_id.to_string(),
        };
        let wrapper_bytes =
            serde_json::to_vec(&wrapper).map_err(|e| PqError::Serialization(e.to_string()))?;
        self.remote_encryptor.encrypt(&wrapper_bytes)
    }

    /// Receive a signed byte payload: decrypt, verify signature + replay +
    /// context binding, return the plaintext bytes.
    ///
    /// Rejects on any failure (decrypt, signature, replay, context mismatch).
    pub fn receive_signed(
        &self,
        sealed: &EncryptedPayload,
        expected_context_id: &str,
    ) -> Result<Vec<u8>> {
        let decrypted = self.local_decryptor.decrypt(sealed)?;
        let wrapper: SignedBytes = serde_json::from_slice(&decrypted)
            .map_err(|e| PqError::Serialization(e.to_string()))?;
        self.remote_verifier.verify_bytes(
            &wrapper.signed_payload,
            &wrapper.context_id,
            expected_context_id,
        )
    }

    /// Send arbitrary data without signing — encryption only.
    pub fn send_data(&self, data: &[u8]) -> Result<EncryptedPayload> {
        self.remote_encryptor.encrypt(data)
    }

    /// Receive arbitrary data without signature verification — decryption only.
    pub fn receive_data(&self, encrypted: &EncryptedPayload) -> Result<Vec<u8>> {
        self.local_decryptor.decrypt(encrypted)
    }
}
