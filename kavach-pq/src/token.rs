//! Post-quantum signer for [`kavach_core::PermitToken`].
//!
//! Wraps the existing ML-DSA-65 (+ optional Ed25519) primitives from [`crate::sign`]
//! behind the [`TokenSigner`] trait that `kavach-core` uses. The gate calls
//! `sign()` before returning a `Permit` verdict; downstream services that
//! receive the token can call `verify()` to confirm the token came from the
//! gate and wasn't tampered with in transit.
//!
//! # Wire format
//!
//! The signature bytes stored in `PermitToken::signature` are a JSON-encoded
//! [`SignedTokenEnvelope`] containing:
//!
//! - `key_id` — identifier of the keypair that produced the signature (so a
//!   verifier can select the right verifying key from a key store).
//! - `algorithm` — `"ml-dsa-65"` or `"ml-dsa-65+ed25519"`.
//! - `ml_dsa_signature` — raw ML-DSA-65 signature over `PermitToken::canonical_bytes()`.
//! - `ed25519_signature` — raw 64-byte Ed25519 signature over the same bytes, in hybrid mode.
//!
//! Signing is over [`kavach_core::PermitToken::canonical_bytes`], which is
//! a stable concatenation of the token_id + evaluation_id + issued_at +
//! expires_at + action_name. It deliberately excludes `signature` itself,
//! so producing and verifying can agree on the message without needing the
//! signature to be stripped first.

use crate::directory::{KeyDirectoryError, PublicKeyDirectory};
use crate::error::PqError;
use crate::keys::{load_ml_dsa_signing_key, load_ml_dsa_verifying_key};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    Verifier as Ed25519Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use hybrid_array::Array;
use kavach_core::{KavachError, PermitToken, TokenSigner};
use ml_dsa::signature::{Signer as MlDsaSigner, Verifier as MlDsaVerifier};
use ml_dsa::{EncodedSignature, MlDsa65, Signature as MlDsaSignature};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// JSON-encoded envelope placed into `PermitToken::signature`.
///
/// Serialized form is self-describing so a verifier can decide what to check
/// (PQ-only vs hybrid) without out-of-band config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTokenEnvelope {
    /// ID of the Kavach keypair that produced this signature.
    pub key_id: String,

    /// Algorithm identifier — `"ml-dsa-65"` or `"ml-dsa-65+ed25519"`.
    pub algorithm: String,

    /// Raw ML-DSA-65 signature bytes over `PermitToken::canonical_bytes()`.
    pub ml_dsa_signature: Vec<u8>,

    /// Raw 64-byte Ed25519 signature (hybrid mode only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ed25519_signature: Option<Vec<u8>>,
}

const ALG_PQ_ONLY: &str = "ml-dsa-65";
const ALG_HYBRID: &str = "ml-dsa-65+ed25519";

/// Signs and verifies permit tokens with ML-DSA-65, optionally plus Ed25519.
///
/// In **hybrid mode**, verification requires *both* signatures to be valid —
/// an attacker must break both ML-DSA and Ed25519 to forge a token.
pub struct PqTokenSigner {
    /// ML-DSA-65 signing key (32-byte seed `xi`).
    ml_dsa_signing_key: Vec<u8>,

    /// ML-DSA-65 verifying key (encoded form).
    ml_dsa_verifying_key: Vec<u8>,

    /// Ed25519 signing key (32-byte seed) — `Some` iff hybrid mode.
    ed25519_signing_key: Option<Vec<u8>>,

    /// Ed25519 verifying key (32 bytes) — `Some` iff hybrid mode.
    ed25519_verifying_key: Option<Vec<u8>>,

    /// Key ID stamped into every envelope.
    key_id: String,

    /// Whether to produce (and require, on verify) a hybrid signature.
    hybrid: bool,
}

impl PqTokenSigner {
    /// Create a PQ-only token signer (ML-DSA-65 only).
    pub fn new(ml_dsa_signing_key: Vec<u8>, ml_dsa_verifying_key: Vec<u8>, key_id: String) -> Self {
        Self {
            ml_dsa_signing_key,
            ml_dsa_verifying_key,
            ed25519_signing_key: None,
            ed25519_verifying_key: None,
            key_id,
            hybrid: false,
        }
    }

    /// Create a hybrid (ML-DSA-65 + Ed25519) token signer.
    pub fn hybrid(
        ml_dsa_signing_key: Vec<u8>,
        ml_dsa_verifying_key: Vec<u8>,
        ed25519_signing_key: Vec<u8>,
        ed25519_verifying_key: Vec<u8>,
        key_id: String,
    ) -> Self {
        Self {
            ml_dsa_signing_key,
            ml_dsa_verifying_key,
            ed25519_signing_key: Some(ed25519_signing_key),
            ed25519_verifying_key: Some(ed25519_verifying_key),
            key_id,
            hybrid: true,
        }
    }

    /// Build a PQ-only signer from a freshly-generated [`crate::KavachKeyPair`].
    pub fn from_keypair_pq_only(kp: &crate::KavachKeyPair) -> Self {
        Self::new(
            kp.ml_dsa_signing_key.clone(),
            kp.ml_dsa_verifying_key.clone(),
            kp.id.clone(),
        )
    }

    /// Build a hybrid signer from a freshly-generated [`crate::KavachKeyPair`].
    pub fn from_keypair_hybrid(kp: &crate::KavachKeyPair) -> Self {
        Self::hybrid(
            kp.ml_dsa_signing_key.clone(),
            kp.ml_dsa_verifying_key.clone(),
            kp.ed25519_signing_key.clone(),
            kp.ed25519_verifying_key.clone(),
            kp.id.clone(),
        )
    }

    /// Sign `msg` with ML-DSA-65, returning the raw signature bytes.
    fn ml_dsa_sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, PqError> {
        let sk = load_ml_dsa_signing_key(&self.ml_dsa_signing_key)?;
        let sig: MlDsaSignature<MlDsa65> = sk
            .try_sign(msg)
            .map_err(|e| PqError::Signing(format!("ML-DSA-65: {e}")))?;
        Ok(sig.encode().as_slice().to_vec())
    }

    /// Sign `msg` with Ed25519 (32-byte seed → 64-byte sig).
    fn ed25519_sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, PqError> {
        let seed = self
            .ed25519_signing_key
            .as_ref()
            .ok_or_else(|| PqError::Signing("hybrid signer missing Ed25519 key".into()))?;
        if seed.len() != 32 {
            return Err(PqError::Signing(format!(
                "Ed25519 seed must be 32 bytes, got {}",
                seed.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        let sk = Ed25519SigningKey::from_bytes(&arr);
        let sig: Ed25519Signature = sk.sign(msg);
        Ok(sig.to_bytes().to_vec())
    }

    /// Verify a raw ML-DSA signature against `msg`.
    fn ml_dsa_verify_raw(&self, msg: &[u8], signature: &[u8]) -> Result<(), PqError> {
        let vk = load_ml_dsa_verifying_key(&self.ml_dsa_verifying_key)?;
        let encoded: EncodedSignature<MlDsa65> = Array::try_from(signature)
            .map_err(|e| PqError::VerificationFailed(format!("ML-DSA sig encoding: {e}")))?;
        let sig = MlDsaSignature::<MlDsa65>::decode(&encoded)
            .ok_or_else(|| PqError::VerificationFailed("ML-DSA signature decode failed".into()))?;
        vk.verify(msg, &sig)
            .map_err(|e| PqError::VerificationFailed(format!("ML-DSA-65: {e}")))
    }

    /// Verify a raw Ed25519 signature against `msg`.
    fn ed25519_verify_raw(&self, msg: &[u8], signature: &[u8]) -> Result<(), PqError> {
        let vk_bytes = self.ed25519_verifying_key.as_ref().ok_or_else(|| {
            PqError::VerificationFailed("hybrid verifier missing Ed25519 key".into())
        })?;
        if vk_bytes.len() != 32 {
            return Err(PqError::VerificationFailed(format!(
                "Ed25519 VK must be 32 bytes, got {}",
                vk_bytes.len()
            )));
        }
        let mut vk_arr = [0u8; 32];
        vk_arr.copy_from_slice(vk_bytes);
        let vk = Ed25519VerifyingKey::from_bytes(&vk_arr)
            .map_err(|e| PqError::VerificationFailed(format!("Ed25519 VK: {e}")))?;
        if signature.len() != 64 {
            return Err(PqError::VerificationFailed(format!(
                "Ed25519 sig must be 64 bytes, got {}",
                signature.len()
            )));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(signature);
        let sig = Ed25519Signature::from_bytes(&sig_arr);
        vk.verify(msg, &sig)
            .map_err(|e| PqError::VerificationFailed(format!("Ed25519: {e}")))
    }
}

/// Helper: turn a PqError into a KavachError::Serialization so it can cross
/// the trait boundary (kavach-core doesn't depend on kavach-pq's error type).
fn to_core_err(e: PqError) -> KavachError {
    KavachError::Serialization(e.to_string())
}

impl TokenSigner for PqTokenSigner {
    fn sign(&self, token: &PermitToken) -> Result<Vec<u8>, KavachError> {
        let message = token.canonical_bytes();
        let ml_dsa_signature = self.ml_dsa_sign_raw(&message).map_err(to_core_err)?;
        let ed25519_signature = if self.hybrid {
            Some(self.ed25519_sign_raw(&message).map_err(to_core_err)?)
        } else {
            None
        };
        let envelope = SignedTokenEnvelope {
            key_id: self.key_id.clone(),
            algorithm: if self.hybrid { ALG_HYBRID } else { ALG_PQ_ONLY }.to_string(),
            ml_dsa_signature,
            ed25519_signature,
        };
        serde_json::to_vec(&envelope)
            .map_err(|e| KavachError::Serialization(format!("token envelope: {e}")))
    }

    fn verify(&self, token: &PermitToken, signature: &[u8]) -> Result<(), KavachError> {
        let envelope: SignedTokenEnvelope = serde_json::from_slice(signature)
            .map_err(|e| KavachError::Serialization(format!("token envelope parse: {e}")))?;

        // If the verifier is configured for hybrid but the token only carries
        // a PQ-only algorithm, reject — do not silently downgrade security.
        let envelope_is_hybrid = envelope.algorithm == ALG_HYBRID;
        if self.hybrid && !envelope_is_hybrid {
            return Err(KavachError::Serialization(format!(
                "hybrid verifier rejects non-hybrid algorithm '{}'",
                envelope.algorithm
            )));
        }
        if !self.hybrid && envelope.algorithm != ALG_PQ_ONLY {
            return Err(KavachError::Serialization(format!(
                "PQ-only verifier expected '{ALG_PQ_ONLY}', got '{}'",
                envelope.algorithm
            )));
        }

        let message = token.canonical_bytes();

        self.ml_dsa_verify_raw(&message, &envelope.ml_dsa_signature)
            .map_err(to_core_err)?;

        if self.hybrid {
            let ed_sig = envelope.ed25519_signature.as_ref().ok_or_else(|| {
                KavachError::Serialization("hybrid envelope missing Ed25519 signature".into())
            })?;
            self.ed25519_verify_raw(&message, ed_sig)
                .map_err(to_core_err)?;
        }

        Ok(())
    }
}

// ──────────────── Directory-backed verifier ────────────────

/// Verifies [`PermitToken`]s by looking up the matching public key in a
/// [`PublicKeyDirectory`] based on the `key_id` stamped into each envelope.
///
/// Use this on downstream services that receive tokens signed by many
/// rotating keys. The verifier never holds a private key — it only holds a
/// handle to the directory.
///
/// # Hybrid mode
///
/// The `hybrid` flag must match what the signer used. A hybrid verifier
/// rejects PQ-only envelopes (downgrade-attack guard), and a PQ-only
/// verifier rejects hybrid envelopes (wrong algorithm). This matches
/// [`PqTokenSigner::verify`] semantics.
///
/// # Errors
///
/// All errors reduce to refusal at the caller. Fail-closed: if the
/// directory says the key is not present, the token is rejected.
pub struct DirectoryTokenVerifier {
    directory: Arc<dyn PublicKeyDirectory>,
    hybrid: bool,
}

/// Errors returned by [`DirectoryTokenVerifier::verify`].
#[derive(Debug, thiserror::Error)]
pub enum DirectoryVerifyError {
    /// The envelope could not be parsed.
    #[error("token envelope parse: {0}")]
    EnvelopeParse(String),

    /// The envelope's algorithm did not match the verifier's configured mode.
    #[error("algorithm mismatch: {0}")]
    AlgorithmMismatch(String),

    /// The directory couldn't supply the key named in the envelope.
    #[error(transparent)]
    Directory(#[from] KeyDirectoryError),

    /// The signature did not verify against the looked-up key.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
}

impl DirectoryTokenVerifier {
    /// Build a PQ-only verifier (ML-DSA-65). Rejects hybrid envelopes.
    pub fn pq_only(directory: Arc<dyn PublicKeyDirectory>) -> Self {
        Self {
            directory,
            hybrid: false,
        }
    }

    /// Build a hybrid verifier (ML-DSA-65 + Ed25519). Rejects PQ-only
    /// envelopes so an attacker can't strip the Ed25519 signature to
    /// force a downgrade.
    pub fn hybrid(directory: Arc<dyn PublicKeyDirectory>) -> Self {
        Self {
            directory,
            hybrid: true,
        }
    }

    /// Verify `token` against `signature` using a key looked up from the
    /// directory by `key_id`.
    pub async fn verify(
        &self,
        token: &PermitToken,
        signature: &[u8],
    ) -> Result<(), DirectoryVerifyError> {
        let envelope: SignedTokenEnvelope = serde_json::from_slice(signature)
            .map_err(|e| DirectoryVerifyError::EnvelopeParse(e.to_string()))?;

        // Algorithm guard — match PqTokenSigner::verify exactly to avoid
        // downgrade attacks.
        let envelope_is_hybrid = envelope.algorithm == ALG_HYBRID;
        if self.hybrid && !envelope_is_hybrid {
            return Err(DirectoryVerifyError::AlgorithmMismatch(format!(
                "hybrid verifier rejects non-hybrid algorithm '{}'",
                envelope.algorithm
            )));
        }
        if !self.hybrid && envelope.algorithm != ALG_PQ_ONLY {
            return Err(DirectoryVerifyError::AlgorithmMismatch(format!(
                "PQ-only verifier expected '{ALG_PQ_ONLY}', got '{}'",
                envelope.algorithm
            )));
        }

        let bundle = self.directory.fetch(&envelope.key_id).await?;
        let message = token.canonical_bytes();

        verify_ml_dsa_with_vk(
            &bundle.ml_dsa_verifying_key,
            &message,
            &envelope.ml_dsa_signature,
        )
        .map_err(|e| DirectoryVerifyError::SignatureInvalid(format!("ML-DSA-65: {e}")))?;

        if self.hybrid {
            let ed_sig = envelope.ed25519_signature.as_ref().ok_or_else(|| {
                DirectoryVerifyError::SignatureInvalid(
                    "hybrid envelope missing Ed25519 signature".into(),
                )
            })?;
            verify_ed25519_with_vk(&bundle.ed25519_verifying_key, &message, ed_sig)
                .map_err(|e| DirectoryVerifyError::SignatureInvalid(format!("Ed25519: {e}")))?;
        }

        Ok(())
    }
}

fn verify_ml_dsa_with_vk(vk_bytes: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), PqError> {
    let vk = load_ml_dsa_verifying_key(vk_bytes)?;
    let encoded: EncodedSignature<MlDsa65> = Array::try_from(signature)
        .map_err(|e| PqError::VerificationFailed(format!("ML-DSA sig encoding: {e}")))?;
    let sig = MlDsaSignature::<MlDsa65>::decode(&encoded)
        .ok_or_else(|| PqError::VerificationFailed("ML-DSA signature decode failed".into()))?;
    vk.verify(msg, &sig)
        .map_err(|e| PqError::VerificationFailed(format!("ML-DSA-65: {e}")))
}

fn verify_ed25519_with_vk(vk_bytes: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), PqError> {
    if vk_bytes.len() != 32 {
        return Err(PqError::VerificationFailed(format!(
            "Ed25519 VK must be 32 bytes, got {}",
            vk_bytes.len()
        )));
    }
    let mut vk_arr = [0u8; 32];
    vk_arr.copy_from_slice(vk_bytes);
    let vk = Ed25519VerifyingKey::from_bytes(&vk_arr)
        .map_err(|e| PqError::VerificationFailed(format!("Ed25519 VK: {e}")))?;
    if signature.len() != 64 {
        return Err(PqError::VerificationFailed(format!(
            "Ed25519 sig must be 64 bytes, got {}",
            signature.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature);
    let sig = Ed25519Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig)
        .map_err(|e| PqError::VerificationFailed(format!("Ed25519: {e}")))
}
