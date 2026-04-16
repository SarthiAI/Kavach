//! Post-quantum digital signatures using ML-DSA-65 (FIPS 204).
//!
//! Signs arbitrary byte payloads. Used by the verdict and audit modules
//! to cryptographically protect gate decisions and log entries.
//!
//! In hybrid mode, payloads are signed with both ML-DSA and Ed25519.
//! Verification requires **both** signatures to be valid — an attacker
//! must break both post-quantum and classical signing to forge a verdict.

use crate::error::{PqError, Result};
use crate::keys::{
    load_ml_dsa_signing_key, load_ml_dsa_verifying_key, KavachKeyPair, PublicKeyBundle,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    Verifier as Ed25519Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use hybrid_array::Array;
use ml_dsa::signature::{Signer as MlDsaSigner, Verifier as MlDsaVerifier};
use ml_dsa::{EncodedSignature, MlDsa65, Signature as MlDsaSignature};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A signed payload — the original data plus its cryptographic signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload {
    /// The original data that was signed.
    pub data: Vec<u8>,

    /// ML-DSA-65 signature over the data (plus nonce + timestamp).
    pub ml_dsa_signature: Vec<u8>,

    /// Ed25519 signature (present in hybrid mode).
    pub ed25519_signature: Option<Vec<u8>>,

    /// ID of the key used to sign.
    pub key_id: String,

    /// When the signature was created.
    pub signed_at: DateTime<Utc>,

    /// Nonce to prevent replay attacks.
    pub nonce: String,
}

/// Compose the signed message: `data || nonce_bytes || timestamp_rfc3339`.
fn compose_message(data: &[u8], nonce: &str, signed_at: DateTime<Utc>) -> Vec<u8> {
    let ts = signed_at.to_rfc3339();
    let mut message = Vec::with_capacity(data.len() + nonce.len() + ts.len());
    message.extend_from_slice(data);
    message.extend_from_slice(nonce.as_bytes());
    message.extend_from_slice(ts.as_bytes());
    message
}

/// Signs payloads with ML-DSA-65 (and optionally Ed25519 in hybrid mode).
pub struct Signer {
    /// ML-DSA-65 signing key bytes (32-byte seed `xi`).
    ml_dsa_key: Vec<u8>,

    /// Ed25519 signing key bytes (32-byte seed, for hybrid mode).
    ed25519_key: Option<Vec<u8>>,

    /// Key ID for this signer.
    key_id: String,

    /// Whether to produce hybrid (ML-DSA + Ed25519) signatures.
    hybrid: bool,
}

impl Signer {
    /// Create a PQ-only signer.
    pub fn new(ml_dsa_key: Vec<u8>, key_id: String) -> Self {
        Self {
            ml_dsa_key,
            ed25519_key: None,
            key_id,
            hybrid: false,
        }
    }

    /// Create a hybrid signer (ML-DSA + Ed25519).
    pub fn hybrid(ml_dsa_key: Vec<u8>, ed25519_key: Vec<u8>, key_id: String) -> Self {
        Self {
            ml_dsa_key,
            ed25519_key: Some(ed25519_key),
            key_id,
            hybrid: true,
        }
    }

    /// Build a signer from a full [`KavachKeyPair`]. `hybrid=true` includes
    /// the Ed25519 seed from the keypair; `hybrid=false` uses ML-DSA-65 only.
    pub fn from_keypair(kp: &KavachKeyPair, hybrid: bool) -> Self {
        if hybrid {
            Self::hybrid(
                kp.ml_dsa_signing_key.clone(),
                kp.ed25519_signing_key.clone(),
                kp.id.clone(),
            )
        } else {
            Self::new(kp.ml_dsa_signing_key.clone(), kp.id.clone())
        }
    }

    /// Whether this signer produces hybrid (ML-DSA-65 + Ed25519) signatures.
    pub fn is_hybrid(&self) -> bool {
        self.hybrid
    }

    /// Key ID stamped on every signed payload.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Sign a byte payload.
    pub fn sign(&self, data: &[u8]) -> Result<SignedPayload> {
        let nonce = Uuid::new_v4().to_string();
        let signed_at = Utc::now();
        let message = compose_message(data, &nonce, signed_at);

        let ml_dsa_signature = self.ml_dsa_sign(&message)?;
        let ed25519_signature = if self.hybrid {
            Some(self.ed25519_sign(&message)?)
        } else {
            None
        };

        Ok(SignedPayload {
            data: data.to_vec(),
            ml_dsa_signature,
            ed25519_signature,
            key_id: self.key_id.clone(),
            signed_at,
            nonce,
        })
    }

    fn ml_dsa_sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = load_ml_dsa_signing_key(&self.ml_dsa_key)?;
        let sig: MlDsaSignature<MlDsa65> = sk
            .try_sign(message)
            .map_err(|e| PqError::Signing(format!("ML-DSA-65: {e}")))?;
        Ok(sig.encode().as_slice().to_vec())
    }

    fn ed25519_sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let key_bytes = self
            .ed25519_key
            .as_ref()
            .ok_or_else(|| PqError::Signing("hybrid signer missing Ed25519 key".into()))?;
        if key_bytes.len() != 32 {
            return Err(PqError::Signing(format!(
                "Ed25519 seed must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(key_bytes);
        let sk = Ed25519SigningKey::from_bytes(&seed);
        let sig: Ed25519Signature = sk.sign(message);
        Ok(sig.to_bytes().to_vec())
    }
}

/// Verifies ML-DSA-65 (and optionally Ed25519) signatures.
pub struct Verifier {
    /// ML-DSA-65 verifying key — encoded form.
    ml_dsa_key: Vec<u8>,

    /// Ed25519 verifying key (for hybrid mode).
    ed25519_key: Option<Vec<u8>>,

    /// Whether to require hybrid verification.
    hybrid: bool,
}

impl Verifier {
    /// Create a PQ-only verifier.
    pub fn new(ml_dsa_key: Vec<u8>) -> Self {
        Self {
            ml_dsa_key,
            ed25519_key: None,
            hybrid: false,
        }
    }

    /// Create a hybrid verifier.
    pub fn hybrid(ml_dsa_key: Vec<u8>, ed25519_key: Vec<u8>) -> Self {
        Self {
            ml_dsa_key,
            ed25519_key: Some(ed25519_key),
            hybrid: true,
        }
    }

    /// Build a verifier from a [`PublicKeyBundle`]. `hybrid=true` enforces
    /// ML-DSA-65 + Ed25519; `hybrid=false` enforces ML-DSA-65 only.
    pub fn from_bundle(bundle: &PublicKeyBundle, hybrid: bool) -> Self {
        if hybrid {
            Self::hybrid(
                bundle.ml_dsa_verifying_key.clone(),
                bundle.ed25519_verifying_key.clone(),
            )
        } else {
            Self::new(bundle.ml_dsa_verifying_key.clone())
        }
    }

    /// Whether this verifier requires hybrid (ML-DSA-65 + Ed25519) signatures.
    pub fn is_hybrid(&self) -> bool {
        self.hybrid
    }

    /// Verify a signed payload.
    ///
    /// In hybrid mode, **both** signatures must be valid. An attacker must
    /// break both ML-DSA-65 and Ed25519 to forge a verdict.
    pub fn verify(&self, payload: &SignedPayload) -> Result<()> {
        let message = compose_message(&payload.data, &payload.nonce, payload.signed_at);

        self.ml_dsa_verify(&message, &payload.ml_dsa_signature)?;

        if self.hybrid {
            let ed_sig = payload.ed25519_signature.as_ref().ok_or_else(|| {
                PqError::VerificationFailed("hybrid mode requires Ed25519 signature".into())
            })?;
            self.ed25519_verify(&message, ed_sig)?;
        }

        Ok(())
    }

    fn ml_dsa_verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let vk = load_ml_dsa_verifying_key(&self.ml_dsa_key)?;
        let encoded: EncodedSignature<MlDsa65> = Array::try_from(signature).map_err(|e| {
            PqError::VerificationFailed(format!("invalid ML-DSA signature encoding: {e}"))
        })?;
        let sig = MlDsaSignature::<MlDsa65>::decode(&encoded)
            .ok_or_else(|| PqError::VerificationFailed("ML-DSA signature decode failed".into()))?;
        vk.verify(message, &sig)
            .map_err(|e| PqError::VerificationFailed(format!("ML-DSA: {e}")))
    }

    fn ed25519_verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let vk_bytes = self.ed25519_key.as_ref().ok_or_else(|| {
            PqError::VerificationFailed("hybrid verifier missing Ed25519 key".into())
        })?;
        if vk_bytes.len() != 32 {
            return Err(PqError::VerificationFailed(format!(
                "Ed25519 verifying key must be 32 bytes, got {}",
                vk_bytes.len()
            )));
        }
        let mut vk_arr = [0u8; 32];
        vk_arr.copy_from_slice(vk_bytes);
        let vk = Ed25519VerifyingKey::from_bytes(&vk_arr)
            .map_err(|e| PqError::VerificationFailed(format!("Ed25519 VK: {e}")))?;
        if signature.len() != 64 {
            return Err(PqError::VerificationFailed(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            )));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(signature);
        let sig = Ed25519Signature::from_bytes(&sig_arr);
        vk.verify(message, &sig)
            .map_err(|e| PqError::VerificationFailed(format!("Ed25519: {e}")))
    }
}
