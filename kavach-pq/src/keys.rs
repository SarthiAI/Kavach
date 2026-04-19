//! Key management for Kavach PQ.
//!
//! Generates, stores, and rotates post-quantum and classical keypairs
//! using audited RustCrypto implementations:
//!
//! - **ML-DSA-65** (FIPS 204) for post-quantum signatures
//! - **ML-KEM-768** (FIPS 203) for post-quantum key encapsulation
//! - **Ed25519** for classical signatures (hybrid mode)
//! - **X25519** for classical key exchange (hybrid mode)
//!
//! All secret key bytes are zeroized on drop.

use crate::error::{PqError, Result};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use ml_dsa::signature::Keypair as MlDsaKeypair;
use ml_dsa::{
    EncodedVerifyingKey, KeyGen, MlDsa65, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey, B32,
};
use ml_kem::array::Array;
use ml_kem::ml_kem_768::MlKem768;
use ml_kem::{DecapsulationKey, EncapsulationKey, FromSeed, KeyExport, KeySizeUser};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroize;

/// A Kavach keypair containing both PQ and classical keys.
///
/// Used for signing verdicts and establishing encrypted channels.
/// The keypair ID is used for key rotation, services reference
/// keys by ID, so rotating is just adding a new key and retiring the old one.
pub struct KavachKeyPair {
    /// Unique key identifier.
    pub id: String,

    /// When this key was generated.
    pub created_at: DateTime<Utc>,

    /// When this key expires (None = no expiry).
    pub expires_at: Option<DateTime<Utc>>,

    /// ML-DSA-65 signing key, stored as the 32-byte seed (`xi` in FIPS 204).
    pub ml_dsa_signing_key: Vec<u8>,

    /// ML-DSA-65 verifying key, encoded form.
    pub ml_dsa_verifying_key: Vec<u8>,

    /// ML-KEM-768 decapsulation key, encoded (seed) form.
    pub ml_kem_decapsulation_key: Vec<u8>,

    /// ML-KEM-768 encapsulation key, encoded form.
    pub ml_kem_encapsulation_key: Vec<u8>,

    /// Ed25519 signing key, 32-byte seed.
    pub ed25519_signing_key: Vec<u8>,

    /// Ed25519 verifying key, 32-byte compressed Edwards point.
    pub ed25519_verifying_key: Vec<u8>,

    /// X25519 static secret, 32 bytes.
    pub x25519_secret_key: Vec<u8>,

    /// X25519 public key, 32 bytes.
    pub x25519_public_key: Vec<u8>,
}

/// Fill `dst` with cryptographically secure bytes from the OS via getrandom.
fn fill_random(dst: &mut [u8]) -> Result<()> {
    getrandom::fill(dst).map_err(|e| PqError::KeyGeneration(format!("OS RNG failed: {e}")))
}

impl KavachKeyPair {
    /// Generate a new keypair with all PQ and classical keys.
    pub fn generate() -> Result<Self> {
        Self::generate_with_expiry(None)
    }

    /// Generate a keypair that expires after the given duration.
    pub fn generate_with_expiry(lifetime: Option<Duration>) -> Result<Self> {
        let now = Utc::now();

        // ── ML-DSA-65 (FIPS 204 signatures) ──────────────────────────
        // Generate a 32-byte seed xi and derive the signing key from it
        // via FIPS 204's KeyGen_internal (ml_dsa::KeyGen::from_seed).
        let mut dsa_xi_bytes = [0u8; 32];
        fill_random(&mut dsa_xi_bytes)?;
        let dsa_xi = B32::from(dsa_xi_bytes);
        let dsa_kp = <MlDsa65 as KeyGen>::from_seed(&dsa_xi);
        let ml_dsa_verifying_key = MlDsaKeypair::verifying_key(&dsa_kp)
            .encode()
            .as_slice()
            .to_vec();

        // ── ML-KEM-768 (FIPS 203 KEM) ────────────────────────────────
        // Derive both keys deterministically from a 64-byte seed, avoids
        // cross-crate RNG trait version issues and keeps secret storage compact.
        let kem_seed_size =
            <<MlKem768 as FromSeed>::SeedSize as hybrid_array::typenum::Unsigned>::USIZE;
        let mut kem_seed_vec = vec![0u8; kem_seed_size];
        fill_random(&mut kem_seed_vec)?;
        let kem_seed: Array<u8, <MlKem768 as FromSeed>::SeedSize> =
            Array::try_from(kem_seed_vec.as_slice())
                .map_err(|e| PqError::KeyGeneration(format!("KEM seed shape: {e}")))?;
        let (_dk, ek) = <MlKem768 as FromSeed>::from_seed(&kem_seed);
        let ml_kem_decapsulation_key = kem_seed_vec;
        let ml_kem_encapsulation_key = ek.to_bytes().as_slice().to_vec();

        // ── Ed25519 (classical signatures) ───────────────────────────
        let mut ed_seed = [0u8; 32];
        fill_random(&mut ed_seed)?;
        let ed_sk = Ed25519SigningKey::from_bytes(&ed_seed);
        let ed_vk: Ed25519VerifyingKey = ed_sk.verifying_key();

        // ── X25519 (classical DH) ────────────────────────────────────
        let mut x_seed = [0u8; 32];
        fill_random(&mut x_seed)?;
        let x_sk = X25519Secret::from(x_seed);
        let x_pk = X25519PublicKey::from(&x_sk);

        Ok(Self {
            id: format!("kavach-key-{}", Uuid::new_v4()),
            created_at: now,
            expires_at: lifetime.map(|d| now + d),
            ml_dsa_signing_key: dsa_xi_bytes.to_vec(),
            ml_dsa_verifying_key,
            ml_kem_decapsulation_key,
            ml_kem_encapsulation_key,
            ed25519_signing_key: ed_sk.to_bytes().to_vec(),
            ed25519_verifying_key: ed_vk.to_bytes().to_vec(),
            x25519_secret_key: x_sk.to_bytes().to_vec(),
            x25519_public_key: x_pk.to_bytes().to_vec(),
        })
    }

    /// Check if this keypair has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Get the public portion of this keypair (safe to share).
    pub fn public_keys(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            id: self.id.clone(),
            ml_dsa_verifying_key: self.ml_dsa_verifying_key.clone(),
            ml_kem_encapsulation_key: self.ml_kem_encapsulation_key.clone(),
            ed25519_verifying_key: self.ed25519_verifying_key.clone(),
            x25519_public_key: self.x25519_public_key.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

impl Drop for KavachKeyPair {
    fn drop(&mut self) {
        // Securely clear secret keys from memory
        self.ml_dsa_signing_key.zeroize();
        self.ml_kem_decapsulation_key.zeroize();
        self.ed25519_signing_key.zeroize();
        self.x25519_secret_key.zeroize();
    }
}

/// Public keys that can be shared with other services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    pub id: String,
    pub ml_dsa_verifying_key: Vec<u8>,
    pub ml_kem_encapsulation_key: Vec<u8>,
    pub ed25519_verifying_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// In-memory key store with rotation support.
///
/// Stores multiple keypairs indexed by ID. The "active" key is used
/// for signing new verdicts. Old keys are kept for verification of
/// previously-signed verdicts until they expire.
pub struct KeyStore {
    keys: RwLock<HashMap<String, KavachKeyPair>>,
    active_key_id: RwLock<Option<String>>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            active_key_id: RwLock::new(None),
        }
    }

    /// Generate a new keypair and make it the active signing key.
    pub fn generate_and_activate(&self, lifetime: Option<Duration>) -> Result<String> {
        let keypair = KavachKeyPair::generate_with_expiry(lifetime)?;
        let id = keypair.id.clone();

        let mut keys = self.keys.write().unwrap();
        keys.insert(id.clone(), keypair);

        let mut active = self.active_key_id.write().unwrap();
        let old_id = active.replace(id.clone());

        tracing::info!(
            new_key = %id,
            old_key = ?old_id,
            "key rotated"
        );

        Ok(id)
    }

    /// Get the active keypair for signing.
    pub fn active_key(&self) -> Result<String> {
        self.active_key_id
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| PqError::KeyNotFound("no active key".into()))
    }

    /// Get public keys for a specific key ID (for verification).
    pub fn public_keys(&self, key_id: &str) -> Result<PublicKeyBundle> {
        let keys = self.keys.read().unwrap();
        keys.get(key_id)
            .map(|kp| kp.public_keys())
            .ok_or_else(|| PqError::KeyNotFound(key_id.into()))
    }

    /// Remove expired keys.
    pub fn cleanup_expired(&self) -> usize {
        let mut keys = self.keys.write().unwrap();
        let before = keys.len();
        keys.retain(|id, kp| {
            let keep = !kp.is_expired();
            if !keep {
                tracing::info!(key_id = %id, "expired key removed");
            }
            keep
        });
        before - keys.len()
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Internal loaders (typed reconstruction from stored bytes) ─────────

/// Reconstruct an ML-DSA-65 verifying key from its encoded form.
pub(crate) fn load_ml_dsa_verifying_key(bytes: &[u8]) -> Result<MlDsaVerifyingKey<MlDsa65>> {
    let encoded: EncodedVerifyingKey<MlDsa65> = Array::try_from(bytes)
        .map_err(|e| PqError::KeyGeneration(format!("invalid ML-DSA VK bytes: {e}")))?;
    Ok(MlDsaVerifyingKey::<MlDsa65>::decode(&encoded))
}

/// Reconstruct an ML-DSA-65 signing key from its 32-byte seed.
pub(crate) fn load_ml_dsa_signing_key(seed_bytes: &[u8]) -> Result<MlDsaSigningKey<MlDsa65>> {
    if seed_bytes.len() != 32 {
        return Err(PqError::KeyGeneration(format!(
            "ML-DSA seed must be 32 bytes, got {}",
            seed_bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(seed_bytes);
    Ok(<MlDsa65 as KeyGen>::from_seed(&B32::from(arr)))
}

/// Reconstruct an ML-KEM-768 encapsulation key from its encoded form.
pub(crate) fn load_ml_kem_encapsulation_key(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768>> {
    let key: Array<u8, <EncapsulationKey<MlKem768> as KeySizeUser>::KeySize> =
        Array::try_from(bytes)
            .map_err(|e| PqError::KeyGeneration(format!("invalid ML-KEM EK bytes: {e}")))?;
    EncapsulationKey::<MlKem768>::new(&key)
        .map_err(|e| PqError::KeyGeneration(format!("ML-KEM EK init: {e}")))
}

/// Reconstruct an ML-KEM-768 decapsulation key from its 64-byte seed.
pub(crate) fn load_ml_kem_decapsulation_key(bytes: &[u8]) -> Result<DecapsulationKey<MlKem768>> {
    let seed: Array<u8, <MlKem768 as FromSeed>::SeedSize> = Array::try_from(bytes)
        .map_err(|e| PqError::KeyGeneration(format!("invalid ML-KEM DK seed: {e}")))?;
    let (dk, _ek) = <MlKem768 as FromSeed>::from_seed(&seed);
    Ok(dk)
}
