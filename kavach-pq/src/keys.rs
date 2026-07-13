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
    EncodedVerifyingKey, MlDsa65, SigningKey as MlDsaSigningKey,
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
        // via FIPS 204's KeyGen_internal (ml_dsa::SigningKey::from_seed).
        let mut dsa_xi_bytes = [0u8; 32];
        fill_random(&mut dsa_xi_bytes)?;
        let dsa_xi = B32::from(dsa_xi_bytes);
        let dsa_kp = MlDsaSigningKey::<MlDsa65>::from_seed(&dsa_xi);
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

    /// Serialize the **full keypair, including secret keys**, to self-describing
    /// bytes.
    ///
    /// # Security
    ///
    /// The returned buffer contains private signing and decapsulation key
    /// material. It is as sensitive as any raw private key: never log it, never
    /// send it over an unauthenticated channel, and zeroize or drop it as soon
    /// as it has been persisted. Prefer [`KavachKeyPair::save_to_file`], which
    /// writes to an owner-only file and clears its transient buffer for you.
    ///
    /// Round-trips exactly through [`KavachKeyPair::from_secret_bytes`].
    pub fn to_secret_bytes(&self) -> Result<Vec<u8>> {
        let wire = SecretKeyPairWire {
            id: self.id.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            ml_dsa_signing_key: self.ml_dsa_signing_key.clone(),
            ml_dsa_verifying_key: self.ml_dsa_verifying_key.clone(),
            ml_kem_decapsulation_key: self.ml_kem_decapsulation_key.clone(),
            ml_kem_encapsulation_key: self.ml_kem_encapsulation_key.clone(),
            ed25519_signing_key: self.ed25519_signing_key.clone(),
            ed25519_verifying_key: self.ed25519_verifying_key.clone(),
            x25519_secret_key: self.x25519_secret_key.clone(),
            x25519_public_key: self.x25519_public_key.clone(),
        };
        let mut body = serde_json::to_vec(&wire)
            .map_err(|e| PqError::Serialization(format!("keypair encode: {e}")))?;
        // `wire` zeroizes its secret vecs on drop at end of scope.
        let mut out = Vec::with_capacity(SECRET_KEYPAIR_MAGIC.len() + 1 + body.len());
        out.extend_from_slice(SECRET_KEYPAIR_MAGIC);
        out.push(SECRET_KEYPAIR_VERSION);
        out.extend_from_slice(&body);
        // The header+body copy now lives in `out`; clear the intermediate.
        body.zeroize();
        Ok(out)
    }

    /// Reconstruct a keypair from bytes produced by
    /// [`KavachKeyPair::to_secret_bytes`].
    ///
    /// Verifies the magic prefix and version before decoding. The reconstructed
    /// keypair is identical to the original: same `id`, same `public_keys()`,
    /// and it signs with the same identity.
    pub fn from_secret_bytes(data: &[u8]) -> Result<Self> {
        let header_len = SECRET_KEYPAIR_MAGIC.len() + 1;
        if data.len() < header_len {
            return Err(PqError::Serialization(
                "keypair blob too short for header".into(),
            ));
        }
        if &data[..SECRET_KEYPAIR_MAGIC.len()] != SECRET_KEYPAIR_MAGIC {
            return Err(PqError::Serialization(
                "keypair magic mismatch (not a KVSK blob)".into(),
            ));
        }
        let version = data[SECRET_KEYPAIR_MAGIC.len()];
        if version != SECRET_KEYPAIR_VERSION {
            return Err(PqError::Serialization(format!(
                "unsupported keypair version {version}, expected {SECRET_KEYPAIR_VERSION}"
            )));
        }
        let wire: SecretKeyPairWire = serde_json::from_slice(&data[header_len..])
            .map_err(|e| PqError::Serialization(format!("keypair decode: {e}")))?;
        // Clone out of `wire` before it drops and zeroizes its secret vecs.
        Ok(Self {
            id: wire.id.clone(),
            created_at: wire.created_at,
            expires_at: wire.expires_at,
            ml_dsa_signing_key: wire.ml_dsa_signing_key.clone(),
            ml_dsa_verifying_key: wire.ml_dsa_verifying_key.clone(),
            ml_kem_decapsulation_key: wire.ml_kem_decapsulation_key.clone(),
            ml_kem_encapsulation_key: wire.ml_kem_encapsulation_key.clone(),
            ed25519_signing_key: wire.ed25519_signing_key.clone(),
            ed25519_verifying_key: wire.ed25519_verifying_key.clone(),
            x25519_secret_key: wire.x25519_secret_key.clone(),
            x25519_public_key: wire.x25519_public_key.clone(),
        })
    }

    /// Write the keypair to a file with owner-only permissions.
    ///
    /// On Unix the file is created `0600` (owner read/write only). If the file
    /// already exists, its permissions are tightened to owner-only but never
    /// widened, so a caller who has pre-restricted the file (for example to
    /// `0400`) is not silently opened up.
    ///
    /// # Security
    ///
    /// This writes **secret key material** to disk. Treat the resulting file as
    /// you would any private key: store it on an encrypted volume or behind a
    /// KMS/HSM, restrict access, and back it up securely. The transient
    /// in-memory buffer is zeroized after the write.
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        use std::io::Write;
        let path = path.as_ref();
        let mut buf = self.to_secret_bytes()?;

        #[cfg(unix)]
        let existing_mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path)
                .ok()
                .map(|m| m.permissions().mode() & 0o777)
        };

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let write_result = (|| -> Result<()> {
            let mut f = opts.open(path).map_err(|e| {
                PqError::Serialization(format!("open key file {}: {e}", path.display()))
            })?;
            f.write_all(&buf).map_err(|e| {
                PqError::Serialization(format!("write key file {}: {e}", path.display()))
            })?;
            f.sync_all().map_err(|e| {
                PqError::Serialization(format!("sync key file {}: {e}", path.display()))
            })?;
            Ok(())
        })();
        // Clear the plaintext secret buffer regardless of write outcome.
        buf.zeroize();
        write_result?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Owner-only, and never add bits an existing file did not already have.
            let target = match existing_mode {
                Some(cur) => cur & 0o600,
                None => 0o600,
            };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(target)).map_err(
                |e| PqError::Serialization(format!("chmod key file {}: {e}", path.display())),
            )?;
        }

        Ok(())
    }

    /// Load a keypair previously written by [`KavachKeyPair::save_to_file`].
    ///
    /// The on-disk bytes hold secret key material; they are read into a
    /// transient buffer that is zeroized before this returns.
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut buf = std::fs::read(path)
            .map_err(|e| PqError::Serialization(format!("read key file {}: {e}", path.display())))?;
        let result = Self::from_secret_bytes(&buf);
        buf.zeroize();
        result
    }
}

/// Magic prefix for the secret keypair byte form ("KVSK" = Kavach Secret
/// Keypair). Distinguishes the blob and marks it as carrying secret material.
const SECRET_KEYPAIR_MAGIC: &[u8; 4] = b"KVSK";

/// Format version of the secret keypair byte form. Bump on any incompatible
/// layout change after the header.
const SECRET_KEYPAIR_VERSION: u8 = 1;

/// Serde wire form for the full keypair, **including secret keys**.
///
/// Kept private and separate from [`KavachKeyPair`] so the public type never
/// gains a blanket `Serialize` that could leak secrets through an unrelated
/// serializer. The secret vecs are zeroized when this wire struct drops.
#[derive(Serialize, Deserialize)]
struct SecretKeyPairWire {
    id: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    ml_dsa_signing_key: Vec<u8>,
    ml_dsa_verifying_key: Vec<u8>,
    ml_kem_decapsulation_key: Vec<u8>,
    ml_kem_encapsulation_key: Vec<u8>,
    ed25519_signing_key: Vec<u8>,
    ed25519_verifying_key: Vec<u8>,
    x25519_secret_key: Vec<u8>,
    x25519_public_key: Vec<u8>,
}

impl Drop for SecretKeyPairWire {
    fn drop(&mut self) {
        self.ml_dsa_signing_key.zeroize();
        self.ml_kem_decapsulation_key.zeroize();
        self.ed25519_signing_key.zeroize();
        self.x25519_secret_key.zeroize();
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    pub id: String,
    pub ml_dsa_verifying_key: Vec<u8>,
    pub ml_kem_encapsulation_key: Vec<u8>,
    pub ed25519_verifying_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Magic prefix for the self-describing `PublicKeyBundle` byte form.
///
/// "KVPB" = Kavach Public Bundle. Present so a stray blob can be told apart
/// from other serializations, and so a future format revision is
/// distinguishable from this one.
const PUBLIC_BUNDLE_MAGIC: &[u8; 4] = b"KVPB";

/// Format version of the `PublicKeyBundle` byte form. Bump when the layout
/// after the header changes in a non-backward-compatible way.
const PUBLIC_BUNDLE_VERSION: u8 = 1;

impl PublicKeyBundle {
    /// Serialize this bundle to self-describing bytes (public material only).
    ///
    /// The output is a 5-byte header (`b"KVPB"` + a one-byte version) followed
    /// by the JSON encoding of the bundle. It carries only public keys and is
    /// safe to share; there is no path by which secret material reaches this
    /// output because the bundle itself holds none.
    ///
    /// Round-trips exactly through [`PublicKeyBundle::from_bytes`].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let body = serde_json::to_vec(self)
            .map_err(|e| PqError::Serialization(format!("public bundle encode: {e}")))?;
        let mut out = Vec::with_capacity(PUBLIC_BUNDLE_MAGIC.len() + 1 + body.len());
        out.extend_from_slice(PUBLIC_BUNDLE_MAGIC);
        out.push(PUBLIC_BUNDLE_VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Reconstruct a bundle from bytes produced by [`PublicKeyBundle::to_bytes`].
    ///
    /// Verifies the magic prefix and version before decoding, so an unrelated
    /// or future-format blob is rejected with a clear error rather than
    /// silently mis-parsed.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let header_len = PUBLIC_BUNDLE_MAGIC.len() + 1;
        if data.len() < header_len {
            return Err(PqError::Serialization(
                "public bundle too short for header".into(),
            ));
        }
        if &data[..PUBLIC_BUNDLE_MAGIC.len()] != PUBLIC_BUNDLE_MAGIC {
            return Err(PqError::Serialization(
                "public bundle magic mismatch (not a KVPB blob)".into(),
            ));
        }
        let version = data[PUBLIC_BUNDLE_MAGIC.len()];
        if version != PUBLIC_BUNDLE_VERSION {
            return Err(PqError::Serialization(format!(
                "unsupported public bundle version {version}, expected {PUBLIC_BUNDLE_VERSION}"
            )));
        }
        serde_json::from_slice(&data[header_len..])
            .map_err(|e| PqError::Serialization(format!("public bundle decode: {e}")))
    }
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
    Ok(MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(arr)))
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
