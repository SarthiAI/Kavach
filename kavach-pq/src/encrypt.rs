//! Post-quantum encryption using ML-KEM-768 (FIPS 203) for key encapsulation
//! and ChaCha20-Poly1305 for symmetric authenticated encryption.
//!
//! ML-KEM establishes a shared secret between two parties.
//! That shared secret (combined with an X25519 DH secret in hybrid mode)
//! is passed through HKDF-SHA256 to derive the symmetric key that
//! ChaCha20-Poly1305 uses to encrypt the data.
//!
//! This is how secure channels are established between Kavach components.

use crate::error::{PqError, Result};
use crate::keys::{load_ml_kem_decapsulation_key, load_ml_kem_encapsulation_key};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

/// Info string passed to HKDF so derived keys are context-separated.
const HKDF_INFO: &[u8] = b"kavach-pq-channel-key-v1";
const HKDF_SALT: &[u8] = b"kavach-pq-salt-v1";

/// An encrypted payload with all metadata needed for decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// The ML-KEM ciphertext (encapsulated shared secret).
    pub kem_ciphertext: Vec<u8>,

    /// The symmetrically encrypted ciphertext (AEAD tag appended by `chacha20poly1305`).
    pub encrypted_data: Vec<u8>,

    /// Nonce used for ChaCha20-Poly1305 (12 bytes).
    pub nonce: Vec<u8>,

    /// Reserved for wire compat; current versions embed the tag in `encrypted_data`.
    pub auth_tag: Vec<u8>,

    /// Ephemeral X25519 public key (hybrid mode only). Empty in PQ-only mode.
    #[serde(default)]
    pub ephemeral_x25519_pk: Vec<u8>,

    /// ID of the recipient's encapsulation key.
    pub recipient_key_id: String,

    /// Unique payload ID (for replay detection at a higher layer).
    pub payload_id: String,
}

/// Derive a 32-byte symmetric key from one or two shared secrets via HKDF-SHA256.
fn derive_symmetric_key(pq_secret: &[u8], classical_secret: Option<&[u8]>) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(pq_secret.len() + classical_secret.map_or(0, |s| s.len()));
    ikm.extend_from_slice(pq_secret);
    if let Some(cs) = classical_secret {
        ikm.extend_from_slice(cs);
    }
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| PqError::Encryption(format!("HKDF: {e}")))?;
    Ok(okm)
}

/// Encrypts data for a recipient using their ML-KEM public key.
pub struct Encryptor {
    /// Recipient's ML-KEM encapsulation (public) key bytes.
    recipient_ek: Vec<u8>,

    /// Recipient's key ID.
    recipient_key_id: String,

    /// Recipient's X25519 public key for hybrid mode (optional).
    recipient_x25519: Option<Vec<u8>>,
}

impl Encryptor {
    /// Create an encryptor targeting a specific recipient.
    pub fn new(recipient_ek: Vec<u8>, recipient_key_id: String) -> Self {
        Self {
            recipient_ek,
            recipient_key_id,
            recipient_x25519: None,
        }
    }

    /// Enable hybrid mode with the recipient's X25519 public key.
    pub fn with_x25519(mut self, x25519_pk: Vec<u8>) -> Self {
        self.recipient_x25519 = Some(x25519_pk);
        self
    }

    /// The recipient key ID this encryptor targets (used as AAD binding).
    pub fn recipient_key_id(&self) -> &str {
        &self.recipient_key_id
    }

    /// Encrypt data for the recipient.
    ///
    /// Steps:
    /// 1. ML-KEM encapsulate → (kem_ciphertext, pq_shared_secret)
    /// 2. If hybrid: generate ephemeral X25519 key, DH with recipient → x_secret
    /// 3. HKDF-SHA256 over (pq_shared_secret || x_secret) → 32-byte AEAD key
    /// 4. ChaCha20-Poly1305 encrypt with a fresh 12-byte nonce, binding recipient key id as AAD
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload> {
        // 1. ML-KEM encapsulation
        let ek = load_ml_kem_encapsulation_key(&self.recipient_ek)?;
        let mut rng = OsCryptoRng;
        let (kem_ct, pq_shared) = ek.encapsulate_with_rng(&mut rng);
        let kem_ciphertext = kem_ct.as_slice().to_vec();

        // 2. Optional X25519 hybrid DH using a true EphemeralSecret,
        //    x25519-dalek's dedicated one-shot type that's consumed by
        //    `diffie_hellman` so it can't accidentally be reused.
        let (x_shared_bytes, ephemeral_pk_bytes) = if let Some(rx_bytes) = &self.recipient_x25519 {
            let rx = to_x25519_pk(rx_bytes)?;
            // x25519-dalek 2 requires a rand_core 0.6 `RngCore + CryptoRng`;
            // rand_core_06::OsRng (pulled in via our explicit dep with the
            // `getrandom` feature) satisfies both bounds.
            let eph = EphemeralSecret::random_from_rng(rand_core_06::OsRng);
            let eph_pk = X25519PublicKey::from(&eph);
            let shared = eph.diffie_hellman(&rx);
            (Some(shared.as_bytes().to_vec()), eph_pk.to_bytes().to_vec())
        } else {
            (None, Vec::new())
        };

        // 3. KDF
        let key_bytes = derive_symmetric_key(pq_shared.as_slice(), x_shared_bytes.as_deref())?;

        // 4. ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key_bytes));
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| PqError::Encryption(format!("nonce RNG: {e}")))?;
        let nonce = ChaChaNonce::from_slice(&nonce_bytes);

        let encrypted_data = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: self.recipient_key_id.as_bytes(),
                },
            )
            .map_err(|e| PqError::Encryption(format!("AEAD encrypt: {e}")))?;

        Ok(EncryptedPayload {
            kem_ciphertext,
            encrypted_data,
            nonce: nonce_bytes.to_vec(),
            auth_tag: Vec::new(),
            ephemeral_x25519_pk: ephemeral_pk_bytes,
            recipient_key_id: self.recipient_key_id.clone(),
            payload_id: Uuid::new_v4().to_string(),
        })
    }
}

/// Decrypts data using the recipient's ML-KEM secret key.
pub struct Decryptor {
    /// ML-KEM decapsulation (secret) key bytes.
    dk: Vec<u8>,

    /// X25519 secret key for hybrid mode (optional).
    x25519_sk: Option<Vec<u8>>,

    /// Recipient key ID, must match the payload's `recipient_key_id` (used as AAD).
    recipient_key_id: String,
}

impl Decryptor {
    pub fn new(dk: Vec<u8>, recipient_key_id: String) -> Self {
        Self {
            dk,
            x25519_sk: None,
            recipient_key_id,
        }
    }

    pub fn with_x25519(mut self, x25519_sk: Vec<u8>) -> Self {
        self.x25519_sk = Some(x25519_sk);
        self
    }

    /// The recipient key ID this decryptor is bound to, payloads targeting
    /// a different ID are rejected at decrypt time.
    pub fn recipient_key_id(&self) -> &str {
        &self.recipient_key_id
    }

    /// Decrypt an encrypted payload.
    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>> {
        if payload.recipient_key_id != self.recipient_key_id {
            return Err(PqError::Decryption(format!(
                "recipient key id mismatch: payload targeted '{}', decryptor holds '{}'",
                payload.recipient_key_id, self.recipient_key_id
            )));
        }

        // 1. ML-KEM decapsulation (via slice-taking convenience wrapper, infallible)
        let dk = load_ml_kem_decapsulation_key(&self.dk)?;
        let pq_shared = dk
            .decapsulate_slice(&payload.kem_ciphertext)
            .map_err(|e| PqError::Decryption(format!("ML-KEM ciphertext size: {e}")))?;

        // 2. Optional X25519 hybrid DH
        let x_shared_bytes = if !payload.ephemeral_x25519_pk.is_empty() {
            let sk_bytes = self.x25519_sk.as_ref().ok_or_else(|| {
                PqError::Decryption(
                    "payload uses hybrid mode but decryptor has no X25519 key".into(),
                )
            })?;
            let sk = to_x25519_sk(sk_bytes)?;
            let pk = to_x25519_pk(&payload.ephemeral_x25519_pk)?;
            Some(sk.diffie_hellman(&pk).as_bytes().to_vec())
        } else {
            None
        };

        // 3. KDF
        let key_bytes = derive_symmetric_key(pq_shared.as_slice(), x_shared_bytes.as_deref())?;

        // 4. AEAD decrypt
        let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key_bytes));
        if payload.nonce.len() != 12 {
            return Err(PqError::Decryption(format!(
                "nonce must be 12 bytes, got {}",
                payload.nonce.len()
            )));
        }
        let nonce = ChaChaNonce::from_slice(&payload.nonce);

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &payload.encrypted_data,
                    aad: payload.recipient_key_id.as_bytes(),
                },
            )
            .map_err(|e| PqError::Decryption(format!("AEAD decrypt: {e}")))
    }
}

// ─── RNG adapter ───────────────────────────────────────────────────────

/// A rand_core 0.10 `CryptoRng` backed by `getrandom`.
///
/// ml-kem's `Encapsulate::encapsulate_with_rng` requires a `CryptoRng`,
/// which in rand_core 0.10 is the trait hierarchy `TryRng → Rng → CryptoRng`.
/// `getrandom` is considered infallible (panics on OS failure) so we wire
/// it as an infallible `Rng + CryptoRng`.
pub(crate) struct OsCryptoRng;

impl rand_core::TryRng for OsCryptoRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("OS RNG unavailable");
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("OS RNG unavailable");
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        getrandom::fill(dst).expect("OS RNG unavailable");
        Ok(())
    }
}

// `Rng` is blanket-impl'd for `TryRng<Error = Infallible>`, and `CryptoRng` is
// blanket-impl'd for `TryCryptoRng<Error = Infallible>`, so we only mark the
// fallible variants and the infallible ones are automatic.
impl rand_core::TryCryptoRng for OsCryptoRng {}

// ─── Small helpers ─────────────────────────────────────────────────────

fn to_x25519_pk(bytes: &[u8]) -> Result<X25519PublicKey> {
    if bytes.len() != 32 {
        return Err(PqError::Decryption(format!(
            "X25519 public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(X25519PublicKey::from(arr))
}

fn to_x25519_sk(bytes: &[u8]) -> Result<X25519Secret> {
    if bytes.len() != 32 {
        return Err(PqError::Decryption(format!(
            "X25519 secret key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(X25519Secret::from(arr))
}
