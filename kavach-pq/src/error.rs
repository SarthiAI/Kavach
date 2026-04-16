use thiserror::Error;

#[derive(Debug, Error)]
pub enum PqError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("key encapsulation failed: {0}")]
    Encapsulation(String),

    #[error("key decapsulation failed: {0}")]
    Decapsulation(String),

    #[error("channel error: {0}")]
    Channel(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("key expired: {0}")]
    KeyExpired(String),

    #[error("audit chain broken at entry {index}: {reason}")]
    AuditChainBroken { index: u64, reason: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("replay detected: nonce {0} already seen")]
    ReplayDetected(String),
}

pub type Result<T> = std::result::Result<T, PqError>;
