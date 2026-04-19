//! # Kavach PQ, Post-Quantum Transport Security
//!
//! Protects the wire between Kavach components. While `kavach-core`
//! decides what's allowed, `kavach-pq` ensures those decisions can't
//! be forged, replayed, or tampered with, even by quantum attackers.
//!
//! - **Signs verdicts** with ML-DSA (FIPS 204)
//! - **Encrypts channels** with ML-KEM (FIPS 203) + ChaCha20-Poly1305
//! - **Hybrid mode**, classical + PQ combined
//! - **Signs audit logs** with tamper-evident chaining
//!
//! Every algorithm comes from audited RustCrypto crates. We compose, not invent.

pub mod audit;
pub mod channel;
pub mod directory;
pub mod encrypt;
pub mod error;
pub mod hybrid;
#[cfg(feature = "http")]
pub mod http_directory;
pub mod keys;
pub mod sign;
pub mod token;
pub mod verdict;

pub use audit::{ChainMode, SignedAuditChain, SignedAuditEntry};
pub use channel::{SealedVerdict, SecureChannel, SignedBytes};
pub use directory::{
    FilePublicKeyDirectory, InMemoryPublicKeyDirectory, KeyDirectoryError, PublicKeyDirectory,
    SignedDirectoryManifest,
};
#[cfg(feature = "http")]
pub use http_directory::HttpPublicKeyDirectory;
pub use encrypt::{EncryptedPayload, Encryptor};
pub use error::PqError;
pub use hybrid::{HybridChannel, HybridKeyPair};
pub use keys::{KavachKeyPair, KeyStore, PublicKeyBundle};
pub use sign::{SignedPayload, Signer, Verifier};
pub use token::{DirectoryTokenVerifier, DirectoryVerifyError, PqTokenSigner, SignedTokenEnvelope};
pub use verdict::{SignedVerdict, VerdictSigner, VerdictVerifier};
