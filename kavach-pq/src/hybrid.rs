//! Hybrid mode: classical (X25519/Ed25519) + post-quantum (ML-KEM/ML-DSA).
//!
//! In hybrid mode, both classical and PQ algorithms run in parallel.
//! An attacker must break BOTH to compromise the system. This provides
//! defense-in-depth: if ML-DSA has an undiscovered flaw, Ed25519 still
//! protects. If quantum breaks Ed25519, ML-DSA still protects.

use crate::encrypt::{Decryptor, EncryptedPayload, Encryptor};
use crate::error::Result;
use crate::keys::KavachKeyPair;
use crate::sign::{SignedPayload, Signer, Verifier};

/// A hybrid keypair combining PQ and classical keys.
///
/// This is the recommended configuration for production use.
pub struct HybridKeyPair {
    inner: KavachKeyPair,
}

impl HybridKeyPair {
    /// Generate a new hybrid keypair.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            inner: KavachKeyPair::generate()?,
        })
    }

    /// Create a hybrid signer from this keypair.
    pub fn signer(&self) -> Signer {
        Signer::hybrid(
            self.inner.ml_dsa_signing_key.clone(),
            self.inner.ed25519_signing_key.clone(),
            self.inner.id.clone(),
        )
    }

    /// Create a hybrid verifier from this keypair's public keys.
    pub fn verifier(&self) -> Verifier {
        Verifier::hybrid(
            self.inner.ml_dsa_verifying_key.clone(),
            self.inner.ed25519_verifying_key.clone(),
        )
    }

    /// Create a hybrid encryptor targeting this keypair.
    pub fn encryptor(&self) -> Encryptor {
        Encryptor::new(
            self.inner.ml_kem_encapsulation_key.clone(),
            self.inner.id.clone(),
        )
        .with_x25519(self.inner.x25519_public_key.clone())
    }

    /// Create a hybrid decryptor using this keypair's secret keys.
    pub fn decryptor(&self) -> Decryptor {
        Decryptor::new(
            self.inner.ml_kem_decapsulation_key.clone(),
            self.inner.id.clone(),
        )
        .with_x25519(self.inner.x25519_secret_key.clone())
    }

    pub fn key_id(&self) -> &str {
        &self.inner.id
    }
}

/// A bidirectional hybrid-encrypted channel between two parties.
///
/// Each party has their own keypair. The channel handles:
/// - Encrypting outbound messages with the remote party's public key
/// - Decrypting inbound messages with the local party's secret key
/// - Signing outbound messages and verifying inbound signatures
pub struct HybridChannel {
    /// Our keypair.
    local: HybridKeyPair,

    /// Remote party's encryptor (their public keys).
    remote_encryptor: Encryptor,

    /// Remote party's verifier (their public keys).
    remote_verifier: Verifier,
}

impl HybridChannel {
    /// Establish a hybrid channel between local and remote keypairs.
    pub fn establish(local: HybridKeyPair, remote_public: &HybridKeyPair) -> Self {
        Self {
            remote_encryptor: remote_public.encryptor(),
            remote_verifier: remote_public.verifier(),
            local,
        }
    }

    /// Send a message: sign with our key, encrypt for the remote party.
    pub fn send(&self, plaintext: &[u8]) -> Result<(SignedPayload, EncryptedPayload)> {
        // Sign first, then encrypt (sign-then-encrypt)
        let signed = self.local.signer().sign(plaintext)?;
        let signed_bytes = serde_json::to_vec(&signed)
            .map_err(|e| crate::error::PqError::Serialization(e.to_string()))?;
        let encrypted = self.remote_encryptor.encrypt(&signed_bytes)?;
        Ok((signed, encrypted))
    }

    /// Receive a message: decrypt with our key, verify remote's signature.
    pub fn receive(&self, encrypted: &EncryptedPayload) -> Result<Vec<u8>> {
        // Decrypt first, then verify (reverse of sign-then-encrypt)
        let decrypted = self.local.decryptor().decrypt(encrypted)?;
        let signed: SignedPayload = serde_json::from_slice(&decrypted)
            .map_err(|e| crate::error::PqError::Serialization(e.to_string()))?;
        self.remote_verifier.verify(&signed)?;
        Ok(signed.data)
    }
}
