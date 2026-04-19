//! Public key directory, how verifiers find the right [`PublicKeyBundle`]
//! for a token they've received.
//!
//! # Problem this solves
//!
//! A [`PermitToken`] signed by node A carries a `key_id` in its signed
//! envelope. A verifier elsewhere needs to look up the corresponding
//! [`PublicKeyBundle`] to check the signature. Without a distribution
//! mechanism, verifiers have to be told the key out-of-band, which breaks
//! as soon as node A rotates its signing key.
//!
//! # Design
//!
//! - [`PublicKeyDirectory`], async trait: `fetch(key_id)` returns the bundle.
//! - [`InMemoryPublicKeyDirectory`], programmatic store; useful for tests
//!   and for deployments that seed bundles at startup from code.
//! - [`FilePublicKeyDirectory`], loads bundles from a JSON manifest on disk.
//!   Supports optional root-signed manifests: the verifier pins an ML-DSA
//!   root verifying key in config, and any file whose contents aren't signed
//!   by that root is rejected. Reload is explicit (`reload()`) so integrators
//!   control the cadence, a file watcher can be built on top using `notify`.
//!
//! # Trust model
//!
//! The directory returns bundles; it does **not** itself sign tokens. If the
//! file impl is configured with a root verifying key, it verifies that the
//! manifest was signed by the root before exposing any bundle. Without a
//! root key, the file contents are trusted as-is, appropriate only when
//! the file is on a host Kavach trusts entirely (local disk on the verifier,
//! etc.). Cross-host distribution should always use a root-signed manifest.
//!
//! # Fail-closed
//!
//! Any error fetching a key (`NotFound`, `BackendUnavailable`,
//! `RootSignatureInvalid`) must cause the downstream verifier to **refuse**
//! the token. Kavach's default-deny posture extends here: unverifiable
//! tokens are rejected, never permitted.

use crate::error::PqError;
use crate::keys::{load_ml_dsa_verifying_key, PublicKeyBundle};
use async_trait::async_trait;
use hybrid_array::Array;
use ml_dsa::signature::Verifier as MlDsaVerifierTrait;
use ml_dsa::{EncodedSignature, MlDsa65, Signature as MlDsaSignature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use thiserror::Error;

/// Errors returned by [`PublicKeyDirectory`] implementations.
#[derive(Debug, Error)]
pub enum KeyDirectoryError {
    /// The requested `key_id` is not in the directory.
    #[error("public key not found for id '{0}'")]
    NotFound(String),

    /// The backing transport failed (file missing, HTTP down, etc.).
    #[error("public key directory unavailable: {0}")]
    BackendUnavailable(String),

    /// The manifest's root signature failed to verify.
    #[error("public key directory: root signature invalid")]
    RootSignatureInvalid,

    /// The manifest could not be parsed.
    #[error("public key directory corrupt: {0}")]
    Corrupt(String),

    /// Implementation-specific failure.
    #[error("public key directory: {0}")]
    Other(String),
}

/// Resolve a `key_id` to the corresponding [`PublicKeyBundle`].
///
/// Implementations must be safe to share across threads (`Send + Sync`).
#[async_trait]
pub trait PublicKeyDirectory: Send + Sync {
    /// Fetch the bundle for `key_id`. Returns `NotFound` if the directory
    /// does not know about this key (vs. `BackendUnavailable` for a transport
    /// failure, callers may want to distinguish).
    async fn fetch(&self, key_id: &str) -> Result<PublicKeyBundle, KeyDirectoryError>;
}

// ───────────────────────── In-memory impl ─────────────────────────

/// Directory backed by an in-process `HashMap`.
///
/// Intended for tests and for deployments that build their directory from
/// code at startup (e.g., by iterating the local [`crate::KeyStore`]).
#[derive(Debug, Default)]
pub struct InMemoryPublicKeyDirectory {
    bundles: RwLock<HashMap<String, PublicKeyBundle>>,
}

impl InMemoryPublicKeyDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a directory pre-populated with `bundles`. Later bundles with
    /// duplicate ids overwrite earlier ones.
    pub fn from_bundles(bundles: impl IntoIterator<Item = PublicKeyBundle>) -> Self {
        let map: HashMap<String, PublicKeyBundle> =
            bundles.into_iter().map(|b| (b.id.clone(), b)).collect();
        Self {
            bundles: RwLock::new(map),
        }
    }

    /// Insert (or overwrite) a bundle. Returns the previous bundle with the
    /// same id if one was present.
    pub fn insert(&self, bundle: PublicKeyBundle) -> Option<PublicKeyBundle> {
        let mut guard = self.bundles.write().unwrap();
        guard.insert(bundle.id.clone(), bundle)
    }

    /// Remove a bundle by id. Returns the removed bundle if any.
    pub fn remove(&self, key_id: &str) -> Option<PublicKeyBundle> {
        let mut guard = self.bundles.write().unwrap();
        guard.remove(key_id)
    }

    /// Current number of bundles in the directory.
    pub fn len(&self) -> usize {
        self.bundles.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl PublicKeyDirectory for InMemoryPublicKeyDirectory {
    async fn fetch(&self, key_id: &str) -> Result<PublicKeyBundle, KeyDirectoryError> {
        let guard = self.bundles.read().unwrap();
        guard
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyDirectoryError::NotFound(key_id.to_string()))
    }
}

// ───────────────────────── File-backed impl ─────────────────────────

/// Wire format for a signed manifest.
///
/// The `bundles_json` field is the raw JSON-encoded array of bundles, stored
/// as a string so the exact bytes that were signed are trivially
/// reconstructible by the verifier (no canonicalization required).
///
/// `signature` is the ML-DSA-65 signature over `bundles_json.as_bytes()`,
/// produced by the root signing key. The matching root verifying key is
/// pinned by the reader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDirectoryManifest {
    /// Raw JSON bytes of a `Vec<PublicKeyBundle>`, kept as a string so the
    /// exact signed bytes are recoverable.
    pub bundles_json: String,
    /// ML-DSA-65 signature over `bundles_json.as_bytes()`.
    pub signature: Vec<u8>,
}

/// Directory that loads bundles from a JSON file on disk.
///
/// Two on-disk formats are supported:
///
/// - **Unsigned:** the file is a JSON array of [`PublicKeyBundle`]s.
/// - **Signed:** the file is a [`SignedDirectoryManifest`]. The reader is
///   configured with a root verifying key; any file whose signature doesn't
///   check out is rejected at load time.
///
/// `reload()` re-reads the file; integrators can drive this from a `notify`
/// file watcher or a periodic tick.
#[derive(Debug)]
pub struct FilePublicKeyDirectory {
    path: PathBuf,
    /// Optional pinned ML-DSA-65 root verifying key. If `Some`, loads expect
    /// a signed manifest. If `None`, the file is read as a plain bundle array.
    root_verifying_key: Option<Vec<u8>>,
    cache: RwLock<HashMap<String, PublicKeyBundle>>,
}

impl FilePublicKeyDirectory {
    /// Load an **unsigned** bundle file. Only safe when the file is on a
    /// host the verifier trusts (e.g., local disk).
    pub fn load_unsigned(path: impl AsRef<Path>) -> Result<Self, KeyDirectoryError> {
        let me = Self {
            path: path.as_ref().to_path_buf(),
            root_verifying_key: None,
            cache: RwLock::new(HashMap::new()),
        };
        me.reload()?;
        Ok(me)
    }

    /// Load a **signed** manifest. `root_verifying_key` is the ML-DSA-65
    /// encoded verifying key of the root authority; any manifest whose
    /// signature does not verify against it is rejected.
    pub fn load_signed(
        path: impl AsRef<Path>,
        root_verifying_key: Vec<u8>,
    ) -> Result<Self, KeyDirectoryError> {
        let me = Self {
            path: path.as_ref().to_path_buf(),
            root_verifying_key: Some(root_verifying_key),
            cache: RwLock::new(HashMap::new()),
        };
        me.reload()?;
        Ok(me)
    }

    /// Re-read the file. Safe to call from a hot-reload watcher.
    ///
    /// On any error, the in-memory cache is left unchanged (the previous
    /// known-good view is preserved).
    pub fn reload(&self) -> Result<(), KeyDirectoryError> {
        let raw = std::fs::read(&self.path).map_err(|e| {
            KeyDirectoryError::BackendUnavailable(format!("read {:?}: {e}", self.path))
        })?;

        let bundles: Vec<PublicKeyBundle> = match &self.root_verifying_key {
            Some(root_vk) => {
                let manifest: SignedDirectoryManifest = serde_json::from_slice(&raw)
                    .map_err(|e| KeyDirectoryError::Corrupt(format!("manifest: {e}")))?;
                verify_root_signature(
                    root_vk,
                    manifest.bundles_json.as_bytes(),
                    &manifest.signature,
                )?;
                serde_json::from_str(&manifest.bundles_json)
                    .map_err(|e| KeyDirectoryError::Corrupt(format!("bundles_json: {e}")))?
            }
            None => serde_json::from_slice::<Vec<PublicKeyBundle>>(&raw)
                .map_err(|e| KeyDirectoryError::Corrupt(format!("bundles: {e}")))?,
        };

        let mut new_cache: HashMap<String, PublicKeyBundle> = HashMap::with_capacity(bundles.len());
        for bundle in bundles {
            new_cache.insert(bundle.id.clone(), bundle);
        }

        let mut guard = self.cache.write().unwrap();
        *guard = new_cache;
        Ok(())
    }

    /// Build a signed manifest from bundles + an ML-DSA-65 signing key.
    ///
    /// This is a helper for producers of the manifest file. The signing
    /// key is the root authority's signing key (never distributed).
    pub fn build_signed_manifest(
        bundles: &[PublicKeyBundle],
        ml_dsa_signing_key_seed: &[u8],
    ) -> Result<SignedDirectoryManifest, PqError> {
        use crate::keys::load_ml_dsa_signing_key;
        use ml_dsa::signature::Signer as MlDsaSignerTrait;

        let bundles_json = serde_json::to_string(bundles)
            .map_err(|e| PqError::Serialization(format!("bundles: {e}")))?;
        let sk = load_ml_dsa_signing_key(ml_dsa_signing_key_seed)?;
        let sig: MlDsaSignature<MlDsa65> = sk
            .try_sign(bundles_json.as_bytes())
            .map_err(|e| PqError::Signing(format!("ML-DSA manifest: {e}")))?;
        Ok(SignedDirectoryManifest {
            bundles_json,
            signature: sig.encode().as_slice().to_vec(),
        })
    }

    /// Current cached bundle count (observability).
    pub fn len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl PublicKeyDirectory for FilePublicKeyDirectory {
    async fn fetch(&self, key_id: &str) -> Result<PublicKeyBundle, KeyDirectoryError> {
        let guard = self.cache.read().unwrap();
        guard
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyDirectoryError::NotFound(key_id.to_string()))
    }
}

fn verify_root_signature(
    root_vk_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), KeyDirectoryError> {
    let vk = load_ml_dsa_verifying_key(root_vk_bytes)
        .map_err(|e| KeyDirectoryError::Corrupt(format!("root VK: {e}")))?;
    let encoded: EncodedSignature<MlDsa65> =
        Array::try_from(signature_bytes).map_err(|_| KeyDirectoryError::RootSignatureInvalid)?;
    let sig = MlDsaSignature::<MlDsa65>::decode(&encoded)
        .ok_or(KeyDirectoryError::RootSignatureInvalid)?;
    vk.verify(message, &sig)
        .map_err(|_| KeyDirectoryError::RootSignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KavachKeyPair;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_bundle(id: &str) -> PublicKeyBundle {
        let kp = KavachKeyPair::generate().expect("keypair");
        let mut b = kp.public_keys();
        b.id = id.to_string();
        b
    }

    // ── InMemory ──────────────────────────────────────────────

    #[tokio::test]
    async fn in_memory_fetch_hit() {
        let b = sample_bundle("k-1");
        let dir = InMemoryPublicKeyDirectory::from_bundles([b.clone()]);
        let got = dir.fetch("k-1").await.unwrap();
        assert_eq!(got.id, b.id);
    }

    #[tokio::test]
    async fn in_memory_fetch_miss() {
        let dir = InMemoryPublicKeyDirectory::new();
        let err = dir.fetch("missing").await.unwrap_err();
        assert!(matches!(err, KeyDirectoryError::NotFound(_)));
    }

    #[tokio::test]
    async fn in_memory_insert_remove() {
        let dir = InMemoryPublicKeyDirectory::new();
        dir.insert(sample_bundle("k-1"));
        dir.insert(sample_bundle("k-2"));
        assert_eq!(dir.len(), 2);
        assert!(dir.fetch("k-1").await.is_ok());
        assert!(dir.remove("k-1").is_some());
        assert!(matches!(
            dir.fetch("k-1").await.unwrap_err(),
            KeyDirectoryError::NotFound(_)
        ));
    }

    // ── File, unsigned ─────────────────────────────────────────

    #[tokio::test]
    async fn file_unsigned_roundtrip() {
        let bundles = vec![sample_bundle("k-1"), sample_bundle("k-2")];
        let json = serde_json::to_vec(&bundles).unwrap();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&json).unwrap();
        let dir = FilePublicKeyDirectory::load_unsigned(f.path()).unwrap();

        assert_eq!(dir.len(), 2);
        let got = dir.fetch("k-2").await.unwrap();
        assert_eq!(got.id, "k-2");
    }

    #[tokio::test]
    async fn file_unsigned_missing_file_is_backend_unavailable() {
        let err =
            FilePublicKeyDirectory::load_unsigned("/nonexistent/path/to/nowhere").unwrap_err();
        assert!(matches!(err, KeyDirectoryError::BackendUnavailable(_)));
    }

    #[tokio::test]
    async fn file_unsigned_corrupt_json_is_corrupt() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"not-json").unwrap();
        let err = FilePublicKeyDirectory::load_unsigned(f.path()).unwrap_err();
        assert!(matches!(err, KeyDirectoryError::Corrupt(_)));
    }

    #[tokio::test]
    async fn file_unsigned_fetch_miss() {
        let bundles = vec![sample_bundle("k-1")];
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&serde_json::to_vec(&bundles).unwrap()).unwrap();
        let dir = FilePublicKeyDirectory::load_unsigned(f.path()).unwrap();

        let err = dir.fetch("k-missing").await.unwrap_err();
        assert!(matches!(err, KeyDirectoryError::NotFound(_)));
    }

    #[tokio::test]
    async fn file_unsigned_reload_picks_up_changes() {
        let bundles1 = vec![sample_bundle("k-1")];
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&serde_json::to_vec(&bundles1).unwrap())
            .unwrap();

        let dir = FilePublicKeyDirectory::load_unsigned(f.path()).unwrap();
        assert_eq!(dir.len(), 1);

        // Overwrite with additional bundle
        let bundles2 = vec![sample_bundle("k-1"), sample_bundle("k-2")];
        std::fs::write(f.path(), serde_json::to_vec(&bundles2).unwrap()).unwrap();
        dir.reload().unwrap();

        assert_eq!(dir.len(), 2);
        assert!(dir.fetch("k-2").await.is_ok());
    }

    #[tokio::test]
    async fn file_reload_preserves_cache_on_parse_error() {
        let bundles = vec![sample_bundle("k-1")];
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&serde_json::to_vec(&bundles).unwrap()).unwrap();

        let dir = FilePublicKeyDirectory::load_unsigned(f.path()).unwrap();

        // Corrupt the file, then try to reload.
        std::fs::write(f.path(), b"garbage").unwrap();
        let err = dir.reload().unwrap_err();
        assert!(matches!(err, KeyDirectoryError::Corrupt(_)));

        // Cache must still hold the previously-good bundle.
        assert!(dir.fetch("k-1").await.is_ok());
    }

    // ── File, signed ───────────────────────────────────────────

    fn build_root_keypair() -> KavachKeyPair {
        KavachKeyPair::generate().unwrap()
    }

    #[tokio::test]
    async fn file_signed_valid_manifest_loads() {
        let root = build_root_keypair();
        let bundles = vec![sample_bundle("k-1"), sample_bundle("k-2")];
        let manifest =
            FilePublicKeyDirectory::build_signed_manifest(&bundles, &root.ml_dsa_signing_key)
                .unwrap();

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();

        let dir = FilePublicKeyDirectory::load_signed(f.path(), root.ml_dsa_verifying_key.clone())
            .unwrap();

        assert_eq!(dir.len(), 2);
        assert!(dir.fetch("k-1").await.is_ok());
    }

    #[tokio::test]
    async fn file_signed_wrong_root_key_is_rejected() {
        let real_root = build_root_keypair();
        let imposter = build_root_keypair();
        let bundles = vec![sample_bundle("k-1")];
        let manifest =
            FilePublicKeyDirectory::build_signed_manifest(&bundles, &real_root.ml_dsa_signing_key)
                .unwrap();

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();

        let err =
            FilePublicKeyDirectory::load_signed(f.path(), imposter.ml_dsa_verifying_key.clone())
                .unwrap_err();
        assert!(matches!(err, KeyDirectoryError::RootSignatureInvalid));
    }

    #[tokio::test]
    async fn file_signed_tampered_bundles_are_rejected() {
        let root = build_root_keypair();
        let bundles = vec![sample_bundle("k-1")];
        let mut manifest =
            FilePublicKeyDirectory::build_signed_manifest(&bundles, &root.ml_dsa_signing_key)
                .unwrap();

        // Tamper with the bundles_json without re-signing.
        let tampered = manifest.bundles_json.replace("k-1", "evil");
        manifest.bundles_json = tampered;

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();

        let err = FilePublicKeyDirectory::load_signed(f.path(), root.ml_dsa_verifying_key.clone())
            .unwrap_err();
        assert!(matches!(err, KeyDirectoryError::RootSignatureInvalid));
    }

    #[tokio::test]
    async fn file_signed_tampered_signature_is_rejected() {
        let root = build_root_keypair();
        let bundles = vec![sample_bundle("k-1")];
        let mut manifest =
            FilePublicKeyDirectory::build_signed_manifest(&bundles, &root.ml_dsa_signing_key)
                .unwrap();

        // Flip a byte in the signature.
        if let Some(byte) = manifest.signature.get_mut(0) {
            *byte ^= 0xFF;
        }

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();

        let err = FilePublicKeyDirectory::load_signed(f.path(), root.ml_dsa_verifying_key.clone())
            .unwrap_err();
        assert!(matches!(err, KeyDirectoryError::RootSignatureInvalid));
    }
}
