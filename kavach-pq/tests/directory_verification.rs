//! End-to-end: sign a PermitToken with PqTokenSigner, then verify it through
//! a PublicKeyDirectory using DirectoryTokenVerifier. This is the multi-node
//! scenario the directory trait was designed for.

use async_trait::async_trait;
use kavach_core::{PermitToken, TokenSigner};
use kavach_pq::{
    DirectoryTokenVerifier, DirectoryVerifyError, FilePublicKeyDirectory,
    InMemoryPublicKeyDirectory, KavachKeyPair, KeyDirectoryError, PqTokenSigner, PublicKeyBundle,
    PublicKeyDirectory,
};
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;
use uuid::Uuid;

fn sample_token(action: &str) -> PermitToken {
    PermitToken::new(Uuid::new_v4(), action.to_string())
}

// ── PQ-only round trip through in-memory directory ─────────

#[tokio::test]
async fn pq_only_sign_then_verify_through_in_memory_directory() {
    let kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_pq_only(&kp);
    let directory: Arc<dyn PublicKeyDirectory> =
        Arc::new(InMemoryPublicKeyDirectory::from_bundles([kp.public_keys()]));
    let verifier = DirectoryTokenVerifier::pq_only(directory);

    let mut token = sample_token("act");
    let sig = signer.sign(&token).unwrap();
    token.signature = Some(sig.clone());

    verifier.verify(&token, &sig).await.unwrap();
}

// ── Hybrid round trip ──────────────────────────────────────

#[tokio::test]
async fn hybrid_sign_then_verify_through_in_memory_directory() {
    let kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_hybrid(&kp);
    let directory: Arc<dyn PublicKeyDirectory> =
        Arc::new(InMemoryPublicKeyDirectory::from_bundles([kp.public_keys()]));
    let verifier = DirectoryTokenVerifier::hybrid(directory);

    let mut token = sample_token("act");
    let sig = signer.sign(&token).unwrap();
    token.signature = Some(sig.clone());

    verifier.verify(&token, &sig).await.unwrap();
}

// ── Directory misses the key ───────────────────────────────

#[tokio::test]
async fn verifier_rejects_when_directory_does_not_have_key() {
    let signing_kp = KavachKeyPair::generate().unwrap();
    let other_kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_pq_only(&signing_kp);

    // Directory only knows about `other_kp`; it does NOT have `signing_kp`.
    let directory: Arc<dyn PublicKeyDirectory> =
        Arc::new(InMemoryPublicKeyDirectory::from_bundles([
            other_kp.public_keys()
        ]));
    let verifier = DirectoryTokenVerifier::pq_only(directory);

    let token = sample_token("act");
    let sig = signer.sign(&token).unwrap();

    let err = verifier.verify(&token, &sig).await.unwrap_err();
    assert!(
        matches!(
            err,
            DirectoryVerifyError::Directory(KeyDirectoryError::NotFound(_))
        ),
        "expected NotFound, got {err:?}"
    );
}

// ── Wrong public key in directory ──────────────────────────

#[tokio::test]
async fn verifier_rejects_when_directory_returns_wrong_key_for_id() {
    // Simulate a directory where the key_id maps to the wrong public key —
    // either because of a mistake or an active attack.
    let signing_kp = KavachKeyPair::generate().unwrap();
    let other_kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_pq_only(&signing_kp);

    // Build a bundle with signing_kp's id but other_kp's public key.
    let mut bad_bundle = other_kp.public_keys();
    bad_bundle.id = signing_kp.id.clone();

    let directory: Arc<dyn PublicKeyDirectory> =
        Arc::new(InMemoryPublicKeyDirectory::from_bundles([bad_bundle]));
    let verifier = DirectoryTokenVerifier::pq_only(directory);

    let token = sample_token("act");
    let sig = signer.sign(&token).unwrap();

    let err = verifier.verify(&token, &sig).await.unwrap_err();
    assert!(
        matches!(err, DirectoryVerifyError::SignatureInvalid(_)),
        "expected SignatureInvalid, got {err:?}"
    );
}

// ── Algorithm mismatches (downgrade-attack guards) ─────────

#[tokio::test]
async fn hybrid_verifier_rejects_pq_only_token() {
    let kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_pq_only(&kp); // PQ-only
    let directory: Arc<dyn PublicKeyDirectory> =
        Arc::new(InMemoryPublicKeyDirectory::from_bundles([kp.public_keys()]));
    let verifier = DirectoryTokenVerifier::hybrid(directory); // hybrid

    let token = sample_token("act");
    let sig = signer.sign(&token).unwrap();

    let err = verifier.verify(&token, &sig).await.unwrap_err();
    assert!(
        matches!(err, DirectoryVerifyError::AlgorithmMismatch(_)),
        "hybrid verifier must reject PQ-only token, got {err:?}"
    );
}

#[tokio::test]
async fn pq_only_verifier_rejects_hybrid_token() {
    let kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_hybrid(&kp); // hybrid
    let directory: Arc<dyn PublicKeyDirectory> =
        Arc::new(InMemoryPublicKeyDirectory::from_bundles([kp.public_keys()]));
    let verifier = DirectoryTokenVerifier::pq_only(directory); // PQ-only

    let token = sample_token("act");
    let sig = signer.sign(&token).unwrap();

    let err = verifier.verify(&token, &sig).await.unwrap_err();
    assert!(
        matches!(err, DirectoryVerifyError::AlgorithmMismatch(_)),
        "PQ-only verifier must reject hybrid token, got {err:?}"
    );
}

// ── Tampered signature ─────────────────────────────────────

#[tokio::test]
async fn verifier_rejects_tampered_signature() {
    let kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_pq_only(&kp);
    let directory: Arc<dyn PublicKeyDirectory> =
        Arc::new(InMemoryPublicKeyDirectory::from_bundles([kp.public_keys()]));
    let verifier = DirectoryTokenVerifier::pq_only(directory);

    let token = sample_token("act");
    let mut sig = signer.sign(&token).unwrap();
    // Flip a byte inside the envelope — this corrupts the JSON OR the
    // embedded signature depending on where we land, but either way the
    // envelope must not pass verification.
    if let Some(last) = sig.last_mut() {
        *last ^= 0xFF;
    }

    let err = verifier.verify(&token, &sig).await.unwrap_err();
    match err {
        DirectoryVerifyError::EnvelopeParse(_)
        | DirectoryVerifyError::SignatureInvalid(_)
        | DirectoryVerifyError::Directory(KeyDirectoryError::NotFound(_))
        | DirectoryVerifyError::AlgorithmMismatch(_) => {}
        other => panic!("tamper must be rejected; got {other:?}"),
    }
}

// ── Tampered token (signature valid for original, not for modified) ─

#[tokio::test]
async fn verifier_rejects_when_token_fields_are_tampered() {
    let kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_pq_only(&kp);
    let directory: Arc<dyn PublicKeyDirectory> =
        Arc::new(InMemoryPublicKeyDirectory::from_bundles([kp.public_keys()]));
    let verifier = DirectoryTokenVerifier::pq_only(directory);

    let original = sample_token("act");
    let sig = signer.sign(&original).unwrap();

    // Keep the same signature, but change the action name.
    let mut tampered = original.clone();
    tampered.action_name = "stolen_action".into();

    let err = verifier.verify(&tampered, &sig).await.unwrap_err();
    assert!(
        matches!(err, DirectoryVerifyError::SignatureInvalid(_)),
        "signature must not verify for a mutated token, got {err:?}"
    );
}

// ── File-based directory (unsigned) round trip ─────────────

#[tokio::test]
async fn verify_through_unsigned_file_directory() {
    let kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_pq_only(&kp);

    let bundles: Vec<PublicKeyBundle> = vec![kp.public_keys()];
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&serde_json::to_vec(&bundles).unwrap()).unwrap();

    let directory: Arc<dyn PublicKeyDirectory> =
        Arc::new(FilePublicKeyDirectory::load_unsigned(f.path()).unwrap());
    let verifier = DirectoryTokenVerifier::pq_only(directory);

    let token = sample_token("act");
    let sig = signer.sign(&token).unwrap();
    verifier.verify(&token, &sig).await.unwrap();
}

// ── File-based directory (signed) round trip ───────────────

#[tokio::test]
async fn verify_through_signed_file_directory() {
    let signing_kp = KavachKeyPair::generate().unwrap();
    let root_kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_pq_only(&signing_kp);

    let bundles: Vec<PublicKeyBundle> = vec![signing_kp.public_keys()];
    let manifest =
        FilePublicKeyDirectory::build_signed_manifest(&bundles, &root_kp.ml_dsa_signing_key)
            .unwrap();

    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&serde_json::to_vec(&manifest).unwrap())
        .unwrap();

    let directory: Arc<dyn PublicKeyDirectory> = Arc::new(
        FilePublicKeyDirectory::load_signed(f.path(), root_kp.ml_dsa_verifying_key.clone())
            .unwrap(),
    );
    let verifier = DirectoryTokenVerifier::pq_only(directory);

    let token = sample_token("act");
    let sig = signer.sign(&token).unwrap();
    verifier.verify(&token, &sig).await.unwrap();
}

// ── Directory backend unavailable during verify ────────────

struct FlakyDirectory;

#[async_trait]
impl PublicKeyDirectory for FlakyDirectory {
    async fn fetch(&self, _key_id: &str) -> Result<PublicKeyBundle, KeyDirectoryError> {
        Err(KeyDirectoryError::BackendUnavailable("simulated".into()))
    }
}

#[tokio::test]
async fn verifier_fails_closed_on_directory_backend_error() {
    let kp = KavachKeyPair::generate().unwrap();
    let signer = PqTokenSigner::from_keypair_pq_only(&kp);
    let verifier = DirectoryTokenVerifier::pq_only(Arc::new(FlakyDirectory));

    let token = sample_token("act");
    let sig = signer.sign(&token).unwrap();

    let err = verifier.verify(&token, &sig).await.unwrap_err();
    assert!(
        matches!(
            err,
            DirectoryVerifyError::Directory(KeyDirectoryError::BackendUnavailable(_))
        ),
        "backend failure must propagate as Directory(BackendUnavailable), got {err:?}"
    );
}
