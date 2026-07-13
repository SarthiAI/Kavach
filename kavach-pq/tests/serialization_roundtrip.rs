//! P16 acceptance walkthrough: public-bundle export and keypair persistence.
//!
//! These assertions double as the manual round-trip walkthrough for the
//! independent-audit-verification work order:
//!   1. `PublicKeyBundle` serde + `to_bytes`/`from_bytes` round-trip exactly,
//!      and a `Verifier` built from a reconstructed bundle verifies a real
//!      multi-entry chain in both hybrid and PQ-only modes.
//!   2. The serialized public bundle contains no secret key bytes.
//!   3. The downgrade guard survives the round-trip (hybrid stays hybrid,
//!      PQ-only stays PQ-only, mode mismatch still fails).
//!   4. `KavachKeyPair` round-trips through `to_secret_bytes`/`from_secret_bytes`
//!      and `save_to_file`/`load_from_file`; a chain signed by the original key
//!      verifies under the reloaded key. `save_to_file` writes 0600 and does not
//!      widen an existing file.

use kavach_core::audit::AuditEntry;
use kavach_pq::audit::{verify_chain, SignedAuditChain};
use kavach_pq::keys::{KavachKeyPair, PublicKeyBundle};
use kavach_pq::sign::{Signer, Verifier};
use uuid::Uuid;

/// Build a signed multi-entry chain under the given keypair and mode.
fn build_chain(kp: &KavachKeyPair, hybrid: bool, n: u64) -> SignedAuditChain {
    let signer = Signer::from_keypair(kp, hybrid);
    let chain = SignedAuditChain::new(signer);
    for i in 0..n {
        let entry = AuditEntry {
            id: Uuid::new_v4(),
            evaluation_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            principal_id: format!("node-{i}"),
            action_name: "push_audit".to_string(),
            resource: Some(format!("chain-seg-{i}")),
            verdict: "permit".to_string(),
            verdict_detail: format!("entry={i}"),
            decided_by: None,
            session_id: Uuid::new_v4(),
            ip: Some("10.0.0.7".to_string()),
            context_snapshot: None,
        };
        chain.append(&entry).expect("append entry");
    }
    chain
}

#[test]
fn public_bundle_bytes_roundtrip_is_exact() {
    let kp = KavachKeyPair::generate().expect("generate");
    let bundle = kp.public_keys();

    let bytes = bundle.to_bytes().expect("to_bytes");
    let restored = PublicKeyBundle::from_bytes(&bytes).expect("from_bytes");
    assert_eq!(bundle, restored, "byte round-trip must be exact");

    // serde path round-trips too (this is the shape Niyam's JSON enrollment uses).
    let json = serde_json::to_string(&bundle).expect("serde to_string");
    let via_serde: PublicKeyBundle = serde_json::from_str(&json).expect("serde from_str");
    assert_eq!(bundle, via_serde, "serde round-trip must be exact");
}

#[test]
fn reconstructed_bundle_verifies_real_chain_both_modes() {
    for hybrid in [true, false] {
        let kp = KavachKeyPair::generate().expect("generate");
        let chain = build_chain(&kp, hybrid, 5);
        let entries = chain.entries();

        // Verifier from the ORIGINAL bundle.
        let original_bundle = kp.public_keys();
        let v_original = Verifier::from_bundle(&original_bundle, hybrid);
        verify_chain(&entries, &v_original).expect("original bundle verifies chain");

        // Verifier from a bundle that crossed the byte boundary.
        let moved = PublicKeyBundle::from_bytes(&original_bundle.to_bytes().unwrap()).unwrap();
        let v_moved = Verifier::from_bundle(&moved, hybrid);
        verify_chain(&entries, &v_moved)
            .unwrap_or_else(|e| panic!("reconstructed bundle (hybrid={hybrid}) must verify: {e}"));
    }
}

#[test]
fn serialized_public_bundle_contains_no_secret_bytes() {
    let kp = KavachKeyPair::generate().expect("generate");
    let bundle = kp.public_keys();
    let bytes = bundle.to_bytes().expect("to_bytes");

    // Every secret field of the keypair must be absent from the public blob.
    let secrets: [(&str, &[u8]); 4] = [
        ("ml_dsa_signing_key", &kp.ml_dsa_signing_key),
        ("ml_kem_decapsulation_key", &kp.ml_kem_decapsulation_key),
        ("ed25519_signing_key", &kp.ed25519_signing_key),
        ("x25519_secret_key", &kp.x25519_secret_key),
    ];
    for (name, secret) in secrets {
        assert!(
            !contains_subslice(&bytes, secret),
            "public bundle bytes must not contain {name}"
        );
    }
}

#[test]
fn downgrade_guard_survives_roundtrip() {
    let kp = KavachKeyPair::generate().expect("generate");

    // Hybrid chain, reconstructed hybrid verifier: OK.
    let hybrid_entries = build_chain(&kp, true, 3).entries();
    let bundle = PublicKeyBundle::from_bytes(&kp.public_keys().to_bytes().unwrap()).unwrap();
    verify_chain(&hybrid_entries, &Verifier::from_bundle(&bundle, true))
        .expect("hybrid chain under reconstructed hybrid verifier");

    // Same reconstructed bundle, PQ-only verifier against a hybrid chain: must fail.
    assert!(
        verify_chain(&hybrid_entries, &Verifier::from_bundle(&bundle, false)).is_err(),
        "PQ-only verifier must reject a hybrid chain (downgrade guard)"
    );

    // PQ-only chain, reconstructed PQ-only verifier: OK; hybrid verifier: must fail.
    let pq_entries = build_chain(&kp, false, 3).entries();
    verify_chain(&pq_entries, &Verifier::from_bundle(&bundle, false))
        .expect("pq-only chain under reconstructed pq-only verifier");
    assert!(
        verify_chain(&pq_entries, &Verifier::from_bundle(&bundle, true)).is_err(),
        "hybrid verifier must reject a PQ-only chain (downgrade guard)"
    );
}

#[test]
fn from_bytes_rejects_bad_header() {
    let kp = KavachKeyPair::generate().expect("generate");
    let mut bytes = kp.public_keys().to_bytes().expect("to_bytes");

    assert!(PublicKeyBundle::from_bytes(b"KV").is_err(), "too short");
    assert!(
        PublicKeyBundle::from_bytes(b"XXXX\x01{}").is_err(),
        "wrong magic"
    );
    // Corrupt the version byte.
    bytes[4] = 0xFF;
    assert!(
        PublicKeyBundle::from_bytes(&bytes).is_err(),
        "unsupported version must be rejected"
    );
}

#[test]
fn keypair_secret_bytes_roundtrip_preserves_identity() {
    let kp = KavachKeyPair::generate().expect("generate");
    let chain_before = build_chain(&kp, true, 2).entries();

    let secret = kp.to_secret_bytes().expect("to_secret_bytes");
    let reloaded = KavachKeyPair::from_secret_bytes(&secret).expect("from_secret_bytes");

    assert_eq!(kp.id, reloaded.id, "id preserved");
    assert_eq!(
        kp.public_keys(),
        reloaded.public_keys(),
        "public bundle identical after reload"
    );

    // A chain signed before the round-trip verifies under the reloaded key's bundle.
    let verifier = Verifier::from_bundle(&reloaded.public_keys(), true);
    verify_chain(&chain_before, &verifier).expect("pre-reload chain verifies under reloaded key");

    // And the reloaded key keeps signing the same continuous identity.
    let chain_after = build_chain(&reloaded, true, 2).entries();
    verify_chain(&chain_after, &Verifier::from_bundle(&kp.public_keys(), true))
        .expect("post-reload chain verifies under original bundle");
}

#[test]
fn keypair_from_secret_bytes_rejects_bad_header() {
    assert!(KavachKeyPair::from_secret_bytes(b"KV").is_err(), "too short");
    assert!(
        KavachKeyPair::from_secret_bytes(b"XXXX\x01{}").is_err(),
        "wrong magic"
    );
}

#[cfg(unix)]
#[test]
fn save_to_file_writes_owner_only_and_roundtrips() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("node-signer.key");

    let kp = KavachKeyPair::generate().expect("generate");
    kp.save_to_file(&path).expect("save_to_file");

    // 0600: owner rw only, no group/other bits.
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "new key file must be 0600, got {mode:o}");

    let reloaded = KavachKeyPair::load_from_file(&path).expect("load_from_file");
    assert_eq!(kp.id, reloaded.id);
    assert_eq!(kp.public_keys(), reloaded.public_keys());

    // Overwriting a deliberately-tightened file must not widen it.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    // 0400 is read-only for the owner; re-saving may fail to open for write, which
    // is acceptable (fail-closed). If it does succeed, the mode must not widen.
    if kp.save_to_file(&path).is_ok() {
        let mode2 = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert!(
            mode2 & 0o177 == 0,
            "existing file permissions must never be widened, got {mode2:o}"
        );
    }
}

#[cfg(unix)]
#[test]
fn save_to_file_tightens_a_previously_broad_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("broad.key");
    // Pre-create a world-readable placeholder.
    std::fs::write(&path, b"placeholder").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let kp = KavachKeyPair::generate().expect("generate");
    kp.save_to_file(&path).expect("save_to_file over broad file");

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "broad file must be tightened to 0600, got {mode:o}");
}

/// Naive substring search over byte slices, used to prove secrets are absent.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
