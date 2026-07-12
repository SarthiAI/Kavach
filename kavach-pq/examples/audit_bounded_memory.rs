//! Bounded-memory audit chain, end to end.
//!
//! Demonstrates the fix for unbounded `SignedAuditChain` memory growth: a
//! `ManagedAuditChain` streams old entries to a JSONL file and prunes them from
//! RAM under a retention policy, while the full chain (on-disk file + in-memory
//! tail) still verifies from genesis.
//!
//! Run: `cargo run --example audit_bounded_memory -p kavach-pq`

use kavach_core::audit::AuditEntry;
use kavach_pq::audit::{parse_jsonl, verify_chain};
use kavach_pq::audit_sink::{ManagedAuditChain, RetentionPolicy, SinkFailurePolicy};
use kavach_pq::{KavachKeyPair, Signer, Verifier};
use std::time::Duration;
use uuid::Uuid;

fn mk_entry(i: u64) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4(),
        evaluation_id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        principal_id: format!("reviewer-{}", i % 20),
        action_name: "approve_payout".to_string(),
        resource: Some(format!("PAYOUT-{i}")),
        verdict: "permit".to_string(),
        verdict_detail: format!("token_id=tok-{i}"),
        decided_by: None,
        session_id: Uuid::new_v4(),
        ip: Some("10.0.0.1".to_string()),
        context_snapshot: None,
    }
}

fn main() {
    let kp = KavachKeyPair::generate().expect("keygen");
    let signer = Signer::from_keypair(&kp, true);
    let verifier = Verifier::from_bundle(&kp.public_keys(), true);

    let dir = std::env::temp_dir().join(format!("kavach-audit-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let sink_path = dir.join("audit.jsonl");

    // Cap the in-memory window at 500 entries OR ~2 MB, whichever comes first;
    // also flush on a 1s timer. Keep 50 most-recent entries hot.
    let policy = RetentionPolicy {
        max_entries: Some(500),
        max_bytes: Some(2_000_000),
        flush_interval: Some(Duration::from_secs(1)),
        min_retained: 50,
        on_sink_failure: SinkFailurePolicy::Buffer {
            buffer_ceiling: 100_000,
        },
    };
    let chain = ManagedAuditChain::with_file_sink(signer, &sink_path, policy);

    let total: u64 = 50_000;
    println!("Appending {total} audit entries through a bounded chain...");
    for i in 0..total {
        chain.append(&mk_entry(i)).expect("append");
    }
    // Bring the window to the floor so the numbers are crisp.
    chain.flush().expect("flush");

    let stats = chain.stats();
    println!("\n--- After {total} appends ---");
    println!("total appended     : {}", stats.entries_appended);
    println!("resident in RAM    : {} entries", stats.resident_entries);
    println!("resident bytes     : {} bytes", stats.resident_bytes);
    println!("evicted to disk    : {} entries", stats.entries_evicted);
    println!("on-disk file       : {}", sink_path.display());
    println!(
        "on-disk file size  : {} bytes",
        std::fs::metadata(&sink_path).map(|m| m.len()).unwrap_or(0)
    );

    assert!(
        stats.resident_entries <= 500,
        "in-memory window stayed bounded"
    );

    // Verify the full chain: on-disk evicted prefix + in-memory tail.
    let disk_bytes = std::fs::read(&sink_path).expect("read sink");
    let mut all = parse_jsonl(&disk_bytes).expect("parse disk");
    all.extend(chain.chain().entries());
    verify_chain(&all, &verifier).expect("full chain verifies from genesis");
    println!(
        "\nFull chain of {} entries (disk + tail) verifies from genesis. Memory stayed flat.",
        all.len()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
