//! Bounded-memory audit chain: prune primitive, anchored / segment
//! verification, the managed chain, and its retention policy.
//!
//! The security-critical set (tamper, reorder, drop, splice, boundary breaks)
//! lives alongside the memory-behavior set. The soak and concurrency stress
//! tests are `#[ignore]` so default `cargo test` stays fast; run them with:
//!
//! ```text
//! cargo test --release -p kavach-pq -- --ignored --nocapture
//! ```

use kavach_core::audit::AuditEntry;
use kavach_pq::audit::{verify_chain, verify_chain_from, verify_segments, SignedAuditEntry};
use kavach_pq::audit_sink::{
    AuditSink, ManagedAuditChain, RetentionPolicy, SinkFailurePolicy,
};
use kavach_pq::{KavachKeyPair, SignedAuditChain, Signer, Verifier};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

// ─── Helpers ─────────────────────────────────────────────────────

fn pq_pair() -> (Signer, Verifier) {
    let kp = KavachKeyPair::generate().unwrap();
    (
        Signer::new(kp.ml_dsa_signing_key.clone(), kp.id.clone()),
        Verifier::new(kp.ml_dsa_verifying_key.clone()),
    )
}

fn hybrid_pair() -> (Signer, Verifier) {
    let kp = KavachKeyPair::generate().unwrap();
    (
        Signer::from_keypair(&kp, true),
        Verifier::from_bundle(&kp.public_keys(), true),
    )
}

fn mk_entry(i: u64) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4(),
        evaluation_id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        principal_id: format!("user-{i}"),
        action_name: "issue_refund".to_string(),
        resource: Some(format!("ORD-{i}")),
        verdict: "permit".to_string(),
        verdict_detail: format!("token_id=tok-{i}"),
        decided_by: None,
        session_id: Uuid::new_v4(),
        ip: Some("10.0.0.1".to_string()),
        context_snapshot: None,
    }
}

/// A test sink that captures entries in order and can be toggled to fail.
struct FaultSink {
    fail: AtomicBool,
    captured: Mutex<Vec<SignedAuditEntry>>,
}

impl FaultSink {
    fn new() -> Self {
        Self {
            fail: AtomicBool::new(false),
            captured: Mutex::new(Vec::new()),
        }
    }
    fn set_fail(&self, v: bool) {
        self.fail.store(v, Ordering::SeqCst);
    }
    fn entries(&self) -> Vec<SignedAuditEntry> {
        self.captured.lock().unwrap().clone()
    }
}

impl AuditSink for FaultSink {
    fn append_segment(&self, entries: &[SignedAuditEntry]) -> kavach_pq::error::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(kavach_pq::error::PqError::Serialization(
                "injected sink failure".into(),
            ));
        }
        self.captured.lock().unwrap().extend_from_slice(entries);
        Ok(())
    }
}

/// Deterministic PRNG so the property test is reproducible without a dep.
struct XorShift(u64);
impl XorShift {
    fn new(seed: u64) -> Self {
        XorShift(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

// ─── Layer-1 primitive: prune / entries_since / base_index ───────

#[test]
fn prune_basic() {
    let (signer, _v) = pq_pair();
    let chain = SignedAuditChain::new(signer);
    let head_before_any = chain.head_hash();
    assert_eq!(head_before_any, "genesis");

    for i in 0..20 {
        chain.append(&mk_entry(i)).unwrap();
    }
    let head = chain.head_hash();

    let dropped = chain.prune_before(8);
    assert_eq!(dropped, 8);
    assert_eq!(chain.base_index(), 8);
    assert_eq!(chain.len(), 20); // total unchanged
    assert_eq!(chain.head_hash(), head); // head unchanged by prune
    assert_eq!(chain.resident_entries(), 12);
    assert_eq!(chain.entries_since(8).unwrap().len(), 12);
    // Asking for an evicted index is a loud error, not a partial tail.
    assert!(chain.entries_since(7).is_err());
}

#[test]
fn prune_noop_and_clamp() {
    let (signer, _v) = pq_pair();
    let chain = SignedAuditChain::new(signer);
    for i in 0..10 {
        chain.append(&mk_entry(i)).unwrap();
    }
    assert_eq!(chain.prune_before(0), 0); // no-op
    chain.prune_before(4);
    assert_eq!(chain.prune_before(4), 0); // <= base_index → no-op
    assert_eq!(chain.prune_before(3), 0); // below base_index → no-op
                                          // Over len clamps to len; drops the whole in-memory set.
    let dropped = chain.prune_before(9999);
    assert_eq!(dropped, 6); // 10 total, 4 already pruned
    assert_eq!(chain.base_index(), 10);
    assert_eq!(chain.resident_entries(), 0);
    assert_eq!(chain.len(), 10);
}

#[test]
fn append_after_prune_continues_chain() {
    let (signer, verifier) = pq_pair();
    let chain = SignedAuditChain::new(signer);
    let mut all = Vec::new();
    for i in 0..5 {
        all.push(chain.append(&mk_entry(i)).unwrap());
    }
    let head_before = chain.head_hash();
    chain.prune_before(5); // drop everything in memory
    assert_eq!(chain.resident_entries(), 0);
    assert_eq!(chain.anchor_hash(), head_before);

    // The next append chains from the pre-prune head.
    let e5 = chain.append(&mk_entry(5)).unwrap();
    all.push(e5.clone());
    assert_eq!(e5.previous_hash, head_before);
    assert_eq!(e5.index, 5);

    // The reconstructed full chain still verifies from genesis.
    verify_chain(&all, &verifier).expect("full chain after prune verifies");
}

#[test]
fn anchor_hash_tracks_base() {
    let (signer, verifier) = pq_pair();
    let chain = SignedAuditChain::new(signer);
    assert_eq!(chain.anchor_hash(), "genesis");
    let mut all = Vec::new();
    for i in 0..10 {
        all.push(chain.append(&mk_entry(i)).unwrap());
    }
    chain.prune_before(6);
    // Anchor is the previous_hash of entry 6 == entry_hash of entry 5.
    assert_eq!(chain.anchor_hash(), all[5].entry_hash);
    // The in-memory tail verifies from the anchor.
    let tail = chain.entries_since(6).unwrap();
    verify_chain_from(&tail, &verifier, &chain.anchor_hash())
        .expect("tail verifies from anchor");
    // A wrong anchor fails.
    assert!(verify_chain_from(&tail, &verifier, "genesis").is_err());
}

// ─── Verification / tamper (security-critical) ───────────────────

#[test]
fn verify_segments_ok_and_tamper() {
    let (signer, verifier) = pq_pair();
    let chain = SignedAuditChain::new(signer);
    let mut all = Vec::new();
    for i in 0..12 {
        all.push(chain.append(&mk_entry(i)).unwrap());
    }
    // Split into two on-disk segments + in-memory tail.
    let seg_a: Vec<_> = all[0..5].to_vec();
    let seg_b: Vec<_> = all[5..9].to_vec();
    chain.prune_before(9);
    let tail = chain.entries_since(9).unwrap();

    verify_segments(&[&seg_a, &seg_b, &tail], &verifier).expect("segments verify");

    // Tamper in a pruned (on-disk) entry: byte flip in the signed data.
    let mut seg_a_bad = seg_a.clone();
    seg_a_bad[2].signed_payload.data[0] ^= 0xFF;
    assert!(verify_segments(&[&seg_a_bad, &seg_b, &tail], &verifier).is_err());

    // Tamper in the in-memory tail.
    let mut tail_bad = tail.clone();
    tail_bad[0].signed_payload.ml_dsa_signature[0] ^= 0x01;
    assert!(verify_segments(&[&seg_a, &seg_b, &tail_bad], &verifier).is_err());

    // Reorder within a segment.
    let mut seg_a_reordered = seg_a.clone();
    seg_a_reordered.swap(1, 2);
    assert!(verify_segments(&[&seg_a_reordered, &seg_b, &tail], &verifier).is_err());

    // Drop an entry from the middle of a segment (broken link).
    let mut seg_b_gap = seg_b.clone();
    seg_b_gap.remove(1);
    assert!(verify_segments(&[&seg_a, &seg_b_gap, &tail], &verifier).is_err());

    // Gap at the boundary between segments (skip seg_b entirely).
    assert!(verify_segments(&[&seg_a, &tail], &verifier).is_err());
}

#[test]
fn segment_mode_splice_is_rejected() {
    // A PQ-only chain, verified with a hybrid verifier, must fail (downgrade
    // guard) even across the segmented path.
    let (signer, _pq_verifier) = pq_pair();
    let (_s2, hybrid_verifier) = hybrid_pair();
    let chain = SignedAuditChain::new(signer);
    let mut all = Vec::new();
    for i in 0..6 {
        all.push(chain.append(&mk_entry(i)).unwrap());
    }
    let seg: Vec<_> = all[0..3].to_vec();
    let tail: Vec<_> = all[3..6].to_vec();
    assert!(verify_segments(&[&seg, &tail], &hybrid_verifier).is_err());
}

// ─── Property-based: random append / prune interleavings ─────────

#[test]
fn property_random_append_prune() {
    for seed in [1u64, 7, 42, 12345] {
        let mut rng = XorShift::new(seed);
        let (signer, verifier) = pq_pair();
        let chain = SignedAuditChain::new(signer);
        let mut evicted: Vec<SignedAuditEntry> = Vec::new();
        let mut logical_head = 0u64;

        for _ in 0..30 {
            if rng.next() % 3 == 0 && chain.len() > 0 {
                let base = chain.base_index();
                let len = chain.len();
                let before = base + (rng.next() % (len - base + 1));
                let n = (before - base) as usize;
                let to_evict = chain.entries_since(base).unwrap();
                evicted.extend(to_evict.into_iter().take(n));
                let dropped = chain.prune_before(before);
                assert_eq!(dropped, before - base);
            } else {
                chain.append(&mk_entry(logical_head)).unwrap();
                logical_head += 1;
            }

            // Invariants after every step.
            assert_eq!(chain.len(), logical_head);
            assert!(chain.base_index() <= chain.len());
            let tail = chain.entries_since(chain.base_index()).unwrap();
            let mut full = evicted.clone();
            full.extend(tail);
            verify_chain(&full, &verifier).expect("full chain always verifies");
            let expected_head = full
                .last()
                .map(|e| e.entry_hash.clone())
                .unwrap_or_else(|| "genesis".to_string());
            assert_eq!(chain.head_hash(), expected_head);
        }
    }
}

// ─── Managed chain: bounded memory + policies ────────────────────

fn full_chain_from(sink: &FaultSink, mgr: &ManagedAuditChain) -> Vec<SignedAuditEntry> {
    let mut all = sink.entries();
    all.extend(mgr.chain().entries());
    all
}

#[test]
fn managed_bounded_by_count() {
    let (signer, verifier) = pq_pair();
    let sink = Arc::new(FaultSink::new());
    let policy = RetentionPolicy {
        max_entries: Some(50),
        max_bytes: None,
        flush_interval: None,
        min_retained: 5,
        on_sink_failure: SinkFailurePolicy::Buffer {
            buffer_ceiling: 10_000,
        },
    };
    let mgr = ManagedAuditChain::new(signer, sink.clone(), policy);
    for i in 0..400 {
        mgr.append(&mk_entry(i)).unwrap();
    }
    // Bring the window to the floor deterministically.
    mgr.flush().unwrap();
    assert_eq!(mgr.len(), 400);
    assert_eq!(mgr.resident_entries(), 5); // min_retained
    assert!(mgr.stats().entries_evicted >= 395);

    let full = full_chain_from(&sink, &mgr);
    assert_eq!(full.len(), 400);
    verify_chain(&full, &verifier).expect("full chain verifies");
}

#[test]
fn managed_bounded_by_bytes() {
    let (signer, verifier) = pq_pair();
    let sink = Arc::new(FaultSink::new());
    // One pq-only entry is ~4 KB; cap the window at ~40 KB.
    let policy = RetentionPolicy {
        max_entries: None,
        max_bytes: Some(40_000),
        flush_interval: None,
        min_retained: 2,
        on_sink_failure: SinkFailurePolicy::Buffer {
            buffer_ceiling: 10_000,
        },
    };
    let mgr = ManagedAuditChain::new(signer, sink.clone(), policy);
    for i in 0..300 {
        mgr.append(&mk_entry(i)).unwrap();
    }
    // The byte trigger fired during appends.
    assert!(mgr.stats().entries_evicted > 0);
    mgr.flush().unwrap();
    assert_eq!(mgr.resident_entries(), 2);
    assert!(mgr.resident_bytes() < 40_000);

    let full = full_chain_from(&sink, &mgr);
    assert_eq!(full.len(), 300);
    verify_chain(&full, &verifier).expect("full chain verifies");
}

#[test]
fn managed_periodic_flush() {
    let (signer, verifier) = pq_pair();
    let sink = Arc::new(FaultSink::new());
    let policy = RetentionPolicy {
        max_entries: None,
        max_bytes: None,
        flush_interval: Some(Duration::from_millis(40)),
        min_retained: 0,
        on_sink_failure: SinkFailurePolicy::Buffer {
            buffer_ceiling: 10_000,
        },
    };
    let mgr = ManagedAuditChain::new(signer, sink.clone(), policy);
    for i in 0..10 {
        mgr.append(&mk_entry(i)).unwrap();
    }
    // Below any size threshold: only the timer can evict. Give it a few cycles.
    std::thread::sleep(Duration::from_millis(300));
    let s = mgr.stats();
    assert_eq!(s.entries_evicted, 10, "periodic timer evicted everything");
    assert_eq!(mgr.resident_entries(), 0);

    let full = full_chain_from(&sink, &mgr);
    assert_eq!(full.len(), 10);
    verify_chain(&full, &verifier).expect("full chain verifies");
}

#[test]
fn managed_sink_failure_fail_closed_and_recovery() {
    let (signer, verifier) = pq_pair();
    let sink = Arc::new(FaultSink::new());
    sink.set_fail(true);
    let policy = RetentionPolicy {
        max_entries: Some(5),
        max_bytes: None,
        flush_interval: Some(Duration::from_millis(30)),
        min_retained: 1,
        on_sink_failure: SinkFailurePolicy::RejectAppends,
    };
    let mgr = ManagedAuditChain::new(signer, sink.clone(), policy);

    let mut ok = 0u64;
    let mut rejected = 0u64;
    for i in 0..200 {
        match mgr.append(&mk_entry(i)) {
            Ok(_) => ok += 1,
            Err(_) => rejected += 1,
        }
        if i % 10 == 0 {
            // Let the worker attempt (and fail) a flush so health flips.
            std::thread::sleep(Duration::from_millis(35));
        }
    }
    assert!(rejected > 0, "backpressure must reject once the sink is down");
    let s = mgr.stats();
    assert!(!s.sink_healthy);
    assert!(s.sink_failures > 0);
    // Memory stayed bounded under backpressure (never grew toward 200).
    assert!(
        mgr.resident_entries() <= 60,
        "resident stayed bounded under backpressure, was {}",
        mgr.resident_entries()
    );

    // Recover the sink and drain.
    sink.set_fail(false);
    while mgr.drain().unwrap_or(0) > 0 {}

    // No entry lost: every accepted append is now on the sink, in order.
    let persisted = sink.entries();
    assert_eq!(persisted.len() as u64, ok);
    verify_chain(&persisted, &verifier).expect("recovered chain verifies");
}

#[test]
fn managed_buffer_ceiling_rejects() {
    // The Buffer policy (as opposed to RejectAppends): when the sink is down the
    // buffer grows until it hits buffer_ceiling, after which append hard-rejects.
    let (signer, verifier) = pq_pair();
    let sink = Arc::new(FaultSink::new());
    sink.set_fail(true); // sink down from the start
    let policy = RetentionPolicy {
        max_entries: Some(5),
        max_bytes: None,
        flush_interval: Some(Duration::from_millis(30)),
        min_retained: 1,
        on_sink_failure: SinkFailurePolicy::Buffer { buffer_ceiling: 20 },
    };
    let mgr = ManagedAuditChain::new(signer, sink.clone(), policy);

    let mut ok = 0u64;
    let mut rejected = 0u64;
    for i in 0..200 {
        match mgr.append(&mk_entry(i)) {
            Ok(_) => ok += 1,
            Err(_) => rejected += 1,
        }
    }
    assert!(rejected > 0, "buffer ceiling must reject once the buffer is full");
    assert_eq!(ok, 20, "exactly buffer_ceiling entries were accepted");
    assert!(
        mgr.resident_entries() <= 20,
        "resident capped at buffer_ceiling, was {}",
        mgr.resident_entries()
    );

    // Recover and drain: every accepted entry persists, none lost.
    sink.set_fail(false);
    while mgr.drain().unwrap_or(0) > 0 {}
    let persisted = sink.entries();
    assert_eq!(persisted.len() as u64, ok);
    verify_chain(&persisted, &verifier).expect("chain verifies after recovery");
}

// ─── Concurrency stress (ignored by default) ─────────────────────

#[test]
#[ignore = "stress test; run explicitly with --ignored"]
fn concurrency_append_prune() {
    let (signer, verifier) = pq_pair();
    let chain = Arc::new(SignedAuditChain::new(signer));
    let n_producers = 4u64;
    let per = 5000u64;

    let stop = Arc::new(AtomicBool::new(false));
    let pruner = {
        let c = Arc::clone(&chain);
        let s = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                let len = c.len();
                if len > 100 {
                    c.prune_before(len - 100);
                }
                std::thread::yield_now();
            }
        })
    };

    let mut handles = Vec::new();
    for _ in 0..n_producers {
        let c = Arc::clone(&chain);
        handles.push(std::thread::spawn(move || {
            for i in 0..per {
                c.append(&mk_entry(i)).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    pruner.join().unwrap();

    assert_eq!(chain.len(), n_producers * per);
    let tail = chain.entries();
    // Retained window is contiguous and strictly increasing in index.
    for w in tail.windows(2) {
        assert_eq!(w[1].index, w[0].index + 1);
    }
    assert_eq!(chain.base_index() + tail.len() as u64, chain.len());
    // The retained tail verifies from the anchor.
    verify_chain_from(&tail, &verifier, &chain.anchor_hash())
        .expect("retained tail verifies from anchor");
}

// ─── Memory soak (ignored by default) ────────────────────────────

fn current_rss_kb() -> u64 {
    let pid = std::process::id();
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .trim()
            .parse::<u64>()
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Append N entries with periodic prune (managed) and assert resident memory
/// plateaus; contrast with a no-prune control that grows ~linearly. Override N
/// with KAVACH_SOAK_N.
#[test]
#[ignore = "soak test; run with: cargo test --release -p kavach-pq -- --ignored --nocapture"]
fn soak_plateau_vs_control() {
    let n: u64 = std::env::var("KAVACH_SOAK_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);

    // Pruned run: managed chain with a small window.
    let (signer, _v) = pq_pair();
    let sink = Arc::new(FaultSink::new());
    let policy = RetentionPolicy {
        max_entries: Some(2_000),
        max_bytes: None,
        flush_interval: Some(Duration::from_millis(50)),
        min_retained: 500,
        on_sink_failure: SinkFailurePolicy::Buffer {
            buffer_ceiling: 100_000,
        },
    };
    let mgr = ManagedAuditChain::new(signer, sink.clone(), policy);
    // Drop captured entries as we go so the sink itself does not grow (this
    // test measures the CHAIN's memory, not a toy sink).
    let mut samples = Vec::new();
    for i in 0..n {
        mgr.append(&mk_entry(i)).unwrap();
        if i % (n / 10).max(1) == 0 {
            sink.captured.lock().unwrap().clear();
            samples.push(current_rss_kb());
        }
    }
    mgr.flush().unwrap();
    let plateau = mgr.resident_entries();
    println!("[soak] pruned: appended {n}, resident_entries={plateau}, rss samples={samples:?}");
    assert!(
        plateau <= 2_000,
        "pruned window stayed bounded: {plateau}"
    );
    // Last-half RSS slope should be roughly flat, not linear in n.
    let half = samples.len() / 2;
    if samples.len() >= 4 && samples[half] > 0 {
        let first_half_growth = samples[half].saturating_sub(samples[1]);
        let second_half_growth = samples[samples.len() - 1].saturating_sub(samples[half]);
        println!(
            "[soak] rss growth first-half={first_half_growth}KB second-half={second_half_growth}KB"
        );
        // Second half should not grow much more than the first (plateau).
        assert!(
            second_half_growth <= first_half_growth + 50_000,
            "resident memory did not plateau: 1st={first_half_growth}KB 2nd={second_half_growth}KB"
        );
    }

    // Control: no prune, must grow ~linearly (proves the test has teeth).
    let control_n = (n / 5).max(1_000); // keep control smaller so it stays in RAM
    let (signer2, _v2) = pq_pair();
    let control = SignedAuditChain::new(signer2);
    let rss_before = current_rss_kb();
    for i in 0..control_n {
        control.append(&mk_entry(i)).unwrap();
    }
    let rss_after = current_rss_kb();
    println!(
        "[soak] control: appended {control_n} with NO prune, rss {rss_before}KB -> {rss_after}KB (grew {}KB)",
        rss_after.saturating_sub(rss_before)
    );
    assert_eq!(control.resident_entries(), control_n);
    assert!(
        rss_after > rss_before,
        "control (no prune) grew RSS as expected"
    );
}
