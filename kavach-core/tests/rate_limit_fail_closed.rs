//! Fail-closed behavior tests for the pluggable RateLimitStore.
//!
//! These tests exercise the full `PolicyEngine` evaluation path with a
//! user-supplied [`RateLimitStore`] that returns errors, and confirm:
//!
//! 1. A store that fails on `record` causes the whole policy evaluation to
//!    refuse (rate-limit backend unreachable ≠ silent permit).
//! 2. A store that fails only on `count_in_window` causes any policy with a
//!    `RateLimit` condition to not match (condition evaluates to `false`),
//!    so default-deny kicks in.
//! 3. Backward compat: `PolicyEngine::new` with the default in-memory store
//!    still records and counts correctly across evaluations.

use async_trait::async_trait;
use kavach_core::{
    ActionContext, ActionDescriptor, EnvContext, Evaluator, Gate, GateConfig, PolicyEngine,
    PolicySet, Principal, PrincipalKind, RateLimitStore, RateLimitStoreError, SessionState,
    Verdict,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn make_ctx(action: &str) -> ActionContext {
    let principal = Principal {
        id: "p1".into(),
        kind: PrincipalKind::Agent,
        roles: vec!["role".into()],
        credentials_issued_at: chrono::Utc::now(),
        display_name: None,
    };
    ActionContext::new(
        principal,
        ActionDescriptor::new(action),
        SessionState::new(),
        EnvContext::default(),
    )
}

fn gate_for(engine: Arc<PolicyEngine>) -> Gate {
    Gate::new(vec![engine as Arc<dyn Evaluator>], GateConfig::default())
}

/// Store that fails on `record` and succeeds on count.
struct RecordFailingStore;

#[async_trait]
impl RateLimitStore for RecordFailingStore {
    async fn record(&self, _key: &str, _at: i64) -> Result<(), RateLimitStoreError> {
        Err(RateLimitStoreError::BackendUnavailable(
            "record down".into(),
        ))
    }
    async fn count_in_window(
        &self,
        _key: &str,
        _now: i64,
        _window_secs: u64,
    ) -> Result<u64, RateLimitStoreError> {
        Ok(0)
    }
}

/// Store that records fine but fails on every count query.
struct CountFailingStore;

#[async_trait]
impl RateLimitStore for CountFailingStore {
    async fn record(&self, _key: &str, _at: i64) -> Result<(), RateLimitStoreError> {
        Ok(())
    }
    async fn count_in_window(
        &self,
        _key: &str,
        _now: i64,
        _window_secs: u64,
    ) -> Result<u64, RateLimitStoreError> {
        Err(RateLimitStoreError::BackendUnavailable("count down".into()))
    }
}

/// Store that records metrics we can assert on afterwards.
#[derive(Default)]
struct SpyStore {
    records: AtomicU64,
    counts: AtomicU64,
}

#[async_trait]
impl RateLimitStore for SpyStore {
    async fn record(&self, _key: &str, _at: i64) -> Result<(), RateLimitStoreError> {
        self.records.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn count_in_window(
        &self,
        _key: &str,
        _now: i64,
        _window_secs: u64,
    ) -> Result<u64, RateLimitStoreError> {
        self.counts.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
}

#[tokio::test]
async fn record_failure_causes_evaluation_to_refuse() {
    let toml = r#"
[[policy]]
name = "permit_all"
effect = "permit"
conditions = [{ action = "act" }]
"#;
    let engine = Arc::new(PolicyEngine::with_rate_store(
        PolicySet::from_toml(toml).unwrap(),
        Arc::new(RecordFailingStore),
    ));
    let gate = gate_for(engine);

    let verdict = gate.evaluate(&make_ctx("act")).await;
    match verdict {
        Verdict::Refuse(reason) => {
            assert_eq!(reason.evaluator, "policy");
            assert!(
                reason.reason.contains("rate-limit"),
                "refuse reason should cite the rate-limit backend, got: {}",
                reason.reason
            );
        }
        other => panic!("record failure must refuse, got {other:?}"),
    }
}

#[tokio::test]
async fn count_failure_in_rate_limit_condition_defaults_to_no_match() {
    // A rate-limit-gated permit policy: if the store can't count, the
    // condition evaluates to `false`, the policy doesn't match, default-deny
    // kicks in → Refuse.
    let toml = r#"
[[policy]]
name = "permit_under_limit"
effect = "permit"
conditions = [
    { action = "act" },
    { rate_limit = { max = 5, window = "1m" } },
]
"#;
    let engine = Arc::new(PolicyEngine::with_rate_store(
        PolicySet::from_toml(toml).unwrap(),
        Arc::new(CountFailingStore),
    ));
    let gate = gate_for(engine);

    let verdict = gate.evaluate(&make_ctx("act")).await;
    assert!(
        matches!(verdict, Verdict::Refuse(_)),
        "count failure on rate-limited policy must refuse, got {verdict:?}"
    );
}

#[tokio::test]
async fn count_failure_does_not_affect_non_rate_limited_policy() {
    // A policy that does NOT use rate_limit should not be affected by a
    // flaky count backend — the hot path shouldn't artificially deny.
    // (record still succeeds; only count fails in this impl.)
    let toml = r#"
[[policy]]
name = "permit_no_limit"
effect = "permit"
conditions = [{ action = "act" }]
"#;
    let engine = Arc::new(PolicyEngine::with_rate_store(
        PolicySet::from_toml(toml).unwrap(),
        Arc::new(CountFailingStore),
    ));
    let gate = gate_for(engine);

    let verdict = gate.evaluate(&make_ctx("act")).await;
    assert!(
        matches!(verdict, Verdict::Permit(_)),
        "count failure on non-rate-limited policy must still permit, got {verdict:?}"
    );
}

#[tokio::test]
async fn custom_store_is_hit_on_record_and_on_matching_rate_condition() {
    let toml = r#"
[[policy]]
name = "permit_under_limit"
effect = "permit"
conditions = [
    { action = "act" },
    { rate_limit = { max = 5, window = "1m" } },
]
"#;
    let spy = Arc::new(SpyStore::default());
    let engine = Arc::new(PolicyEngine::with_rate_store(
        PolicySet::from_toml(toml).unwrap(),
        spy.clone() as Arc<dyn RateLimitStore>,
    ));
    let gate = gate_for(engine);

    gate.evaluate(&make_ctx("act")).await;
    gate.evaluate(&make_ctx("act")).await;

    assert_eq!(spy.records.load(Ordering::SeqCst), 2);
    assert!(
        spy.counts.load(Ordering::SeqCst) >= 2,
        "count_in_window should fire at least once per evaluation that reaches the rate-limit condition",
    );
}

#[tokio::test]
async fn default_new_preserves_in_memory_rate_limit_behavior() {
    // A policy that permits up to 2 calls per minute. The third call must
    // be refused because default-deny kicks in when the rate_limit condition
    // evaluates to `false`.
    let toml = r#"
[[policy]]
name = "limit_to_two"
effect = "permit"
conditions = [
    { action = "act" },
    { rate_limit = { max = 2, window = "1m" } },
]
"#;
    let engine = Arc::new(PolicyEngine::new(PolicySet::from_toml(toml).unwrap()));
    let gate = gate_for(engine);

    assert!(matches!(
        gate.evaluate(&make_ctx("act")).await,
        Verdict::Permit(_)
    ));
    assert!(matches!(
        gate.evaluate(&make_ctx("act")).await,
        Verdict::Permit(_)
    ));
    // Third call over the limit → refuse.
    assert!(matches!(
        gate.evaluate(&make_ctx("act")).await,
        Verdict::Refuse(_)
    ));
}
