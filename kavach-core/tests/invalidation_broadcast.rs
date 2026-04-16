//! End-to-end tests for Gate + InvalidationBroadcaster wiring.
//!
//! Confirms:
//! 1. An `Invalidate` verdict triggers `broadcaster.publish(scope)`.
//! 2. `Permit` and `Refuse` verdicts do NOT publish.
//! 3. Broadcast failure does not downgrade the local `Invalidate` verdict.
//! 4. A listener subscribed to the broadcaster receives the same scope the
//!    gate published.

use async_trait::async_trait;
use kavach_core::verdict::{InvalidationScope, InvalidationTarget, RefuseCode, RefuseReason};
use kavach_core::{
    spawn_invalidation_listener, ActionContext, ActionDescriptor, BroadcastError, EnvContext,
    Evaluator, Gate, GateConfig, InMemoryInvalidationBroadcaster, InvalidationBroadcaster,
    Principal, PrincipalKind, SessionState, Verdict,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::time::{timeout, Duration};

fn principal() -> Principal {
    Principal {
        id: "p".into(),
        kind: PrincipalKind::Agent,
        roles: vec![],
        credentials_issued_at: chrono::Utc::now(),
        display_name: None,
    }
}

fn ctx() -> ActionContext {
    ActionContext::new(
        principal(),
        ActionDescriptor::new("act"),
        SessionState::new(),
        EnvContext::default(),
    )
}

/// Always returns a fixed verdict. Lets us trigger whichever branch we
/// want to test in `Gate::evaluate`.
struct FixedVerdictEvaluator {
    verdict: Mutex<Option<Verdict>>,
}

impl FixedVerdictEvaluator {
    fn new(verdict: Verdict) -> Self {
        Self {
            verdict: Mutex::new(Some(verdict)),
        }
    }
}

#[async_trait]
impl Evaluator for FixedVerdictEvaluator {
    fn name(&self) -> &str {
        "fixed"
    }
    fn priority(&self) -> u32 {
        10
    }
    async fn evaluate(&self, ctx: &ActionContext) -> Verdict {
        // Clone on every call — a single evaluator instance may be reused
        // across multiple gate invocations in some tests.
        let v = self.verdict.lock().unwrap().clone().unwrap_or_else(|| {
            Verdict::Refuse(RefuseReason {
                evaluator: "fixed".into(),
                reason: "default".into(),
                code: RefuseCode::PolicyDenied,
                evaluation_id: ctx.evaluation_id,
            })
        });
        v
    }
}

/// Spy broadcaster — records every publish. Wraps an InMemoryBroadcaster so
/// subscribers still receive the messages.
struct SpyBroadcaster {
    inner: InMemoryInvalidationBroadcaster,
    publishes: AtomicU64,
    last_reason: Mutex<Option<String>>,
}

impl SpyBroadcaster {
    fn new() -> Self {
        Self {
            inner: InMemoryInvalidationBroadcaster::new(),
            publishes: AtomicU64::new(0),
            last_reason: Mutex::new(None),
        }
    }
}

#[async_trait]
impl InvalidationBroadcaster for SpyBroadcaster {
    async fn publish(&self, scope: InvalidationScope) -> Result<(), BroadcastError> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        *self.last_reason.lock().unwrap() = Some(scope.reason.clone());
        self.inner.publish(scope).await
    }
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<InvalidationScope> {
        self.inner.subscribe()
    }
}

/// Broadcaster that always fails on publish.
struct FailingBroadcaster;

#[async_trait]
impl InvalidationBroadcaster for FailingBroadcaster {
    async fn publish(&self, _scope: InvalidationScope) -> Result<(), BroadcastError> {
        Err(BroadcastError::BackendUnavailable("down".into()))
    }
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<InvalidationScope> {
        // Unused in these tests — return a receiver that will stay idle.
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        rx
    }
}

#[tokio::test]
async fn invalidate_verdict_triggers_broadcaster_publish() {
    let spy = Arc::new(SpyBroadcaster::new());
    let invalidator = Arc::new(FixedVerdictEvaluator::new(Verdict::Invalidate(
        InvalidationScope {
            target: InvalidationTarget::Session(uuid::Uuid::new_v4()),
            reason: "drift-test".into(),
            evaluator: "fixed".into(),
        },
    ))) as Arc<dyn Evaluator>;

    let gate = Gate::new(vec![invalidator], GateConfig::default())
        .with_broadcaster(spy.clone() as Arc<dyn InvalidationBroadcaster>);

    let verdict = gate.evaluate(&ctx()).await;
    assert!(matches!(verdict, Verdict::Invalidate(_)));
    assert_eq!(spy.publishes.load(Ordering::SeqCst), 1);
    assert_eq!(
        spy.last_reason.lock().unwrap().clone().as_deref(),
        Some("drift-test")
    );
}

#[tokio::test]
async fn permit_verdict_does_not_publish() {
    let spy = Arc::new(SpyBroadcaster::new());
    // An evaluator that permits — gate will also issue its own final Permit.
    let permitter = Arc::new(FixedVerdictEvaluator::new(Verdict::Permit(
        kavach_core::verdict::PermitToken::new(uuid::Uuid::new_v4(), "act".into()),
    ))) as Arc<dyn Evaluator>;

    let gate = Gate::new(vec![permitter], GateConfig::default())
        .with_broadcaster(spy.clone() as Arc<dyn InvalidationBroadcaster>);

    let verdict = gate.evaluate(&ctx()).await;
    assert!(matches!(verdict, Verdict::Permit(_)));
    assert_eq!(spy.publishes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refuse_verdict_does_not_publish() {
    let spy = Arc::new(SpyBroadcaster::new());
    let refuser = Arc::new(FixedVerdictEvaluator::new(Verdict::Refuse(RefuseReason {
        evaluator: "fixed".into(),
        reason: "nope".into(),
        code: RefuseCode::PolicyDenied,
        evaluation_id: uuid::Uuid::new_v4(),
    }))) as Arc<dyn Evaluator>;

    let gate = Gate::new(vec![refuser], GateConfig::default())
        .with_broadcaster(spy.clone() as Arc<dyn InvalidationBroadcaster>);

    let verdict = gate.evaluate(&ctx()).await;
    assert!(matches!(verdict, Verdict::Refuse(_)));
    assert_eq!(spy.publishes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn broadcast_failure_does_not_downgrade_local_invalidate() {
    let invalidator = Arc::new(FixedVerdictEvaluator::new(Verdict::Invalidate(
        InvalidationScope {
            target: InvalidationTarget::Session(uuid::Uuid::new_v4()),
            reason: "test".into(),
            evaluator: "fixed".into(),
        },
    ))) as Arc<dyn Evaluator>;

    let gate = Gate::new(vec![invalidator], GateConfig::default())
        .with_broadcaster(Arc::new(FailingBroadcaster) as Arc<dyn InvalidationBroadcaster>);

    let verdict = gate.evaluate(&ctx()).await;
    assert!(
        matches!(verdict, Verdict::Invalidate(_)),
        "local verdict must remain Invalidate even when broadcast fails, got {verdict:?}"
    );
}

#[tokio::test]
async fn subscribed_listener_receives_scope_from_gate_publish() {
    let broadcaster: Arc<dyn InvalidationBroadcaster> =
        Arc::new(InMemoryInvalidationBroadcaster::new());

    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let r = received.clone();
    let listener = spawn_invalidation_listener(broadcaster.clone(), move |scope| {
        let r = r.clone();
        async move {
            r.lock().unwrap().push(scope.reason);
        }
    });
    tokio::task::yield_now().await;

    let invalidator = Arc::new(FixedVerdictEvaluator::new(Verdict::Invalidate(
        InvalidationScope {
            target: InvalidationTarget::Session(uuid::Uuid::new_v4()),
            reason: "e2e".into(),
            evaluator: "fixed".into(),
        },
    ))) as Arc<dyn Evaluator>;

    let gate =
        Gate::new(vec![invalidator], GateConfig::default()).with_broadcaster(broadcaster.clone());

    gate.evaluate(&ctx()).await;

    for _ in 0..50 {
        if received.lock().unwrap().iter().any(|r| r == "e2e") {
            listener.abort();
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("listener did not receive the gate's published scope");
}

#[tokio::test]
async fn default_gate_without_broadcaster_still_returns_invalidate() {
    // A gate constructed without `.with_broadcaster(...)` uses the no-op
    // broadcaster. Publishing is a no-op; the local verdict must still be
    // Invalidate. This confirms backward-compatible default behavior.
    let invalidator = Arc::new(FixedVerdictEvaluator::new(Verdict::Invalidate(
        InvalidationScope {
            target: InvalidationTarget::Session(uuid::Uuid::new_v4()),
            reason: "default".into(),
            evaluator: "fixed".into(),
        },
    ))) as Arc<dyn Evaluator>;

    let gate = Gate::new(vec![invalidator], GateConfig::default());
    let verdict = timeout(Duration::from_millis(500), gate.evaluate(&ctx()))
        .await
        .expect("evaluation must not hang on default no-op broadcaster");
    assert!(matches!(verdict, Verdict::Invalidate(_)));
}
