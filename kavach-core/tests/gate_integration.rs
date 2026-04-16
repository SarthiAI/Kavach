//! Integration tests for the gate.
//!
//! These tests exercise the gate end-to-end through its public API —
//! building an ActionContext, running it through evaluators, and asserting
//! on the resulting Verdict. They protect the product's core invariants:
//!
//! - **Default-deny**: an action matching no policy is refused, never permitted.
//! - **Invariants cannot be overridden** by policies.
//! - **Drift violations invalidate the session**, not just refuse the action.
//! - **The `Guarded<A>` wrapper** cannot be created without a gate verdict.

use kavach_core::{
    ActionContext, ActionDescriptor, EnvContext, Evaluator, Gate, GateConfig, Invariant,
    InvariantSet, PolicyEngine, PolicySet, Principal, PrincipalKind, SessionState,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn ctx(principal_id: &str, roles: Vec<&str>, action: &str) -> ActionContext {
    let principal = Principal {
        id: principal_id.to_string(),
        kind: PrincipalKind::Agent,
        roles: roles.into_iter().map(String::from).collect(),
        credentials_issued_at: chrono::Utc::now(),
        display_name: None,
    };
    let mut desc = ActionDescriptor::new(action);
    desc = desc.with_param("amount", json!(100.0));
    ActionContext::new(principal, desc, SessionState::new(), EnvContext::default())
}

fn build_gate(policy_toml: &str, invariants: Vec<Invariant>) -> Gate {
    let policy_set = PolicySet::from_toml(policy_toml).expect("policy parse");
    let policy_engine = Arc::new(PolicyEngine::new(policy_set));
    let mut evaluators: Vec<Arc<dyn Evaluator>> = vec![policy_engine];
    if !invariants.is_empty() {
        evaluators.push(Arc::new(InvariantSet::new(invariants)));
    }
    Gate::new(evaluators, GateConfig::default())
}

#[tokio::test]
async fn default_deny_with_no_matching_policy() {
    // A gate with an empty policy set must refuse every action — the
    // most important invariant in the whole product.
    let gate = build_gate("", Vec::new());
    let c = ctx("agent-alice", vec!["support"], "issue_refund");

    let verdict = gate.evaluate(&c).await;
    assert!(verdict.is_refuse(), "expected refuse, got {verdict:?}");
}

#[tokio::test]
async fn policy_permits_matching_action() {
    let toml = r#"
[[policy]]
name = "permit_refunds_for_support"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
]
"#;
    let gate = build_gate(toml, Vec::new());
    let verdict = gate
        .evaluate(&ctx("agent-alice", vec!["support"], "issue_refund"))
        .await;
    assert!(verdict.is_permit(), "expected permit, got {verdict:?}");
}

#[tokio::test]
async fn policy_refuses_when_role_missing() {
    let toml = r#"
[[policy]]
name = "permit_refunds_for_support"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
]
"#;
    let gate = build_gate(toml, Vec::new());
    let verdict = gate
        .evaluate(&ctx("agent-alice", vec!["readonly"], "issue_refund"))
        .await;
    assert!(verdict.is_refuse());
}

#[tokio::test]
async fn invariant_blocks_even_if_policy_permits() {
    // This is the core contract of invariants: a permissive policy cannot
    // override a structural invariant. Even though the policy permits any
    // refund for support agents, the invariant caps amount at 1000.
    let toml = r#"
[[policy]]
name = "permit_any_refund"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
]
"#;
    let gate = build_gate(
        toml,
        vec![Invariant::param_max("max_refund", "amount", 50.0)],
    );
    // Our default ctx() builds amount=100, which violates max=50.
    let verdict = gate
        .evaluate(&ctx("agent-alice", vec!["support"], "issue_refund"))
        .await;
    assert!(
        verdict.is_refuse(),
        "invariant must override policy, got {verdict:?}"
    );
}

#[tokio::test]
async fn invalidated_session_is_blocked_before_evaluators_run() {
    let toml = r#"
[[policy]]
name = "permit_all"
effect = "permit"
conditions = [{ action = "issue_refund" }]
"#;
    let gate = build_gate(toml, Vec::new());
    let mut c = ctx("agent-alice", vec![], "issue_refund");
    c.session.invalidated = true;
    let verdict = gate.evaluate(&c).await;
    assert!(verdict.is_refuse());
}

#[tokio::test]
async fn geo_drift_invalidates_session_on_ip_change() {
    use kavach_core::DriftEvaluator;

    let toml = r#"
[[policy]]
name = "permit_all"
effect = "permit"
conditions = [{ action = "issue_refund" }]
"#;
    let policies = Arc::new(PolicyEngine::new(PolicySet::from_toml(toml).unwrap()));
    let drift = Arc::new(DriftEvaluator::with_defaults());
    let gate = Gate::new(vec![policies, drift], GateConfig::default());

    let mut session = SessionState::new();
    session.origin_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    let principal = Principal {
        id: "agent-alice".into(),
        kind: PrincipalKind::Agent,
        roles: vec![],
        credentials_issued_at: chrono::Utc::now(),
        display_name: None,
    };
    let env = EnvContext {
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))), // different from origin
        ..Default::default()
    };
    let c = ActionContext::new(
        principal,
        ActionDescriptor::new("issue_refund"),
        session,
        env,
    );

    let verdict = gate.evaluate(&c).await;
    // Mid-session IP change → Invalidate
    assert!(
        verdict.is_invalidate(),
        "expected invalidate on IP change, got {verdict:?}"
    );
}

#[tokio::test]
async fn rate_limit_condition_blocks_after_threshold() {
    let toml = r#"
[[policy]]
name = "rate_limited_refunds"
effect = "permit"
conditions = [
    { action = "issue_refund" },
    { rate_limit = { max = 2, window = "1h" } },
]
"#;
    let gate = build_gate(toml, Vec::new());

    // First two calls permitted, third refused.
    for i in 0..2 {
        let verdict = gate
            .evaluate(&ctx("agent-alice", vec![], "issue_refund"))
            .await;
        assert!(
            verdict.is_permit(),
            "call {i} should permit, got {verdict:?}"
        );
    }
    let verdict = gate
        .evaluate(&ctx("agent-alice", vec![], "issue_refund"))
        .await;
    assert!(
        verdict.is_refuse(),
        "third call should be refused by rate limit, got {verdict:?}"
    );
}

#[tokio::test]
async fn policy_engine_hot_reload_changes_verdict() {
    // Build a gate where the policy engine is shared (via Arc) between the
    // test and the gate. After reload, the *same* gate instance must see the
    // new policies on the next call — no need to rebuild the gate.
    let initial_toml = r#"
[[policy]]
name = "permit_refunds"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
]
"#;
    let engine = Arc::new(PolicyEngine::new(
        PolicySet::from_toml(initial_toml).unwrap(),
    ));
    let evaluators: Vec<Arc<dyn Evaluator>> = vec![engine.clone()];
    let gate = Gate::new(evaluators, GateConfig::default());

    // Initial behavior: permitted.
    let ctx_support = ctx("agent-alice", vec!["support"], "issue_refund");
    assert!(gate.evaluate(&ctx_support).await.is_permit());

    // Hot-reload with a stricter policy: now only admins can refund.
    let tighter_toml = r#"
[[policy]]
name = "permit_refunds_admin_only"
effect = "permit"
conditions = [
    { identity_role = "admin" },
    { action = "issue_refund" },
]
"#;
    engine.reload(PolicySet::from_toml(tighter_toml).unwrap());
    assert_eq!(engine.policy_count(), 1);

    // Same support-role request is now refused under the reloaded policy.
    let verdict = gate
        .evaluate(&ctx("agent-alice", vec!["support"], "issue_refund"))
        .await;
    assert!(
        verdict.is_refuse(),
        "reloaded policy must refuse support role, got {verdict:?}"
    );

    // An admin is permitted under the new policy.
    let verdict = gate
        .evaluate(&ctx("agent-bob", vec!["admin"], "issue_refund"))
        .await;
    assert!(
        verdict.is_permit(),
        "reloaded policy must permit admin role, got {verdict:?}"
    );
}

#[tokio::test]
async fn policy_engine_reload_to_empty_is_default_deny() {
    // A reload that empties the policy set should lock the gate down
    // immediately — useful as a "policy kill switch" in incident response.
    let initial_toml = r#"
[[policy]]
name = "permit_all"
effect = "permit"
conditions = [{ action = "issue_refund" }]
"#;
    let engine = Arc::new(PolicyEngine::new(
        PolicySet::from_toml(initial_toml).unwrap(),
    ));
    let evaluators: Vec<Arc<dyn Evaluator>> = vec![engine.clone()];
    let gate = Gate::new(evaluators, GateConfig::default());

    assert!(gate
        .evaluate(&ctx("agent-alice", vec![], "issue_refund"))
        .await
        .is_permit());

    engine.reload(PolicySet::default());
    assert_eq!(engine.policy_count(), 0);

    assert!(gate
        .evaluate(&ctx("agent-alice", vec![], "issue_refund"))
        .await
        .is_refuse());
}

#[tokio::test]
async fn guarded_is_only_constructible_via_gate() {
    // This test is compile-time in spirit: if the line below compiled,
    // the type-safety invariant would be broken.
    //
    // let _fake = kavach_core::Guarded { ... };  // would not compile
    //
    // At runtime we verify that a successful `guard()` returns Ok
    // and that execute() consumes the guarded wrapper.
    use async_trait::async_trait;
    use kavach_core::{Action, KavachError};

    struct NoopRefund;

    #[async_trait]
    impl Action for NoopRefund {
        type Output = &'static str;
        fn descriptor(&self) -> ActionDescriptor {
            ActionDescriptor::new("issue_refund").with_param("amount", json!(10.0))
        }
        async fn execute(self) -> Result<&'static str, KavachError> {
            Ok("refunded")
        }
    }

    let toml = r#"
[[policy]]
name = "permit"
effect = "permit"
conditions = [{ action = "issue_refund" }]
"#;
    let gate = build_gate(toml, Vec::new());
    let c = ctx("agent-alice", vec![], "issue_refund");
    let guarded = gate.guard(&c, NoopRefund).await.expect("gate permits");
    let out = guarded.execute().await.expect("execute");
    assert_eq!(out, "refunded");
}
