//! # Example: REST API with Kavach
//!
//! A payment service API with endpoints for reading orders,
//! issuing refunds, and deleting records. Every mutating request
//! passes through Kavach's gate.
//!
//! Run: `cargo run --example http_api`
//!
//! This example shows:
//! - Setting up the HttpGate with custom config
//! - Auto-deriving action names from HTTP method + path
//! - Gating only mutations (GET passes through)
//! - Excluding health check endpoints
//! - Handling different principal types (user, agent, service)
//! - Observe-only mode for safe rollout

use kavach_core::{
    AuditLog, AuditSink, DriftEvaluator, Gate, GateConfig, Invariant, InvariantSet, PolicyEngine,
    PolicySet, SessionState, Verdict,
};
use kavach_http::{HttpGate, HttpMiddlewareConfig, HttpRequest};
use std::collections::HashMap;
use std::sync::Arc;

// ─── Kavach setup ────────────────────────────────────────────────

fn build_http_gate(observe_only: bool) -> (HttpGate, Arc<AuditLog>) {
    // 1. Policies
    let policy_toml = r#"
        [[policy]]
        name = "user_read_anything"
        effect = "permit"
        priority = 10
        conditions = [
            { identity_kind = "user" },
            { action = "orders.read" },
        ]

        [[policy]]
        name = "user_create_refund"
        effect = "permit"
        priority = 10
        conditions = [
            { identity_role = "support" },
            { action = "refunds.create" },
            { param_max = { field = "amount", max = 50000.0 } },
            { rate_limit = { max = 50, window = "1h" } },
        ]

        [[policy]]
        name = "admin_delete"
        effect = "permit"
        priority = 20
        conditions = [
            { identity_role = "admin" },
            { action = "orders.delete" },
            { time_window = "09:00-18:00" },
        ]

        [[policy]]
        name = "service_full_access"
        effect = "permit"
        priority = 30
        conditions = [
            { identity_kind = "service" },
            { identity_id = "payment-service" },
        ]
    "#;

    let policies = PolicySet::from_toml(policy_toml).expect("invalid policy config");
    let policy_engine = Arc::new(PolicyEngine::new(policies));

    // 2. Drift detection
    let drift = Arc::new(DriftEvaluator::with_defaults());

    // 3. Invariants
    let invariants = Arc::new(InvariantSet::new(vec![
        Invariant::param_max("max_refund_amount", "amount", 100_000.0),
        Invariant::blocked_actions(
            "no_drop_tables",
            vec!["tables.delete".to_string(), "database.delete".to_string()],
        ),
    ]));

    // 4. Audit log (in-memory for this example)
    let audit_log = Arc::new(AuditLog::new(1000));

    // 5. Gate
    let gate_config = GateConfig {
        observe_only,
        ..Default::default()
    };
    let gate = Gate::new(vec![policy_engine, drift, invariants], gate_config)
        .with_audit(audit_log.clone() as Arc<dyn AuditSink>);

    // 6. HTTP middleware config
    let http_config = HttpMiddlewareConfig {
        gate_mutations_only: true, // GET requests pass through
        excluded_paths: vec!["/health".to_string(), "/metrics".to_string()],
        ..Default::default()
    };

    let http_gate = HttpGate::new(Arc::new(gate), http_config);
    (http_gate, audit_log)
}

// ─── Helper to simulate requests ────────────────────────────────

fn make_request(
    method: &str,
    path: &str,
    principal_id: &str,
    roles: &str,
    body: Option<serde_json::Value>,
) -> HttpRequest {
    let mut headers = HashMap::new();
    headers.insert("X-Principal-Id".to_string(), principal_id.to_string());
    headers.insert("X-Roles".to_string(), roles.to_string());

    HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        path_params: HashMap::new(),
        query_params: HashMap::new(),
        body,
        headers,
        remote_ip: Some("10.0.1.50".parse().unwrap()),
    }
}

// ─── Simulated API server ────────────────────────────────────────

#[tokio::main]
async fn main() {
    let (http_gate, audit_log) = build_http_gate(false);
    let session = SessionState::new();

    println!("=== Kavach HTTP API Example ===\n");

    // ── 1. GET /health (excluded path, not gated) ────────────────

    println!("1. GET /health");
    let req = make_request("GET", "/health", "monitoring", "", None);
    if http_gate.should_gate(&req) {
        println!("   Gating...");
    } else {
        println!("   SKIPPED — excluded path, passes through\n");
    }

    // ── 2. GET /api/v1/orders (read, not gated in mutations-only) ─

    println!("2. GET /api/v1/orders (read request)");
    let req = make_request("GET", "/api/v1/orders", "user_123", "support", None);
    if http_gate.should_gate(&req) {
        println!("   Gating...");
    } else {
        println!("   SKIPPED — GET requests pass through (gate_mutations_only=true)");
    }
    println!("   Action would be: {}\n", req.derive_action_name());

    // ── 3. POST /api/v1/refunds (support agent, small amount) ────

    println!("3. POST /api/v1/refunds — support agent, ₹2,000");
    let req = make_request(
        "POST",
        "/api/v1/refunds",
        "agent_priya",
        "support",
        Some(serde_json::json!({
            "order_id": "ORD-5678",
            "amount": 2000.0,
            "reason": "defective item"
        })),
    );
    println!("   Action derived: {}", req.derive_action_name());

    if http_gate.should_gate(&req) {
        match http_gate.evaluate(&req, &session).await {
            Verdict::Permit(token) => {
                println!("   PERMITTED (token: {})\n", token.token_id);
            }
            Verdict::Refuse(reason) => {
                println!("   REFUSED — {}\n", reason);
            }
            Verdict::Invalidate(scope) => {
                println!("   INVALIDATED — {}\n", scope);
            }
        }
    }

    // ── 4. POST /api/v1/refunds (support agent, too large) ──────

    println!("4. POST /api/v1/refunds — support agent, ₹75,000 (over limit)");
    let req = make_request(
        "POST",
        "/api/v1/refunds",
        "agent_priya",
        "support",
        Some(serde_json::json!({
            "order_id": "ORD-9012",
            "amount": 75000.0,
            "reason": "bulk return"
        })),
    );

    if http_gate.should_gate(&req) {
        match http_gate.evaluate(&req, &session).await {
            Verdict::Permit(_) => {
                println!("   PERMITTED — unexpected!\n");
            }
            Verdict::Refuse(reason) => {
                println!("   REFUSED — {}\n", reason);
            }
            Verdict::Invalidate(scope) => {
                println!("   INVALIDATED — {}\n", scope);
            }
        }
    }

    // ── 5. DELETE /api/v1/orders/123 (admin) ─────────────────────

    println!("5. DELETE /api/v1/orders/123 — admin user");
    let req = make_request("DELETE", "/api/v1/orders/123", "admin_raj", "admin", None);
    println!("   Action derived: {}", req.derive_action_name());

    if http_gate.should_gate(&req) {
        match http_gate.evaluate(&req, &session).await {
            Verdict::Permit(token) => {
                println!("   PERMITTED (token: {})\n", token.token_id);
            }
            Verdict::Refuse(reason) => {
                println!("   REFUSED — {}\n", reason);
            }
            Verdict::Invalidate(scope) => {
                println!("   INVALIDATED — {}\n", scope);
            }
        }
    }

    // ── 6. DELETE /api/v1/orders/456 (non-admin, should fail) ────

    println!("6. DELETE /api/v1/orders/456 — regular support agent (not admin)");
    let req = make_request(
        "DELETE",
        "/api/v1/orders/456",
        "agent_priya",
        "support",
        None,
    );

    if http_gate.should_gate(&req) {
        match http_gate.evaluate(&req, &session).await {
            Verdict::Permit(_) => {
                println!("   PERMITTED — unexpected!\n");
            }
            Verdict::Refuse(reason) => {
                println!("   REFUSED — {}\n", reason);
            }
            Verdict::Invalidate(scope) => {
                println!("   INVALIDATED — {}\n", scope);
            }
        }
    }

    // ── 7. POST from unknown principal (default deny) ────────────

    println!("7. POST /api/v1/refunds — unknown principal, no roles");
    let req = make_request(
        "POST",
        "/api/v1/refunds",
        "anonymous",
        "",
        Some(serde_json::json!({ "amount": 100.0 })),
    );

    if http_gate.should_gate(&req) {
        match http_gate.evaluate(&req, &session).await {
            Verdict::Permit(_) => {
                println!("   PERMITTED — unexpected!\n");
            }
            Verdict::Refuse(reason) => {
                println!("   REFUSED — {}\n", reason);
            }
            Verdict::Invalidate(scope) => {
                println!("   INVALIDATED — {}\n", scope);
            }
        }
    }

    // ── Audit summary ────────────────────────────────────────────

    println!("─── Audit Log Summary ───");
    let entries = audit_log.entries();
    println!("Total evaluations: {}", entries.len());
    println!(
        "Permitted: {}",
        entries.iter().filter(|e| e.verdict == "permit").count()
    );
    println!(
        "Refused: {}",
        entries.iter().filter(|e| e.verdict == "refuse").count()
    );
    println!(
        "Invalidated: {}",
        entries.iter().filter(|e| e.verdict == "invalidate").count()
    );

    println!("\nRecent entries:");
    for entry in entries.iter().rev().take(5) {
        println!(
            "  [{}] {} → {} by {} — {}",
            entry.verdict.to_uppercase(),
            entry.principal_id,
            entry.action_name,
            entry.decided_by.as_deref().unwrap_or("all"),
            entry.verdict_detail
        );
    }

    // ── Observe-only demo ────────────────────────────────────────

    println!("\n─── Observe-Only Mode Demo ───");
    println!("(Same gate, but logs without blocking)\n");

    let (observe_gate, _observe_audit) = build_http_gate(true);

    let req = make_request(
        "POST",
        "/api/v1/refunds",
        "anonymous",
        "",
        Some(serde_json::json!({ "amount": 999999.0 })),
    );

    println!("8. Anonymous user, ₹9,99,999 refund (observe-only mode)");
    if observe_gate.should_gate(&req) {
        // HttpGate::evaluate now honors GateConfig::observe_only and
        // dispatches to Gate::evaluate_observe_only — always permits
        // while still logging what would have been blocked.
        match observe_gate.evaluate(&req, &session).await {
            Verdict::Permit(_) => {
                println!("   Would be REFUSED in enforcement mode");
                println!("   But in observe-only: logged and permitted");
                println!("   (Check audit logs to see what would be blocked)\n");
            }
            Verdict::Refuse(reason) => {
                println!("   REFUSED — {reason} (unexpected: observe-only should permit)\n");
            }
            Verdict::Invalidate(scope) => {
                println!("   INVALIDATED — {scope} (unexpected: observe-only should permit)\n");
            }
        }
    }

    println!("=== All scenarios complete ===");
}
