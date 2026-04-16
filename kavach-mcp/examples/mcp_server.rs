//! # Example: MCP Server with Kavach
//!
//! A support-bot MCP server that exposes tools for reading orders
//! and issuing refunds. Every tool call passes through Kavach's gate.
//!
//! Run: `cargo run --example mcp_server`
//!
//! This example shows:
//! - Setting up the gate with policy, drift, and invariants
//! - Loading policies from a TOML file
//! - Gating tool calls through McpKavachLayer
//! - Handling Permit, Refuse, and Invalidate verdicts
//! - Session tracking across multiple tool calls

use kavach_core::{
    DriftEvaluator, Gate, GateConfig, Invariant, InvariantSet, PolicyEngine, PolicySet, Verdict,
};
use kavach_mcp::{McpCaller, McpCallerKind, McpKavachLayer, McpToolRequest};
use std::sync::Arc;

// ─── Your business logic (nothing Kavach-specific here) ──────────

async fn execute_read_order(order_id: &str) -> serde_json::Value {
    // In reality, this queries your database
    serde_json::json!({
        "order_id": order_id,
        "customer": "Priya Sharma",
        "amount": 2499.00,
        "currency": "INR",
        "status": "delivered"
    })
}

async fn execute_issue_refund(order_id: &str, amount: f64) -> serde_json::Value {
    // In reality, this calls your payment gateway
    println!("  >> Processing refund: ₹{} for order {}", amount, order_id);
    serde_json::json!({
        "refund_id": "ref_abc123",
        "order_id": order_id,
        "amount": amount,
        "status": "processed"
    })
}

// ─── Kavach setup ────────────────────────────────────────────────

fn build_kavach_layer() -> McpKavachLayer {
    // 1. Load policies from TOML
    //    In production, use PolicySet::from_file("kavach.toml")
    let policy_toml = r#"
        [[policy]]
        name = "agent_read_orders"
        effect = "permit"
        priority = 10
        conditions = [
            { identity_kind = "agent" },
            { action = "read_order" },
            { rate_limit = { max = 100, window = "1h" } },
        ]

        [[policy]]
        name = "agent_small_refunds"
        effect = "permit"
        priority = 10
        conditions = [
            { identity_kind = "agent" },
            { action = "issue_refund" },
            { param_max = { field = "amount", max = 5000.0 } },
            { rate_limit = { max = 20, window = "1h" } },
            { session_age_max = "4h" },
        ]
    "#;

    let policies = PolicySet::from_toml(policy_toml).expect("invalid policy config");
    let policy_engine = Arc::new(PolicyEngine::new(policies));

    // 2. Drift detection with defaults (geo, session age, device, behavior)
    let drift = Arc::new(DriftEvaluator::with_defaults());

    // 3. Hard invariants — these cannot be overridden by policy
    let invariants = Arc::new(InvariantSet::new(vec![
        Invariant::param_max("max_single_refund", "amount", 50_000.0),
        Invariant::max_actions_per_session("session_action_limit", 500),
    ]));

    // 4. Assemble the gate
    let gate = Arc::new(Gate::new(
        vec![policy_engine, drift, invariants],
        GateConfig::default(),
    ));

    // 5. Wrap in MCP layer
    McpKavachLayer::new(gate)
}

// ─── Simulated MCP server loop ───────────────────────────────────

#[tokio::main]
async fn main() {
    // Build the Kavach middleware
    let kavach = build_kavach_layer();

    // Simulated caller: an AI agent
    let agent = McpCaller {
        id: "support-bot-v2".to_string(),
        kind: McpCallerKind::Agent,
        roles: vec!["support_agent".to_string()],
        ip: Some("10.0.1.50".parse().unwrap()),
        client_name: Some("Claude Agent".to_string()),
    };

    let session_id = "session_001".to_string();

    println!("=== Kavach MCP Server Example ===\n");

    // ── Scenario 1: Read an order (should be permitted) ──────────

    println!("1. Agent reads order #ORD-7890");
    let request = McpToolRequest {
        tool_name: "read_order".to_string(),
        params: serde_json::json!({ "order_id": "ORD-7890" }),
        caller: agent.clone(),
        session_id: Some(session_id.clone()),
        metadata: Default::default(),
    };

    match kavach.check(&request).await {
        Verdict::Permit(_) => {
            let result = execute_read_order("ORD-7890").await;
            kavach.record_success(&request).await;
            println!("   PERMITTED — result: {}\n", result);
        }
        Verdict::Refuse(reason) => {
            println!("   REFUSED — {}\n", reason);
        }
        Verdict::Invalidate(scope) => {
            kavach.handle_invalidation(&request, &scope).await;
            println!("   INVALIDATED — {}\n", scope);
        }
    }

    // ── Scenario 2: Small refund (should be permitted) ───────────

    println!("2. Agent issues ₹500 refund for order #ORD-7890");
    let request = McpToolRequest {
        tool_name: "issue_refund".to_string(),
        params: serde_json::json!({
            "order_id": "ORD-7890",
            "amount": 500.0,
            "currency": "INR"
        }),
        caller: agent.clone(),
        session_id: Some(session_id.clone()),
        metadata: Default::default(),
    };

    match kavach.check(&request).await {
        Verdict::Permit(_) => {
            let result = execute_issue_refund("ORD-7890", 500.0).await;
            kavach.record_success(&request).await;
            println!("   PERMITTED — result: {}\n", result);
        }
        Verdict::Refuse(reason) => {
            println!("   REFUSED — {}\n", reason);
        }
        Verdict::Invalidate(scope) => {
            kavach.handle_invalidation(&request, &scope).await;
            println!("   INVALIDATED — {}\n", scope);
        }
    }

    // ── Scenario 3: Large refund (should be REFUSED by policy) ───

    println!("3. Agent tries ₹25,000 refund (exceeds agent limit)");
    let request = McpToolRequest {
        tool_name: "issue_refund".to_string(),
        params: serde_json::json!({
            "order_id": "ORD-7890",
            "amount": 25000.0,
            "currency": "INR"
        }),
        caller: agent.clone(),
        session_id: Some(session_id.clone()),
        metadata: Default::default(),
    };

    match kavach.check(&request).await {
        Verdict::Permit(_) => {
            println!("   PERMITTED — this should not happen!\n");
        }
        Verdict::Refuse(reason) => {
            println!("   REFUSED — {}\n", reason);
        }
        Verdict::Invalidate(scope) => {
            kavach.handle_invalidation(&request, &scope).await;
            println!("   INVALIDATED — {}\n", scope);
        }
    }

    // ── Scenario 4: Unknown tool (should be REFUSED, default deny) ─

    println!("4. Agent tries to call 'delete_customer' (no policy exists)");
    let request = McpToolRequest {
        tool_name: "delete_customer".to_string(),
        params: serde_json::json!({ "customer_id": "cust_456" }),
        caller: agent.clone(),
        session_id: Some(session_id.clone()),
        metadata: Default::default(),
    };

    match kavach.check(&request).await {
        Verdict::Permit(_) => {
            println!("   PERMITTED — this should not happen!\n");
        }
        Verdict::Refuse(reason) => {
            println!("   REFUSED — {}\n", reason);
        }
        Verdict::Invalidate(scope) => {
            kavach.handle_invalidation(&request, &scope).await;
            println!("   INVALIDATED — {}\n", scope);
        }
    }

    // ── Scenario 5: Stolen key, different IP (should INVALIDATE) ─

    println!("5. Same agent credentials, but from a different IP (possible stolen key)");
    let attacker = McpCaller {
        id: "support-bot-v2".to_string(), // Same ID as the real agent
        kind: McpCallerKind::Agent,
        roles: vec!["support_agent".to_string()],
        ip: Some("203.0.113.99".parse().unwrap()), // Different IP!
        client_name: Some("Claude Agent".to_string()),
    };

    let request = McpToolRequest {
        tool_name: "issue_refund".to_string(),
        params: serde_json::json!({
            "order_id": "ORD-7890",
            "amount": 100.0,
            "currency": "INR"
        }),
        caller: attacker,
        session_id: Some(session_id.clone()), // Using the same session
        metadata: Default::default(),
    };

    match kavach.check(&request).await {
        Verdict::Permit(_) => {
            println!("   PERMITTED — drift detection may not catch this without session origin tracking\n");
        }
        Verdict::Refuse(reason) => {
            println!("   REFUSED — {}\n", reason);
        }
        Verdict::Invalidate(scope) => {
            kavach.handle_invalidation(&request, &scope).await;
            println!("   INVALIDATED — {}\n", scope);
        }
    }

    println!("=== All scenarios complete ===");
}
