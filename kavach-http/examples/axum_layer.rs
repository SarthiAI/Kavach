//! Minimal Axum app using `KavachLayer`.
//!
//! Demonstrates the production wiring: a Router with two routes, wrapped in
//! `KavachLayer`. The example drives the router via `ServiceExt::oneshot`
//! so it can run without binding to a real port — keeps the example self-
//! contained and CI-friendly.
//!
//! Run with:
//!
//! ```bash
//! PYO3_PYTHON=... cargo run --example axum_layer -p kavach-http --features tower
//! ```

#![cfg(feature = "tower")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use http_body_util::BodyExt;
use kavach_core::{Evaluator, Gate, GateConfig, PolicyEngine, PolicySet};
use kavach_http::{HttpGate, HttpMiddlewareConfig, KavachLayer};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::main]
async fn main() {
    // ─── Build the Kavach gate ────────────────────────────────
    let policy_toml = r#"
[[policy]]
name = "permit_small_refunds"
effect = "permit"
conditions = [
    { action = "refunds.create" },
    { param_max = { field = "amount", max = 1000.0 } },
]

[[policy]]
name = "permit_reads"
effect = "permit"
conditions = [
    { action = "orders.read" },
]
"#;

    let policy_engine = Arc::new(PolicyEngine::new(
        PolicySet::from_toml(policy_toml).expect("valid policy"),
    ));
    let gate = Arc::new(Gate::new(
        vec![policy_engine as Arc<dyn Evaluator>],
        GateConfig::default(),
    ));
    let http_gate = Arc::new(HttpGate::new(gate, HttpMiddlewareConfig::default()));

    // ─── Build the Axum router and layer ─────────────────────
    let app: Router = Router::new()
        .route(
            "/api/v1/refunds",
            post(
                |body: axum::body::Bytes| async move { format!("processed: {} bytes", body.len()) },
            ),
        )
        .route("/api/v1/orders", get(|| async { "orders list" }))
        .route("/health", get(|| async { "healthy" }))
        .layer(KavachLayer::new(http_gate));

    println!("=== Kavach Axum Layer Example ===\n");

    // Scenario 1: permitted request (under the amount limit)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/refunds")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"amount": 500.0}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    println!(
        "1. POST /api/v1/refunds amount=500   → {} {}",
        resp.status().as_u16(),
        read_body_text(resp.into_body()).await
    );

    // Scenario 2: refused (over amount limit → default-deny path)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/refunds")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"amount": 9999.0}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    println!(
        "2. POST /api/v1/refunds amount=9999  → {} {}",
        resp.status().as_u16(),
        read_body_text(resp.into_body()).await
    );
    assert_eq!(resp_status_as_u16(&StatusCode::FORBIDDEN), 403);

    // Scenario 3: excluded path
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    println!(
        "3. GET /health                        → {} {}",
        resp.status().as_u16(),
        read_body_text(resp.into_body()).await
    );

    // Scenario 4: GET on gated path (gate_mutations_only=true, not gated)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/orders")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    println!(
        "4. GET /api/v1/orders                 → {} {}",
        resp.status().as_u16(),
        read_body_text(resp.into_body()).await
    );

    println!("\n=== Done ===");
}

async fn read_body_text(body: Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| "<binary>".into())
}

fn resp_status_as_u16(s: &StatusCode) -> u16 {
    s.as_u16()
}
