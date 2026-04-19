//! End-to-end tests for [`KavachActixMiddleware`].
//!
//! Exercises the gate through a real Actix App via `actix_web::test`.

#![cfg(feature = "actix")]

use actix_web::{test, web, App, HttpResponse};
use kavach_core::{Evaluator, Gate, GateConfig, PolicyEngine, PolicySet};
use kavach_http::{HttpGate, HttpMiddlewareConfig, KavachActixMiddleware};
use std::sync::Arc;

/// Build an HttpGate with a policy set that permits one specific action
/// (`refunds.create` on /api/v1/refunds for principal kind = user with role
/// = admin). Anything else default-denies.
/// Permit any `refunds.create` action. Keeps tests focused on the
/// middleware glue, not the policy engine.
fn refunds_ok_http_gate() -> Arc<HttpGate> {
    let policy_toml = r#"
[[policy]]
name = "refunds_ok"
effect = "permit"
priority = 10
conditions = [
    { action = "refunds.create" },
]
"#;
    let policies = PolicySet::from_toml(policy_toml).expect("valid policy toml");
    let policy_engine = Arc::new(PolicyEngine::new(policies));
    let gate = Arc::new(Gate::new(
        vec![policy_engine as Arc<dyn Evaluator>],
        GateConfig::default(),
    ));
    Arc::new(HttpGate::new(gate, HttpMiddlewareConfig::default()))
}

/// Default-deny gate, no policy permits anything. Used for refuse-path
/// tests.
fn default_deny_http_gate() -> Arc<HttpGate> {
    let policy_engine = Arc::new(PolicyEngine::new(PolicySet::default()));
    let gate = Arc::new(Gate::new(
        vec![policy_engine as Arc<dyn Evaluator>],
        GateConfig::default(),
    ));
    Arc::new(HttpGate::new(gate, HttpMiddlewareConfig::default()))
}

fn observe_only_http_gate() -> Arc<HttpGate> {
    let policy_engine = Arc::new(PolicyEngine::new(PolicySet::default()));
    let gate = Arc::new(Gate::new(
        vec![policy_engine as Arc<dyn Evaluator>],
        GateConfig {
            observe_only: true,
            ..Default::default()
        },
    ));
    Arc::new(HttpGate::new(gate, HttpMiddlewareConfig::default()))
}

async fn handler_ok() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

#[actix_web::test]
async fn permit_forwards_to_inner_handler() {
    let http_gate = refunds_ok_http_gate();
    let app = test::init_service(
        App::new()
            .wrap(KavachActixMiddleware::new(http_gate))
            .route("/api/v1/refunds", web::post().to(handler_ok)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/refunds")
        .set_json(serde_json::json!({ "amount": 100 }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body = test::read_body(resp).await;
    assert_eq!(body, "ok");
}

#[actix_web::test]
async fn refuse_yields_403_with_json_body() {
    // Default-deny gate, no policy permits anything, so this request
    // should be refused with a 403 + JSON body.
    let http_gate = default_deny_http_gate();
    let app = test::init_service(
        App::new()
            .wrap(KavachActixMiddleware::new(http_gate))
            .route("/api/v1/refunds", web::post().to(handler_ok)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/refunds")
        .insert_header(("X-Principal-Id", "bob"))
        .set_json(serde_json::json!({ "amount": 100 }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
    let body = test::read_body(resp).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"], "kavach_refused");
    assert!(v["reason"].is_string());
    assert!(v["code"].is_string());
}

#[actix_web::test]
async fn excluded_path_bypasses_gate() {
    // The default HttpMiddlewareConfig excludes /health and /ready. Even
    // with a default-deny gate (which would refuse any mutating request),
    // a GET to /health must pass through untouched.
    let http_gate = default_deny_http_gate();
    let app = test::init_service(
        App::new()
            .wrap(KavachActixMiddleware::new(http_gate))
            .route("/health", web::get().to(handler_ok)),
    )
    .await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

#[actix_web::test]
async fn non_mutating_request_bypasses_by_default() {
    // Default config: gate_mutations_only = true. A GET must pass through
    // even with a default-deny gate (because the gate isn't consulted).
    let http_gate = default_deny_http_gate();
    let app = test::init_service(
        App::new()
            .wrap(KavachActixMiddleware::new(http_gate))
            .route("/api/v1/refunds", web::get().to(handler_ok)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/refunds")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

#[actix_web::test]
async fn observe_only_permits_even_when_policy_would_refuse() {
    // Observe-only gate with empty policies would default-deny in enforce
    // mode; in observe mode it must always Permit.
    let http_gate = observe_only_http_gate();
    let app = test::init_service(
        App::new()
            .wrap(KavachActixMiddleware::new(http_gate))
            .route("/api/v1/refunds", web::post().to(handler_ok)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/refunds")
        .set_json(serde_json::json!({ "amount": 100 }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

#[actix_web::test]
async fn body_bytes_reach_inner_handler_after_permit() {
    // The middleware takes the payload for gate eval; it must reattach it so
    // the inner handler still sees the request body.
    async fn echo_handler(body: web::Bytes) -> HttpResponse {
        HttpResponse::Ok().body(body)
    }

    let http_gate = refunds_ok_http_gate();
    let app = test::init_service(
        App::new()
            .wrap(KavachActixMiddleware::new(http_gate))
            .route("/api/v1/refunds", web::post().to(echo_handler)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/refunds")
        .set_json(serde_json::json!({ "amount": 100 }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body = test::read_body(resp).await;
    let echoed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(echoed["amount"], 100);
}

#[actix_web::test]
async fn oversize_body_causes_policy_to_see_none() {
    // With a 32-byte body cap, a 1 KiB body causes the gate to see body =
    // None. The policy is admin-only (not body-dependent) so the permit
    // still fires; this test confirms the over-size path doesn't error.
    let http_gate = refunds_ok_http_gate();
    let app = test::init_service(
        App::new()
            .wrap(
                KavachActixMiddleware::new(http_gate)
                    .with_max_buffered_body_bytes(32),
            )
            .route("/api/v1/refunds", web::post().to(handler_ok)),
    )
    .await;

    // 1 KiB JSON body, way over the 32-byte cap.
    let big_body = serde_json::json!({
        "amount": 100,
        "padding": "x".repeat(1024),
    });

    let req = test::TestRequest::post()
        .uri("/api/v1/refunds")
        .set_json(big_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Permit still fires because the policy doesn't depend on body params;
    // the over-size body is now empty but that's fine for this policy.
    assert_eq!(resp.status().as_u16(), 200);
}
