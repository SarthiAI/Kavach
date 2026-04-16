//! Actix-web + Kavach minimal integration.
//!
//! Run with:
//!
//! ```text
//! cargo run --example actix_middleware -p kavach-http --features actix
//! ```
//!
//! Then hit the server with:
//!
//! ```text
//! # Permitted: GET / (non-mutating, gate is bypassed by default config)
//! curl -i http://127.0.0.1:8787/
//!
//! # Permitted: POST /api/v1/refunds with any body (policy permits)
//! curl -i -X POST http://127.0.0.1:8787/api/v1/refunds \
//!     -H 'Content-Type: application/json' -d '{"amount": 50}'
//!
//! # Refused: POST /api/v1/refunds with amount > 5000 (param_max invariant)
//! curl -i -X POST http://127.0.0.1:8787/api/v1/refunds \
//!     -H 'Content-Type: application/json' -d '{"amount": 10000}'
//!
//! # Refused: POST /api/v1/secrets (no policy permits this action)
//! curl -i -X POST http://127.0.0.1:8787/api/v1/secrets \
//!     -H 'Content-Type: application/json' -d '{}'
//! ```

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use kavach_core::{
    Evaluator, Gate, GateConfig, Invariant, InvariantSet, PolicyEngine, PolicySet,
};
use kavach_http::{HttpGate, HttpMiddlewareConfig, KavachActixMiddleware};
use std::sync::Arc;

async fn root() -> impl Responder {
    HttpResponse::Ok().body("Kavach + Actix example — try POST /api/v1/refunds\n")
}

async fn issue_refund(body: web::Json<serde_json::Value>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "processed": body.into_inner(),
    }))
}

async fn create_secret() -> impl Responder {
    // This handler is never called in this example — Kavach refuses all
    // `secrets.create` actions since no policy permits them.
    HttpResponse::Ok().body("should not reach here")
}

fn build_http_gate() -> Arc<HttpGate> {
    let policy_toml = r#"
[[policy]]
name = "small_refunds"
effect = "permit"
priority = 10
conditions = [
    { action = "refunds.create" },
    { param_max = { field = "amount", max = 5000.0 } },
]
"#;
    let policies = PolicySet::from_toml(policy_toml).expect("valid policy toml");
    let policy_engine = Arc::new(PolicyEngine::new(policies));

    // Hard invariant: refund amount cannot exceed 50,000 regardless of
    // policy. If a future policy tries to permit a 100,000 refund, the
    // invariant still refuses it.
    let invariants = Arc::new(InvariantSet::new(vec![Invariant::param_max(
        "hard_refund_cap",
        "amount",
        50_000.0,
    )]));

    let gate = Arc::new(Gate::new(
        vec![
            policy_engine as Arc<dyn Evaluator>,
            invariants as Arc<dyn Evaluator>,
        ],
        GateConfig::default(),
    ));
    Arc::new(HttpGate::new(gate, HttpMiddlewareConfig::default()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let http_gate = build_http_gate();

    let addr = "127.0.0.1:8787";
    println!("Kavach + Actix listening on http://{addr}");

    HttpServer::new(move || {
        App::new()
            .wrap(KavachActixMiddleware::new(http_gate.clone()))
            .route("/", web::get().to(root))
            .route("/api/v1/refunds", web::post().to(issue_refund))
            .route("/api/v1/secrets", web::post().to(create_secret))
    })
    .bind(addr)?
    .run()
    .await
}
