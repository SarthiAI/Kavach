# HTTP integration

Kavach ships three HTTP integration paths, listed from most general to most opinionated:

1. **[Framework-agnostic `HttpGate`](#framework-agnostic-httpgate)**: a thin wrapper that turns a generic `HttpRequest` struct into an `ActionContext` and runs the gate. Use this when you're on a framework not covered below (Rocket, Warp, Poem, Hyper-only, a custom one, an RPC layer that happens to look HTTP-ish).
2. **[Axum / Tower](#axum--tower-tower-feature)**: enabled by the `tower` feature. `KavachLayer` drops in via `.layer(...)` on any `tower`-based service (Axum, `tower-http`, `hyper-util`).
3. **[Actix-web](#actix-web-actix-feature)**: enabled by the `actix` feature. `KavachActixMiddleware` drops in via `App::wrap(...)`.

All three share the same semantics: a `Verdict::Permit` forwards to the inner handler, a `Verdict::Refuse` short-circuits with `403`/`401`/`429` and a JSON error body, and a `Verdict::Invalidate` short-circuits with `401` to force re-auth. The only differences are how the native request is translated into an [`HttpRequest`](../../kavach-http/src/lib.rs) and how the response body type is threaded through.

See [gate-and-verdicts.md](../concepts/gate-and-verdicts.md) for what a verdict means, and [policies.md](../concepts/policies.md) for how to write the rules the gate evaluates.

---

## Framework-agnostic `HttpGate`

`HttpGate` wraps an `Arc<Gate>` plus an `HttpMiddlewareConfig`. You hand it an [`HttpRequest`](../../kavach-http/src/lib.rs) (method, path, headers, optional parsed JSON body, optional remote IP) and a `SessionState`; it returns a `Verdict`.

Lifted from [kavach-http/examples/http_api.rs](../../kavach-http/examples/http_api.rs):

```rust
use kavach_core::{
    AuditLog, AuditSink, DriftEvaluator, Gate, GateConfig, Invariant, InvariantSet,
    PolicyEngine, PolicySet, SessionState, Verdict,
};
use kavach_http::{HttpGate, HttpMiddlewareConfig, HttpRequest};
use std::collections::HashMap;
use std::sync::Arc;

fn build_http_gate() -> (HttpGate, Arc<AuditLog>) {
    let policy_toml = r#"
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
    "#;

    let policies = PolicySet::from_toml(policy_toml).expect("invalid policy config");
    let policy_engine = Arc::new(PolicyEngine::new(policies));
    let drift = Arc::new(DriftEvaluator::with_defaults());
    let invariants = Arc::new(InvariantSet::new(vec![
        Invariant::param_max("max_refund_amount", "amount", 100_000.0),
        Invariant::blocked_actions(
            "no_drop_tables",
            vec!["tables.delete".to_string(), "database.delete".to_string()],
        ),
    ]));
    let audit_log = Arc::new(AuditLog::new(1000));

    let gate = Gate::new(vec![policy_engine, drift, invariants], GateConfig::default())
        .with_audit(audit_log.clone() as Arc<dyn AuditSink>);

    let http_config = HttpMiddlewareConfig {
        gate_mutations_only: true,
        excluded_paths: vec!["/health".to_string(), "/metrics".to_string()],
        ..Default::default()
    };

    (HttpGate::new(Arc::new(gate), http_config), audit_log)
}

#[tokio::main]
async fn main() {
    let (http_gate, _audit) = build_http_gate();
    let session = SessionState::new();

    let mut headers = HashMap::new();
    headers.insert("X-Principal-Id".to_string(), "agent_priya".to_string());
    headers.insert("X-Roles".to_string(), "support".to_string());

    let req = HttpRequest {
        method: "POST".into(),
        path: "/api/v1/refunds".into(),
        path_params: HashMap::new(),
        query_params: HashMap::new(),
        body: Some(serde_json::json!({
            "order_id": "ORD-5678",
            "amount": 2000.0,
            "reason": "defective item"
        })),
        headers,
        remote_ip: Some("10.0.1.50".parse().unwrap()),
    };

    if http_gate.should_gate(&req) {
        match http_gate.evaluate(&req, &session).await {
            Verdict::Permit(token) => println!("PERMITTED token={}", token.token_id),
            Verdict::Refuse(reason) => println!("REFUSED {reason}"),
            Verdict::Invalidate(scope) => println!("INVALIDATED {scope}"),
        }
    }
}
```

### What `HttpGate` does

- **Action derivation:** `HttpRequest::derive_action_name()` maps `POST /api/v1/refunds` to `refunds.create`, `DELETE /api/v1/users/123` to `users.delete`, `GET /api/v1/orders` to `orders.read`. The `/api` prefix, version segments (`/v1`), and numeric path segments are stripped so policies key on the resource, not the URL layout.
- **Principal extraction:** `config.principal_header` (default `X-Principal-Id`) plus `config.roles_header` (default `X-Roles`, comma-separated) become the `Principal`. Anything unrecognized defaults to an `anonymous` user with no roles: which, against a default-deny policy set, refuses.
- **Body-as-params:** a JSON object body has every top-level key copied into `action.params` so invariants like `param_max { field = "amount", max = 50000 }` can evaluate.
- **Path gating:** `gate_mutations_only = true` (default) lets `GET` pass without evaluation. `excluded_paths` skips any path that starts with a prefix in the list.
- **Observe-only:** when the underlying `Gate` has `GateConfig::observe_only = true`, `HttpGate::evaluate` dispatches to `Gate::evaluate_observe_only`, which logs what would have been refused but always returns `Permit`. This is the Phase-1-rollout path. See [operations/deployment-patterns.md](../operations/deployment-patterns.md) for the rollout playbook.

Use this path when you need to mount Kavach into a framework this guide doesn't cover. Your framework's request-parsing layer builds `HttpRequest`, you call `http_gate.evaluate(...)`, and you turn the `Verdict` into whatever response type the framework expects.

---

## Axum / Tower (`tower` feature)

Turn on `kavach-http`'s `tower` feature and you get a `KavachLayer` that drops into any `tower::ServiceBuilder` or Axum `Router`.

`Cargo.toml`:

```toml
[dependencies]
kavach-core = "0.1"
kavach-http = { version = "0.1", features = ["tower"] }
axum = "0.7"
tokio = { version = "1", features = ["full"] }
tower = "0.5"
```

Full runnable example, lifted from [kavach-http/examples/axum_layer.rs](../../kavach-http/examples/axum_layer.rs):

```rust
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

    let app: Router = Router::new()
        .route(
            "/api/v1/refunds",
            post(|body: axum::body::Bytes| async move {
                format!("processed: {} bytes", body.len())
            }),
        )
        .route("/api/v1/orders", get(|| async { "orders list" }))
        .route("/health", get(|| async { "healthy" }))
        .layer(KavachLayer::new(http_gate));

    // Permitted (amount under the policy cap).
    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/refunds")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"amount": 500.0}"#))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Refused (over the policy cap → default-deny path → 403).
    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/refunds")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"amount": 9999.0}"#))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Excluded path: passes through even without a policy.
    let resp = app.clone().oneshot(
        Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    let _ = resp.into_body().collect().await;
}
```

### Response body type

The layer's response body is `Either<InnerBody, Full<Bytes>>` (from `http_body_util`):

- On `Permit`, the inner service's body passes through as `Either::Left(inner)`.
- On `Refuse` / `Invalidate`, the layer emits a small JSON body as `Either::Right(Full<Bytes>)`.

This is the published alias `LayerResponseBody<B> = Either<B, KavachBody>` in [kavach-http/src/tower_layer.rs](../../kavach-http/src/tower_layer.rs). Axum's `Body` does not implement `From<Full<Bytes>>`, which is why the layer uses `Either` instead of asking the inner body type to absorb the Kavach body.

### Request body buffering

The layer reads the request body into memory up to `max_buffered_body_bytes` (default 64 KiB) so it can hand a parsed JSON body to the gate. Two guards:

- If `body.size_hint().upper()` reports a larger upper bound, the layer skips buffering entirely and the gate sees `body = None`.
- Even with no hint, once the collected bytes exceed the cap the layer drops the buffer and the gate sees `body = None`.

Policies that depend on body params must be paired with an upstream size limit (e.g., `tower-http`'s `RequestBodyLimitLayer`) so large uploads fail fast rather than silently bypassing body-based invariants.

Tune the cap with `.with_max_buffered_body_bytes(limit)`.

### Remote IP handling

`KavachService` reads `X-Forwarded-For` (first value) and falls back to `X-Real-IP`. Hyper doesn't expose the socket peer address via `request.parts`, so if you want a real IP you must put Kavach behind a trusted reverse proxy that sets one of these headers. Headers from untrusted clients give you whatever the client sends: treat IP as advisory in that case.

### Sessions

By default, every request gets a fresh `SessionState::new()`. For cookie- or bearer-token-backed sessions, plug in a resolver:

```rust
use kavach_core::SessionState;
use kavach_http::{HttpRequest, KavachLayer};
use std::sync::Arc;

let layer = KavachLayer::new(http_gate)
    .with_session_fn(|req: &HttpRequest| {
        if let Some(cookie) = req.headers.get("cookie") {
            if let Some(sid) = extract_session_id(cookie) {
                return lookup_session(&sid).unwrap_or_else(SessionState::new);
            }
        }
        SessionState::new()
    });

# fn extract_session_id(_: &str) -> Option<String> { None }
# fn lookup_session(_: &str) -> Option<SessionState> { None }
```

For a distributed session store that survives process restarts, wire a Redis-backed `SessionStore` into the resolver. See [distributed.md](distributed.md).

### Status codes

| Verdict | HTTP status | Body shape |
|---|---|---|
| `Permit` | whatever the inner handler returns | inner body |
| `Refuse` with `RefuseCode::RateLimitExceeded` | `429 Too Many Requests` | `{ "error": "kavach_refused", "code": "...", "evaluator": "...", "reason": "...", "evaluation_id": "..." }` |
| `Refuse` with `IdentityFailed` or `SessionInvalid` | `401 Unauthorized` | same JSON shape |
| `Refuse` (anything else) | `403 Forbidden` | same JSON shape |
| `Invalidate` | `401 Unauthorized` | `{ "error": "kavach_invalidated", "evaluator": "...", "reason": "..." }` |

---

## Actix-web (`actix` feature)

`Cargo.toml`:

```toml
[dependencies]
kavach-core = "0.1"
kavach-http = { version = "0.1", features = ["actix"] }
actix-web = "4"
```

Full runnable example, lifted from [kavach-http/examples/actix_middleware.rs](../../kavach-http/examples/actix_middleware.rs):

```rust
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use kavach_core::{
    Evaluator, Gate, GateConfig, Invariant, InvariantSet, PolicyEngine, PolicySet,
};
use kavach_http::{HttpGate, HttpMiddlewareConfig, KavachActixMiddleware};
use std::sync::Arc;

async fn root() -> impl Responder {
    HttpResponse::Ok().body("Kavach + Actix example\n")
}

async fn issue_refund(body: web::Json<serde_json::Value>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "processed": body.into_inner(),
    }))
}

async fn create_secret() -> impl Responder {
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

    // Hard invariant: refund amount cannot exceed 50,000 regardless of policy.
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
```

Then (from a separate shell):

```bash
# Permitted: under the 5,000 policy cap.
curl -i -X POST http://127.0.0.1:8787/api/v1/refunds \
    -H 'Content-Type: application/json' -d '{"amount": 50}'

# Refused by policy: over the 5,000 cap → 403.
curl -i -X POST http://127.0.0.1:8787/api/v1/refunds \
    -H 'Content-Type: application/json' -d '{"amount": 10000}'

# Refused by default-deny: no policy permits this action → 403.
curl -i -X POST http://127.0.0.1:8787/api/v1/secrets \
    -H 'Content-Type: application/json' -d '{}'
```

### Body reattachment

Actix exposes the request body as a `Payload` stream. The middleware takes the payload, buffers it up to 64 KiB (configurable via `.with_max_buffered_body_bytes(...)`), lets the gate inspect the parsed JSON, then reattaches the buffered bytes as a fresh `Payload` so the downstream handler still sees the body:

```text
request → take_payload() → buffer → build HttpRequest → gate.evaluate(...)
    │                           │
    │                           ├─ Permit   → set_payload(bytes) → call inner service
    │                           ├─ Refuse   → short_circuit (403/401/429)
    │                           └─ Invalidate → short_circuit (401)
```

If the body exceeds the cap, buffering is abandoned and the inner service receives an empty payload. Size-limit upstream (Actix's `PayloadConfig` or a reverse-proxy limit) for any route where that's unacceptable.

### Response body type

`ServiceResponse<EitherBody<B>>`: `Left(B)` on permit (inner handler's body), `Right(BoxBody)` on refuse/invalidate (Kavach-generated JSON).

### Remote IP handling

`X-Forwarded-For` (first value), then `X-Real-IP`, then the socket peer address (Actix exposes `peer_addr()`, unlike Hyper). Same trust caveat as the Tower layer: anything the client sends in the headers is attacker-controlled unless a trusted proxy sits in front.

### Sessions

Identical pattern to the Tower layer:

```rust
use kavach_core::SessionState;
use kavach_http::{HttpRequest, KavachActixMiddleware};

let mw = KavachActixMiddleware::new(http_gate.clone())
    .with_session_fn(|req: &HttpRequest| {
        // Build a SessionState from whatever your app stores
        // (cookie, bearer token, etc.).
        SessionState::new()
    });
```

### Status codes

Identical to the Tower layer: `429` for rate-limit, `401` for identity/session failures and invalidations, `403` for everything else refused, pass-through on permit.

---

## Further reading

- [concepts/gate-and-verdicts.md](../concepts/gate-and-verdicts.md): what a `Verdict` is and why `Invalidate` is distinct from `Refuse`.
- [concepts/evaluators.md](../concepts/evaluators.md): identity, policy, drift, invariants.
- [reference/policy-language.md](../reference/policy-language.md): every `Condition` type the TOML policies above use.
- [distributed.md](distributed.md): wiring Redis-backed stores when you run more than one instance.
- [operations/observability.md](../operations/observability.md): audit log, tracing integration, what to alert on.
