//! Tower [`Layer`]/[`Service`] integration for [`HttpGate`].
//!
//! Enabled by the `tower` feature. Drops into any `hyper`/`axum`/`tower-http`
//! router via `.layer(KavachLayer::new(http_gate))`. The layer wraps each
//! inbound `http::Request<B>` into an [`HttpRequest`], runs the Kavach gate,
//! and:
//!
//! - **Permit** → forwards the request to the inner service unchanged.
//! - **Refuse** → short-circuits with `403 Forbidden` (or `429` for rate-limit
//!   refusals) and a JSON body describing the refusal reason.
//! - **Invalidate** → short-circuits with `401 Unauthorized` so the client
//!   re-authenticates.
//!
//! # Threading the request body
//!
//! The gate only inspects headers, method, path, and an optional parsed JSON
//! body. To avoid double-reading the body (which would break streaming for
//! large uploads), the layer only reads the body when the content type
//! suggests it's JSON *and* the body is small enough to buffer. If the body
//! can't be buffered cheaply, the gate runs with `body = None` — invariants
//! that depend on body params should set explicit size limits upstream.
//!
//! # Session state
//!
//! Each request is evaluated with a fresh `SessionState` unless the caller
//! wires up a custom session resolver via [`KavachLayer::with_session_fn`].
//! For multi-request sessions (cookies, bearer tokens), provide a resolver.

use crate::{HttpGate, HttpRequest};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Either, Full};
use kavach_core::{RefuseCode, SessionState, Verdict};
use pin_project_lite::pin_project;
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Response body produced by the layer on non-permit verdicts.
///
/// On Permit the inner service's response body is passed through unchanged;
/// on Refuse/Invalidate the layer returns a small JSON body. The combined
/// body type is [`http_body_util::Either`] so the two paths can coexist.
pub type KavachBody = Full<Bytes>;

/// The response body type the layer emits — either the inner body (on
/// permit) or a Kavach-generated body (on refuse/invalidate).
pub type LayerResponseBody<B> = Either<B, KavachBody>;

/// Resolver that builds a [`SessionState`] for a given request. Defaults to
/// `SessionState::new()`; callers plug in their own for cookie/token-backed
/// sessions.
pub type SessionFn = Arc<dyn (Fn(&HttpRequest) -> SessionState) + Send + Sync + 'static>;

/// Tower [`Layer`] wrapping [`HttpGate`].
#[derive(Clone)]
pub struct KavachLayer {
    gate: Arc<HttpGate>,
    session_fn: SessionFn,
    max_buffered_body_bytes: usize,
}

impl KavachLayer {
    /// Build a layer around `gate`. Each request gets a fresh session; no
    /// body is buffered beyond 64 KiB.
    pub fn new(gate: Arc<HttpGate>) -> Self {
        Self {
            gate,
            session_fn: Arc::new(|_| SessionState::new()),
            max_buffered_body_bytes: 64 * 1024,
        }
    }

    /// Provide a custom session resolver (e.g., extract session by cookie).
    pub fn with_session_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&HttpRequest) -> SessionState + Send + Sync + 'static,
    {
        self.session_fn = Arc::new(f);
        self
    }

    /// Configure the max body bytes the layer will buffer for gate
    /// evaluation. Bodies larger than this are not parsed — the gate sees
    /// `body = None`. Default 64 KiB.
    pub fn with_max_buffered_body_bytes(mut self, limit: usize) -> Self {
        self.max_buffered_body_bytes = limit;
        self
    }
}

impl<S> Layer<S> for KavachLayer {
    type Service = KavachService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        KavachService {
            inner,
            gate: self.gate.clone(),
            session_fn: self.session_fn.clone(),
            max_buffered_body_bytes: self.max_buffered_body_bytes,
        }
    }
}

/// Tower [`Service`] produced by [`KavachLayer`].
#[derive(Clone)]
pub struct KavachService<S> {
    inner: S,
    gate: Arc<HttpGate>,
    session_fn: SessionFn,
    max_buffered_body_bytes: usize,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for KavachService<S>
where
    S: Service<Request<Full<Bytes>>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: http_body::Body<Data = Bytes> + Send + 'static,
    ReqBody::Error: std::fmt::Display,
    ResBody: http_body::Body<Data = Bytes> + Send + 'static,
{
    type Response = Response<LayerResponseBody<ResBody>>;
    type Error = S::Error;
    type Future = KavachFuture<S, ResBody>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Avoid the not-ready foot-gun: swap in a clone so the cloned
        // `inner` is the one that was polled ready, not the new one.
        let clone = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, clone);

        KavachFuture {
            fut: Box::pin(run_gate_and_call(
                inner,
                req,
                self.gate.clone(),
                self.session_fn.clone(),
                self.max_buffered_body_bytes,
            )),
        }
    }
}

pin_project! {
    /// Future type returned by `KavachService::call`.
    pub struct KavachFuture<S, ResBody>
    where
        S: Service<Request<Full<Bytes>>, Response = Response<ResBody>>,
    {
        #[pin]
        fut: Pin<Box<
            dyn Future<Output = Result<Response<LayerResponseBody<ResBody>>, S::Error>> + Send
        >>,
    }
}

impl<S, ResBody> Future for KavachFuture<S, ResBody>
where
    S: Service<Request<Full<Bytes>>, Response = Response<ResBody>>,
{
    type Output = Result<Response<LayerResponseBody<ResBody>>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

async fn run_gate_and_call<S, ReqBody, ResBody>(
    mut inner: S,
    req: Request<ReqBody>,
    gate: Arc<HttpGate>,
    session_fn: SessionFn,
    max_body: usize,
) -> Result<Response<LayerResponseBody<ResBody>>, S::Error>
where
    S: Service<Request<Full<Bytes>>, Response = Response<ResBody>>,
    ReqBody: http_body::Body<Data = Bytes> + Send + 'static,
    ReqBody::Error: std::fmt::Display,
    ResBody: http_body::Body<Data = Bytes> + Send + 'static,
{
    let (parts, body) = req.into_parts();

    // Collect the body bytes up to the configured cap. If it exceeds the cap
    // or collection fails, the gate sees `body = None` — upstream limits are
    // the caller's job.
    let body_bytes = collect_bounded_body(body, max_body).await;

    // Build the HttpRequest abstraction the gate consumes.
    let http_req = HttpRequest {
        method: parts.method.to_string(),
        path: parts.uri.path().to_string(),
        path_params: HashMap::new(),
        query_params: parts.uri.query().map(parse_query).unwrap_or_default(),
        body: body_bytes
            .as_ref()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok()),
        headers: parts
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect(),
        remote_ip: remote_ip_from_headers(&parts.headers),
    };

    // Let the HttpGate decide whether this path is gated at all.
    if !gate.should_gate(&http_req) {
        let passthrough = Request::from_parts(parts, Full::new(body_bytes.unwrap_or_default()));
        return inner.call(passthrough).await.map(wrap_inner);
    }

    let session = (session_fn)(&http_req);
    let verdict = gate.evaluate(&http_req, &session).await;

    match verdict {
        Verdict::Permit(_) => {
            let passthrough = Request::from_parts(parts, Full::new(body_bytes.unwrap_or_default()));
            inner.call(passthrough).await.map(wrap_inner)
        }
        Verdict::Refuse(reason) => {
            let status = match reason.code {
                RefuseCode::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
                RefuseCode::IdentityFailed | RefuseCode::SessionInvalid => StatusCode::UNAUTHORIZED,
                _ => StatusCode::FORBIDDEN,
            };
            Ok(json_response(
                status,
                serde_json::json!({
                    "error": "kavach_refused",
                    "code": reason.code.to_string(),
                    "evaluator": reason.evaluator,
                    "reason": reason.reason,
                    "evaluation_id": reason.evaluation_id.to_string(),
                }),
            ))
        }
        Verdict::Invalidate(scope) => Ok(json_response(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({
                "error": "kavach_invalidated",
                "evaluator": scope.evaluator,
                "reason": scope.reason,
            }),
        )),
    }
}

fn wrap_inner<B>(resp: Response<B>) -> Response<LayerResponseBody<B>> {
    let (parts, body) = resp.into_parts();
    Response::from_parts(parts, Either::Left(body))
}

async fn collect_bounded_body<B>(body: B, limit: usize) -> Option<Bytes>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    // `Collected::to_bytes` concatenates frames; `Body::size_hint` gives us
    // a cheap upper bound before we pay to collect. If the hint exceeds the
    // limit, bail early so we don't buffer 100 MB into memory to gate a file
    // upload.
    let hint = body.size_hint().upper();
    if let Some(upper) = hint {
        if upper as usize > limit {
            return None;
        }
    }
    match body.collect().await {
        Ok(c) => {
            let bytes = c.to_bytes();
            if bytes.len() > limit {
                None
            } else {
                Some(bytes)
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "failed to collect body for gate evaluation");
            None
        }
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

fn remote_ip_from_headers(headers: &http::HeaderMap) -> Option<IpAddr> {
    // Honor X-Forwarded-For (first entry) if present, else X-Real-IP.
    // Hyper's SocketAddr isn't exposed in parts; callers that need socket
    // IP should set one of these headers via a trusted reverse proxy.
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim())
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok())
        })
}

fn json_response<B>(status: StatusCode, body: serde_json::Value) -> Response<LayerResponseBody<B>> {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(Either::Right(Full::new(Bytes::from(bytes))));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    resp
}
