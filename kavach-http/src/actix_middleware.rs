//! Actix-web [`Transform`]/[`Service`] integration for [`HttpGate`].
//!
//! Enabled by the `actix` feature. Drops into any Actix `App` via
//! `App::wrap(KavachActixMiddleware::new(http_gate))`.
//!
//! The middleware buffers the request body up to a configurable cap (default
//! 64 KiB), converts the request into [`HttpRequest`] the gate understands,
//! runs the gate, and:
//!
//! - **Permit** → forwards the request (body reattached) to the inner service.
//! - **Refuse** → short-circuits with `403 Forbidden` (or `429 Too Many
//!   Requests` for rate-limit refusals, `401 Unauthorized` for identity /
//!   session failures), and a JSON body describing the refusal.
//! - **Invalidate** → short-circuits with `401 Unauthorized`.
//!
//! The response body type is [`EitherBody<B>`], `Left(B)` on permit (the
//! inner service's body passed through), `Right(BoxBody)` on refuse /
//! invalidate (Kavach-generated JSON body).
//!
//! # Session state
//!
//! Each request gets a fresh [`SessionState`] unless the caller wires up a
//! custom resolver via [`KavachActixMiddleware::with_session_fn`]. For
//! cookie- or bearer-token-backed sessions, plug your own in.

use crate::{HttpGate, HttpRequest};
use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{forward_ready, Payload, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::Error as ActixError;
use actix_web::http::StatusCode;
use actix_web::{HttpMessage, HttpResponse};
use bytes::{Bytes, BytesMut};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use futures_util::stream::{self, StreamExt};
use kavach_core::{RefuseCode, SessionState, Verdict};
use std::collections::HashMap;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::Arc;

/// Resolver that builds a [`SessionState`] for a given request. Defaults to
/// `SessionState::new()`.
pub type ActixSessionFn =
    Arc<dyn (Fn(&HttpRequest) -> SessionState) + Send + Sync + 'static>;

/// Actix [`Transform`] wrapping [`HttpGate`].
///
/// Use via `App::wrap(KavachActixMiddleware::new(gate))`.
#[derive(Clone)]
pub struct KavachActixMiddleware {
    gate: Arc<HttpGate>,
    session_fn: ActixSessionFn,
    max_buffered_body_bytes: usize,
}

impl KavachActixMiddleware {
    /// Build middleware around `gate`. Fresh session per request; up to 64
    /// KiB of request body is buffered for gate inspection.
    pub fn new(gate: Arc<HttpGate>) -> Self {
        Self {
            gate,
            session_fn: Arc::new(|_| SessionState::new()),
            max_buffered_body_bytes: 64 * 1024,
        }
    }

    /// Provide a custom session resolver (cookie extraction, bearer token
    /// lookup, etc.).
    pub fn with_session_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&HttpRequest) -> SessionState + Send + Sync + 'static,
    {
        self.session_fn = Arc::new(f);
        self
    }

    /// Configure the maximum request body bytes the middleware will buffer
    /// for gate evaluation. Bodies larger than this are **not** parsed,
    /// the gate sees `body = None`, and any invariant that depends on body
    /// params should already be backed by upstream size limits.
    pub fn with_max_buffered_body_bytes(mut self, limit: usize) -> Self {
        self.max_buffered_body_bytes = limit;
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for KavachActixMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Transform = KavachActixService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(KavachActixService {
            service: Rc::new(service),
            gate: self.gate.clone(),
            session_fn: self.session_fn.clone(),
            max_buffered_body_bytes: self.max_buffered_body_bytes,
        }))
    }
}

/// The [`Service`] produced by [`KavachActixMiddleware`].
pub struct KavachActixService<S> {
    service: Rc<S>,
    gate: Arc<HttpGate>,
    session_fn: ActixSessionFn,
    max_buffered_body_bytes: usize,
}

impl<S, B> Service<ServiceRequest> for KavachActixService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let gate = self.gate.clone();
        let session_fn = self.session_fn.clone();
        let max_body = self.max_buffered_body_bytes;

        Box::pin(async move {
            // Take the payload so we can decide whether to buffer it. Will
            // be reattached before calling the inner service (if we forward).
            let payload = req.take_payload();
            let buffered = collect_bounded_payload(payload, max_body).await;

            let http_req = build_http_request(&req, buffered.as_ref());

            // Reattach the buffered body as the request payload so the inner
            // service still sees the bytes. If we failed to buffer, pass an
            // empty payload, bodies larger than the cap are the caller's
            // responsibility to size-limit upstream.
            let bytes_for_payload = buffered.clone().unwrap_or_default();
            req.set_payload(bytes_to_payload(bytes_for_payload));

            if !gate.should_gate(&http_req) {
                let resp = service.call(req).await?;
                return Ok(resp.map_into_left_body());
            }

            let session = (session_fn)(&http_req);
            let verdict = gate.evaluate(&http_req, &session).await;

            match verdict {
                Verdict::Permit(_) => {
                    let resp = service.call(req).await?;
                    Ok(resp.map_into_left_body())
                }
                Verdict::Refuse(reason) => {
                    let status = match reason.code {
                        RefuseCode::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
                        RefuseCode::IdentityFailed | RefuseCode::SessionInvalid => {
                            StatusCode::UNAUTHORIZED
                        }
                        _ => StatusCode::FORBIDDEN,
                    };
                    let body = serde_json::json!({
                        "error": "kavach_refused",
                        "code": reason.code.to_string(),
                        "evaluator": reason.evaluator,
                        "reason": reason.reason,
                        "evaluation_id": reason.evaluation_id.to_string(),
                    });
                    Ok(short_circuit(req, status, body))
                }
                Verdict::Invalidate(scope) => {
                    let body = serde_json::json!({
                        "error": "kavach_invalidated",
                        "evaluator": scope.evaluator,
                        "reason": scope.reason,
                    });
                    Ok(short_circuit(req, StatusCode::UNAUTHORIZED, body))
                }
            }
        })
    }
}

fn short_circuit<B>(
    req: ServiceRequest,
    status: StatusCode,
    body: serde_json::Value,
) -> ServiceResponse<EitherBody<B>> {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let http_resp = HttpResponse::build(status)
        .content_type("application/json")
        .body(bytes);
    let (http_req, _) = req.into_parts();
    ServiceResponse::new(http_req, http_resp).map_into_right_body::<B>()
}

fn build_http_request(req: &ServiceRequest, body_bytes: Option<&Bytes>) -> HttpRequest {
    let path = req.path().to_string();
    let method = req.method().as_str().to_string();

    let query_params = req
        .query_string()
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect();

    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();

    let body = body_bytes
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok());

    HttpRequest {
        method,
        path,
        path_params: HashMap::new(),
        query_params,
        body,
        headers: headers.clone(),
        remote_ip: remote_ip_from_headers(&headers, req.peer_addr().map(|sa| sa.ip())),
    }
}

async fn collect_bounded_payload(mut payload: Payload, limit: usize) -> Option<Bytes> {
    let mut buf = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e, "failed to read body for gate evaluation");
                return None;
            }
        };
        if buf.len() + chunk.len() > limit {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(buf.freeze())
}

fn bytes_to_payload(bytes: Bytes) -> Payload {
    // Wrap the Bytes in a stream so Actix's Payload type can consume it.
    let stream = stream::once(async move { Ok::<_, actix_web::error::PayloadError>(bytes) });
    Payload::from(stream.boxed_local())
}

fn remote_ip_from_headers(
    headers: &HashMap<String, String>,
    peer: Option<IpAddr>,
) -> Option<IpAddr> {
    // Honor X-Forwarded-For (first entry) if present, else X-Real-IP,
    // then fall back to the socket peer IP (Actix exposes it).
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim())
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.trim().parse().ok())
        })
        .or(peer)
}
