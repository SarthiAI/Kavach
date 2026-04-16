//! # Kavach HTTP
//!
//! HTTP middleware that gates API endpoints through Kavach's execution boundary.
//!
//! Framework-agnostic core with thin adapters for Axum, Actix, and Tower.
//! Every mutating request (POST, PUT, DELETE, PATCH) passes through the gate.
//!
//! # Example with Axum (requires the `tower` feature)
//!
//! ```ignore
//! use std::sync::Arc;
//! use axum::{Router, routing::post};
//! use kavach_http::{HttpGate, HttpMiddlewareConfig, KavachLayer};
//!
//! let http_gate = Arc::new(HttpGate::new(gate, HttpMiddlewareConfig::default()));
//! let app: Router = Router::new()
//!     .route("/refund", post(handle_refund))
//!     .layer(KavachLayer::new(http_gate));
//! ```

use kavach_core::{
    ActionContext, ActionDescriptor, EnvContext, Gate, Principal, PrincipalKind, SessionState,
    Verdict,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[cfg(feature = "tower")]
pub mod tower_layer;

#[cfg(feature = "tower")]
pub use tower_layer::{KavachBody, KavachFuture, KavachLayer, KavachService, LayerResponseBody};

#[cfg(feature = "actix")]
pub mod actix_middleware;

#[cfg(feature = "actix")]
pub use actix_middleware::{KavachActixMiddleware, KavachActixService};

/// An HTTP request abstracted for Kavach evaluation.
///
/// Framework adapters convert their native request types into this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    /// HTTP method (GET, POST, PUT, DELETE, PATCH).
    pub method: String,

    /// Request path (e.g., "/api/v1/refunds").
    pub path: String,

    /// Extracted route parameters (e.g., { "id": "12345" }).
    #[serde(default)]
    pub path_params: HashMap<String, String>,

    /// Query parameters.
    #[serde(default)]
    pub query_params: HashMap<String, String>,

    /// Request body (parsed as JSON if applicable).
    pub body: Option<serde_json::Value>,

    /// Request headers relevant to identity/context.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Caller's IP address.
    pub remote_ip: Option<IpAddr>,
}

impl HttpRequest {
    /// Derive an action name from method + path.
    ///
    /// Maps: `POST /api/v1/refunds` → `refunds.create`
    ///       `DELETE /api/v1/users/123` → `users.delete`
    ///       `GET /api/v1/orders` → `orders.read`
    pub fn derive_action_name(&self) -> String {
        // Extract the resource name from the path
        let resource = self
            .path
            .split('/')
            .filter(|s| !s.is_empty() && *s != "api" && !s.starts_with('v')).rfind(|s| s.parse::<u64>().is_err())
            .unwrap_or("unknown");

        let verb = match self.method.to_uppercase().as_str() {
            "GET" => "read",
            "POST" => "create",
            "PUT" | "PATCH" => "update",
            "DELETE" => "delete",
            _ => "unknown",
        };

        format!("{resource}.{verb}")
    }

    /// Check if this is a mutating request.
    pub fn is_mutating(&self) -> bool {
        matches!(
            self.method.to_uppercase().as_str(),
            "POST" | "PUT" | "PATCH" | "DELETE"
        )
    }
}

/// Configuration for the HTTP middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpMiddlewareConfig {
    /// Only gate mutating requests (POST/PUT/DELETE/PATCH).
    /// GET requests pass through without evaluation.
    #[serde(default = "default_true")]
    pub gate_mutations_only: bool,

    /// Paths to exclude from gating (e.g., health checks).
    #[serde(default)]
    pub excluded_paths: Vec<String>,

    /// Header name containing the principal ID (default: "X-Principal-Id").
    #[serde(default = "default_principal_header")]
    pub principal_header: String,

    /// Header name containing roles (comma-separated, default: "X-Roles").
    #[serde(default = "default_roles_header")]
    pub roles_header: String,
}

fn default_true() -> bool {
    true
}
fn default_principal_header() -> String {
    "X-Principal-Id".to_string()
}
fn default_roles_header() -> String {
    "X-Roles".to_string()
}

impl Default for HttpMiddlewareConfig {
    fn default() -> Self {
        Self {
            gate_mutations_only: true,
            excluded_paths: vec!["/health".to_string(), "/ready".to_string()],
            principal_header: default_principal_header(),
            roles_header: default_roles_header(),
        }
    }
}

/// Convert an HTTP request into a Kavach ActionContext.
pub fn to_action_context(
    request: &HttpRequest,
    config: &HttpMiddlewareConfig,
    session: &SessionState,
) -> ActionContext {
    // Extract principal from headers
    let principal_id = request
        .headers
        .get(&config.principal_header)
        .cloned()
        .unwrap_or_else(|| "anonymous".to_string());

    let roles: Vec<String> = request
        .headers
        .get(&config.roles_header)
        .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let principal = Principal {
        id: principal_id,
        kind: PrincipalKind::User, // Default; override via header if needed
        roles,
        credentials_issued_at: session.started_at,
        display_name: None,
    };

    // Build action descriptor
    let mut action = ActionDescriptor::new(request.derive_action_name());
    action.resource = Some(request.path.clone());

    // Include body params for invariant checking
    if let Some(serde_json::Value::Object(body)) = &request.body {
        for (key, value) in body {
            action.params.insert(key.clone(), value.clone());
        }
    }

    let env = EnvContext {
        ip: request.remote_ip,
        device: None,
        geo: None,
        user_agent: request.headers.get("User-Agent").cloned(),
    };

    ActionContext::new(principal, action, session.clone(), env)
        .with_metadata("http_method", serde_json::json!(request.method))
        .with_metadata("http_path", serde_json::json!(request.path))
}

/// Framework-agnostic HTTP gate.
///
/// Wraps a Kavach gate with HTTP-specific configuration and session management.
pub struct HttpGate {
    gate: Arc<Gate>,
    config: HttpMiddlewareConfig,
}

impl HttpGate {
    pub fn new(gate: Arc<Gate>, config: HttpMiddlewareConfig) -> Self {
        Self { gate, config }
    }

    /// Check if a path is excluded from gating.
    pub fn is_excluded(&self, path: &str) -> bool {
        self.config
            .excluded_paths
            .iter()
            .any(|p| path.starts_with(p))
    }

    /// Check if this request should be gated.
    pub fn should_gate(&self, request: &HttpRequest) -> bool {
        if self.is_excluded(&request.path) {
            return false;
        }
        if self.config.gate_mutations_only {
            return request.is_mutating();
        }
        true
    }

    /// Evaluate an HTTP request against the gate.
    ///
    /// Honors [`GateConfig::observe_only`]: when the underlying gate is in
    /// observe-only mode, this dispatches to [`Gate::evaluate_observe_only`]
    /// which logs what *would* have been refused but always returns Permit.
    /// This is the Phase-1-rollout path — log everything, block nothing.
    pub async fn evaluate(&self, request: &HttpRequest, session: &SessionState) -> Verdict {
        let ctx = to_action_context(request, &self.config, session);
        if self.gate.is_observe_only() {
            self.gate.evaluate_observe_only(&ctx).await
        } else {
            self.gate.evaluate(&ctx).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_name_derivation() {
        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/api/v1/refunds".to_string(),
            path_params: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            headers: HashMap::new(),
            remote_ip: None,
        };
        assert_eq!(request.derive_action_name(), "refunds.create");

        let request = HttpRequest {
            method: "DELETE".to_string(),
            path: "/api/v1/users/123".to_string(),
            ..request
        };
        assert_eq!(request.derive_action_name(), "users.delete");
    }

    #[test]
    fn test_excluded_paths() {
        let gate_config = kavach_core::GateConfig::default();
        let gate = Arc::new(Gate::new(vec![], gate_config));
        let http_gate = HttpGate::new(gate, HttpMiddlewareConfig::default());

        assert!(http_gate.is_excluded("/health"));
        assert!(http_gate.is_excluded("/ready"));
        assert!(!http_gate.is_excluded("/api/v1/refunds"));
    }

    fn post_request() -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            path: "/api/v1/refunds".into(),
            path_params: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            headers: HashMap::new(),
            remote_ip: None,
        }
    }

    #[tokio::test]
    async fn enforcing_gate_with_empty_policies_refuses() {
        // An enforcing gate with no policies default-denies.
        let policy_engine = Arc::new(kavach_core::PolicyEngine::new(
            kavach_core::PolicySet::default(),
        ));
        let gate = Arc::new(Gate::new(
            vec![policy_engine as Arc<dyn kavach_core::Evaluator>],
            kavach_core::GateConfig::default(),
        ));
        let http_gate = HttpGate::new(gate, HttpMiddlewareConfig::default());

        let verdict = http_gate
            .evaluate(&post_request(), &SessionState::new())
            .await;
        assert!(
            verdict.is_refuse(),
            "enforcing gate must refuse when no policy permits, got {verdict:?}"
        );
    }

    #[tokio::test]
    async fn observe_only_gate_permits_even_when_underlying_would_refuse() {
        // Same empty policy set, but observe_only=true. Underlying gate would
        // refuse, but HttpGate::evaluate must dispatch to evaluate_observe_only
        // and return Permit instead.
        let policy_engine = Arc::new(kavach_core::PolicyEngine::new(
            kavach_core::PolicySet::default(),
        ));
        let gate_config = kavach_core::GateConfig {
            observe_only: true,
            ..Default::default()
        };
        let gate = Arc::new(Gate::new(
            vec![policy_engine as Arc<dyn kavach_core::Evaluator>],
            gate_config,
        ));
        let http_gate = HttpGate::new(gate, HttpMiddlewareConfig::default());

        let verdict = http_gate
            .evaluate(&post_request(), &SessionState::new())
            .await;
        assert!(
            verdict.is_permit(),
            "observe-only gate must always permit, got {verdict:?}"
        );
    }
}
