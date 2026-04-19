//! # Kavach MCP
//!
//! Middleware for MCP (Model Context Protocol) servers that gates every
//! tool call through Kavach's execution boundary.
//!
//! Wrap your MCP tool handlers with [`GuardedToolHandler`] and every
//! invocation from an AI agent will pass through identity, policy, drift,
//! and invariant checks before executing.
//!
//! # Example
//!
//! ```ignore
//! use kavach_mcp::{GuardedToolHandler, McpKavachLayer};
//! use kavach_core::{Gate, GateConfig, PolicySet, PolicyEngine, InvariantSet, Invariant};
//!
//! // Your existing MCP tool handler
//! async fn handle_refund(params: serde_json::Value) -> Result<serde_json::Value, McpError> {
//!     // ... process refund
//! }
//!
//! // Wrap it with Kavach
//! let gate = build_gate();
//! let guarded = GuardedToolHandler::new("issue_refund", handle_refund, gate);
//! ```

use kavach_core::{
    ActionContext, ActionDescriptor, EnvContext, Gate, InMemorySessionStore, Principal,
    PrincipalKind, SessionState, SessionStore, SessionStoreError, Verdict,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

/// Represents an incoming MCP tool call request.
///
/// Integration crates for specific MCP SDKs should convert their
/// native request types into this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolRequest {
    /// The tool being called.
    pub tool_name: String,

    /// Parameters passed to the tool.
    pub params: serde_json::Value,

    /// Identity of the caller (agent, user, service).
    pub caller: McpCaller,

    /// Session information.
    pub session_id: Option<String>,

    /// Request metadata (headers, transport info).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Identity of the MCP caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCaller {
    /// Caller identifier.
    pub id: String,

    /// What kind of caller.
    pub kind: McpCallerKind,

    /// Roles (if known).
    #[serde(default)]
    pub roles: Vec<String>,

    /// IP address (if available from transport).
    pub ip: Option<IpAddr>,

    /// Client name / user agent.
    pub client_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpCallerKind {
    Agent,
    User,
    Service,
}

impl From<McpCallerKind> for PrincipalKind {
    fn from(kind: McpCallerKind) -> Self {
        match kind {
            McpCallerKind::Agent => PrincipalKind::Agent,
            McpCallerKind::User => PrincipalKind::User,
            McpCallerKind::Service => PrincipalKind::Service,
        }
    }
}

/// Result of a guarded tool call.
#[derive(Debug, Serialize, Deserialize)]
pub enum GuardedResult {
    /// Tool executed successfully.
    Success(serde_json::Value),

    /// Tool call was refused by the gate.
    Refused {
        code: String,
        reason: String,
        evaluator: String,
    },

    /// Session was invalidated, caller must re-authenticate.
    Invalidated { reason: String },

    /// Tool execution failed (gate permitted, but tool errored).
    Error(String),
}

/// Converts an MCP tool request into a Kavach ActionContext.
///
/// This is the thin translation layer, it maps MCP-specific concepts
/// to Kavach's domain-agnostic context.
pub fn to_action_context(request: &McpToolRequest, session_state: &SessionState) -> ActionContext {
    // Build principal from caller info
    let principal = Principal {
        id: request.caller.id.clone(),
        kind: request.caller.kind.clone().into(),
        roles: request.caller.roles.clone(),
        credentials_issued_at: session_state.started_at,
        display_name: request.caller.client_name.clone(),
    };

    // Build action descriptor from tool name + params
    let mut action = ActionDescriptor::new(&request.tool_name);

    // Extract params into the action descriptor for policy/invariant checks
    if let serde_json::Value::Object(map) = &request.params {
        for (key, value) in map {
            action.params.insert(key.clone(), value.clone());
        }
    }

    // Build environment context
    let env = EnvContext {
        ip: request.caller.ip,
        device: None,
        geo: None,
        user_agent: request.caller.client_name.clone(),
    };

    ActionContext::new(principal, action, session_state.clone(), env)
        .with_metadata("mcp_tool", serde_json::json!(request.tool_name))
}

/// Evaluate an MCP tool request against the Kavach gate.
///
/// This is the primary integration point. Call this before executing
/// any MCP tool handler.
///
/// ```ignore
/// let result = kavach_mcp::evaluate_tool_call(&gate, &request, &session).await;
/// match result {
///     GuardedResult::Success(_) => unreachable!(), // evaluate doesn't execute
///     GuardedResult::Refused { reason, .. } => return error_response(reason),
///     GuardedResult::Invalidated { reason } => return invalidate_session(reason),
///     GuardedResult::Error(e) => return error_response(e),
/// }
/// // If we reach here, the gate permitted, now execute the tool
/// ```
pub async fn evaluate_tool_call(
    gate: &Gate,
    request: &McpToolRequest,
    session: &SessionState,
) -> Verdict {
    let ctx = to_action_context(request, session);
    gate.evaluate(&ctx).await
}

/// Session manager for MCP connections.
///
/// Delegates storage to an injectable [`SessionStore`] so the same manager
/// works with the default in-memory store (single-node) or a shared store
/// (Redis, etc., for multi-node deployments). All methods are async because
/// a non-trivial [`SessionStore`] may perform network I/O.
pub struct McpSessionManager {
    store: Arc<dyn SessionStore>,
}

impl McpSessionManager {
    /// Build a manager backed by the in-memory session store. Suitable for
    /// single-node use and tests; sessions are lost on process restart.
    pub fn new() -> Self {
        Self::with_store(Arc::new(InMemorySessionStore::new()))
    }

    /// Build a manager with a user-supplied [`SessionStore`]. Use this to
    /// plug in a distributed backend so invalidation on one node is visible
    /// to all others.
    pub fn with_store(store: Arc<dyn SessionStore>) -> Self {
        Self { store }
    }

    /// Get or create a session for the given session ID.
    ///
    /// Returns `Err` only when the underlying store fails. A missing session
    /// triggers creation, not an error.
    pub async fn get_or_create(
        &self,
        session_id: &str,
        caller: &McpCaller,
    ) -> Result<SessionState, SessionStoreError> {
        if let Some(session) = self.store.get(session_id).await? {
            return Ok(session);
        }

        let mut session = SessionState::new();
        session.origin_ip = caller.ip;
        self.store.put(session_id, session.clone()).await?;
        Ok(session)
    }

    /// Record a completed action in the session. No-op if the session is
    /// not found (it may have been invalidated & cleaned up).
    pub async fn record_action(
        &self,
        session_id: &str,
        action_name: &str,
    ) -> Result<(), SessionStoreError> {
        let Some(mut session) = self.store.get(session_id).await? else {
            return Ok(());
        };
        session.record_action(action_name);
        self.store.put(session_id, session).await
    }

    /// Invalidate a session. No-op if the session is not found.
    pub async fn invalidate(&self, session_id: &str) -> Result<(), SessionStoreError> {
        let Some(mut session) = self.store.get(session_id).await? else {
            return Ok(());
        };
        session.invalidated = true;
        self.store.put(session_id, session).await?;
        tracing::warn!(session_id = session_id, "MCP session invalidated");
        Ok(())
    }

    /// Clean up sessions older than `max_age_seconds`. Returns how many
    /// were removed.
    pub async fn cleanup(&self, max_age_seconds: i64) -> Result<u64, SessionStoreError> {
        self.store.cleanup(max_age_seconds).await
    }
}

impl Default for McpSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete MCP middleware that ties gate + sessions together.
///
/// This is the high-level API for protecting an entire MCP server.
///
/// ```ignore
/// let middleware = McpKavachLayer::new(gate);
///
/// // For each incoming tool call:
/// let verdict = middleware.check(&request).await;
/// match verdict {
///     Verdict::Permit(_) => {
///         let result = execute_tool(&request).await;
///         middleware.record_success(&request);
///         result
///     }
///     Verdict::Refuse(reason) => error_response(reason),
///     Verdict::Invalidate(scope) => {
///         middleware.handle_invalidation(&request, &scope);
///         error_response("session revoked")
///     }
/// }
/// ```
pub struct McpKavachLayer {
    gate: Arc<Gate>,
    sessions: McpSessionManager,
}

impl McpKavachLayer {
    pub fn new(gate: Arc<Gate>) -> Self {
        Self {
            gate,
            sessions: McpSessionManager::new(),
        }
    }

    /// Build a layer with a user-supplied [`McpSessionManager`] (useful when
    /// plugging in a distributed [`SessionStore`]).
    pub fn with_sessions(gate: Arc<Gate>, sessions: McpSessionManager) -> Self {
        Self { gate, sessions }
    }

    /// Check a tool call against the gate.
    ///
    /// Fails closed: if the session store is unavailable, the call is
    /// refused rather than permitted without a session record.
    pub async fn check(&self, request: &McpToolRequest) -> Verdict {
        let session_id = request
            .session_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        match self
            .sessions
            .get_or_create(&session_id, &request.caller)
            .await
        {
            Ok(session) => evaluate_tool_call(&self.gate, request, &session).await,
            Err(err) => {
                tracing::warn!(
                    session_id = %session_id,
                    error = %err,
                    "session store unavailable, refusing tool call"
                );
                Verdict::Refuse(kavach_core::RefuseReason {
                    evaluator: "mcp_session".to_string(),
                    reason: "session store unavailable".to_string(),
                    code: kavach_core::RefuseCode::IdentityFailed,
                    evaluation_id: Uuid::new_v4(),
                })
            }
        }
    }

    /// Record a successful tool execution in the session. Errors from the
    /// session store are logged and swallowed, recording is best-effort
    /// and must not propagate to application code.
    pub async fn record_success(&self, request: &McpToolRequest) {
        if let Some(session_id) = &request.session_id {
            if let Err(err) = self
                .sessions
                .record_action(session_id, &request.tool_name)
                .await
            {
                tracing::warn!(
                    session_id = %session_id,
                    error = %err,
                    "failed to record successful action"
                );
            }
        }
    }

    /// Handle session invalidation. Best-effort: errors are logged, not
    /// returned, the gate has already made its decision by the time this
    /// is called.
    pub async fn handle_invalidation(
        &self,
        request: &McpToolRequest,
        _scope: &kavach_core::verdict::InvalidationScope,
    ) {
        if let Some(session_id) = &request.session_id {
            if let Err(err) = self.sessions.invalidate(session_id).await {
                tracing::warn!(
                    session_id = %session_id,
                    error = %err,
                    "failed to invalidate session"
                );
            }
        }
    }
}
