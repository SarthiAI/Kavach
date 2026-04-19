use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

/// Complete context for an action being evaluated by the gate.
///
/// This is the "evidence packet" that every evaluator examines.
/// It answers: who is acting, what are they doing, where are they,
/// when did this session start, and what has happened so far.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext {
    /// Unique ID for this evaluation (for audit correlation).
    pub evaluation_id: Uuid,

    /// Who is performing the action.
    pub principal: Principal,

    /// What action is being attempted.
    pub action: ActionDescriptor,

    /// Current session state.
    pub session: SessionState,

    /// Environment context (network, device, geo).
    pub environment: EnvContext,

    /// Timestamp of this evaluation.
    pub evaluated_at: DateTime<Utc>,

    /// Arbitrary metadata attached by the integration layer.
    /// Integration crates (kavach-mcp, kavach-http, etc.) can attach
    /// domain-specific context here without modifying core types.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ActionContext {
    /// Create a new context with the current timestamp and a fresh evaluation ID.
    pub fn new(
        principal: Principal,
        action: ActionDescriptor,
        session: SessionState,
        environment: EnvContext,
    ) -> Self {
        Self {
            evaluation_id: Uuid::new_v4(),
            principal,
            action,
            session,
            environment,
            evaluated_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Attach a metadata key-value pair.
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// The entity performing the action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    /// Unique identifier for this principal.
    pub id: String,

    /// What kind of entity this is.
    pub kind: PrincipalKind,

    /// Roles assigned to this principal.
    pub roles: Vec<String>,

    /// When this principal's credentials were issued.
    pub credentials_issued_at: DateTime<Utc>,

    /// Optional display name.
    pub display_name: Option<String>,
}

/// The type of entity performing an action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A human user.
    User,
    /// An AI agent (LLM, autonomous system).
    Agent,
    /// A backend service or microservice.
    Service,
    /// A scheduled job or cron task.
    Scheduler,
    /// A webhook or external caller.
    External,
}

/// Description of the action being attempted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDescriptor {
    /// The name/type of the action (e.g., "issue_refund", "delete_user", "deploy").
    pub name: String,

    /// The resource being acted upon (e.g., "orders/12345", "users/abc").
    pub resource: Option<String>,

    /// Parameters of the action (for invariant checking).
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
}

impl ActionDescriptor {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            resource: None,
            params: HashMap::new(),
        }
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.params.insert(key.into(), value);
        self
    }

    /// Get a parameter value as f64 (for numeric invariant checks).
    pub fn param_as_f64(&self, key: &str) -> Option<f64> {
        self.params.get(key).and_then(|v| v.as_f64())
    }

    /// Get a parameter value as string.
    pub fn param_as_str(&self, key: &str) -> Option<&str> {
        self.params.get(key).and_then(|v| v.as_str())
    }
}

/// Current state of the session in which the action occurs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Unique session identifier.
    pub session_id: Uuid,

    /// When this session was established.
    pub started_at: DateTime<Utc>,

    /// How many actions have been performed in this session.
    pub action_count: u64,

    /// History of action names taken in this session (most recent last).
    /// Kept bounded, integration layer decides the window size.
    #[serde(default)]
    pub action_history: Vec<String>,

    /// Whether the session has been explicitly invalidated.
    #[serde(default)]
    pub invalidated: bool,

    /// The IP address at session start (for drift comparison).
    pub origin_ip: Option<IpAddr>,

    /// Device fingerprint at session start (for drift comparison).
    pub origin_device: Option<DeviceFingerprint>,

    /// Geographic location at session start (for distance-based drift comparison).
    #[serde(default)]
    pub origin_geo: Option<GeoLocation>,
}

impl SessionState {
    /// Create a new session starting now.
    pub fn new() -> Self {
        Self {
            session_id: Uuid::new_v4(),
            started_at: Utc::now(),
            action_count: 0,
            action_history: Vec::new(),
            invalidated: false,
            origin_ip: None,
            origin_device: None,
            origin_geo: None,
        }
    }

    /// Duration since session start.
    pub fn age(&self) -> chrono::Duration {
        Utc::now() - self.started_at
    }

    /// Record an action in the session history.
    pub fn record_action(&mut self, action_name: &str) {
        self.action_count += 1;
        self.action_history.push(action_name.to_string());
        // Keep bounded at 1000 entries
        if self.action_history.len() > 1000 {
            self.action_history.drain(..500);
        }
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Environment context, where and how the action is happening.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvContext {
    /// Current IP address of the caller.
    pub ip: Option<IpAddr>,

    /// Current device fingerprint.
    pub device: Option<DeviceFingerprint>,

    /// Geographic location (if available).
    pub geo: Option<GeoLocation>,

    /// User agent or client identifier.
    pub user_agent: Option<String>,
}

/// Device fingerprint for identity anchoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DeviceFingerprint {
    /// Opaque fingerprint hash.
    pub hash: String,

    /// Optional device description.
    pub description: Option<String>,
}

/// Geographic location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country_code: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

impl GeoLocation {
    /// Simple distance check (Haversine approximation in km).
    pub fn distance_km(&self, other: &GeoLocation) -> Option<f64> {
        let (lat1, lon1) = (self.latitude?, self.longitude?);
        let (lat2, lon2) = (other.latitude?, other.longitude?);

        let r = 6371.0; // Earth radius in km
        let dlat = (lat2 - lat1).to_radians();
        let dlon = (lon2 - lon1).to_radians();
        let a = (dlat / 2.0).sin().powi(2)
            + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();

        Some(r * c)
    }
}
