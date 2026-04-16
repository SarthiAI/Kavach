use crate::error::KavachError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The gate's decision about an action.
///
/// There are exactly three possible outcomes — no ambiguity, no "maybe":
///
/// - **Permit** — the action may proceed. Comes with a token that proves
///   the gate was consulted (for audit and downstream verification).
/// - **Refuse** — the action is blocked. Includes the reason and which
///   evaluator refused it.
/// - **Invalidate** — not only is this action blocked, but prior authority
///   is revoked. The session or identity is no longer trusted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Verdict {
    /// Action is allowed to proceed.
    Permit(PermitToken),

    /// Action is blocked.
    Refuse(RefuseReason),

    /// Action is blocked AND prior authority is revoked.
    Invalidate(InvalidationScope),
}

impl Verdict {
    pub fn is_permit(&self) -> bool {
        matches!(self, Verdict::Permit(_))
    }

    pub fn is_refuse(&self) -> bool {
        matches!(self, Verdict::Refuse(_))
    }

    pub fn is_invalidate(&self) -> bool {
        matches!(self, Verdict::Invalidate(_))
    }
}

/// Proof that the gate was consulted and issued a Permit.
///
/// This token is consumed when the action executes — it cannot be reused.
/// In PQ-enabled configurations, this token is cryptographically signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermitToken {
    /// Unique token ID.
    pub token_id: Uuid,

    /// Which evaluation produced this permit.
    pub evaluation_id: Uuid,

    /// When the permit was issued.
    pub issued_at: DateTime<Utc>,

    /// When the permit expires (short-lived by design).
    pub expires_at: DateTime<Utc>,

    /// The action name this permit is for (cannot be reused for a different action).
    pub action_name: String,

    /// Optional PQ signature over this token (populated by kavach-pq).
    pub signature: Option<Vec<u8>>,
}

impl PermitToken {
    /// Create a new permit token with a default 30-second expiry.
    pub fn new(evaluation_id: Uuid, action_name: String) -> Self {
        let now = Utc::now();
        Self {
            token_id: Uuid::new_v4(),
            evaluation_id,
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(30),
            action_name,
            signature: None,
        }
    }

    /// Check if the permit has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if this permit matches the given action.
    pub fn matches_action(&self, action_name: &str) -> bool {
        self.action_name == action_name
    }

    /// Canonical byte representation of the token's signable fields.
    ///
    /// Layout: `token_id (16B) || evaluation_id (16B) || issued_ts_le (8B) || expires_ts_le (8B) || action_name_utf8`.
    ///
    /// The `signature` field is explicitly **excluded** — signing produces
    /// bytes that the verifier can reconstruct without knowing the signature.
    /// Any future fields added to `PermitToken` must be included here in
    /// a backwards-compatible way (e.g., length-prefixed) to preserve
    /// signature validity.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + 16 + 8 + 8 + self.action_name.len());
        buf.extend_from_slice(self.token_id.as_bytes());
        buf.extend_from_slice(self.evaluation_id.as_bytes());
        buf.extend_from_slice(&self.issued_at.timestamp().to_le_bytes());
        buf.extend_from_slice(&self.expires_at.timestamp().to_le_bytes());
        buf.extend_from_slice(self.action_name.as_bytes());
        buf
    }
}

/// Signs and verifies [`PermitToken`]s so that a downstream service can confirm
/// a token really came from the gate and wasn't forged in transit.
///
/// kavach-core defines the trait; the concrete post-quantum implementation
/// lives in `kavach-pq` (`PqTokenSigner`). This keeps the core crate
/// crypto-agnostic — a consumer that doesn't need PQ signatures never
/// depends on kavach-pq or pulls its heavy crypto dependencies.
///
/// Signing is over [`PermitToken::canonical_bytes`], which deliberately
/// excludes the `signature` field itself.
pub trait TokenSigner: Send + Sync {
    /// Sign the token and return the opaque signature bytes that the gate
    /// will place in `PermitToken::signature`. The exact encoding is
    /// implementation-defined (e.g., JSON-encoded envelope with key_id +
    /// algorithm + ML-DSA signature + optional Ed25519 signature).
    fn sign(&self, token: &PermitToken) -> Result<Vec<u8>, KavachError>;

    /// Verify a previously-signed token. Returns `Ok(())` on valid signature,
    /// `Err(_)` on any tampering, wrong key, or malformed encoding.
    fn verify(&self, token: &PermitToken, signature: &[u8]) -> Result<(), KavachError>;
}

/// Reason an action was refused.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefuseReason {
    /// Which evaluator refused the action.
    pub evaluator: String,

    /// Human-readable explanation.
    pub reason: String,

    /// Machine-readable refusal code.
    pub code: RefuseCode,

    /// The evaluation that produced this refusal.
    pub evaluation_id: Uuid,
}

impl std::fmt::Display for RefuseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.code, self.evaluator, self.reason)
    }
}

/// Machine-readable codes for refusal reasons.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefuseCode {
    /// Identity could not be resolved or verified.
    IdentityFailed,
    /// Policy explicitly denies this action.
    PolicyDenied,
    /// No policy permits this action (default-deny).
    NoPolicyMatch,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Session has expired or been invalidated.
    SessionInvalid,
    /// Action parameters violate an invariant.
    InvariantViolation,
    /// Drift detected — context has shifted.
    DriftDetected,
    /// Permit token expired before execution.
    PermitExpired,
}

impl std::fmt::Display for RefuseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::IdentityFailed => "IDENTITY_FAILED",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::NoPolicyMatch => "NO_POLICY_MATCH",
            Self::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            Self::SessionInvalid => "SESSION_INVALID",
            Self::InvariantViolation => "INVARIANT_VIOLATION",
            Self::DriftDetected => "DRIFT_DETECTED",
            Self::PermitExpired => "PERMIT_EXPIRED",
        };
        write!(f, "{s}")
    }
}

/// Scope of authority being revoked when a verdict is Invalidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationScope {
    /// What is being invalidated.
    pub target: InvalidationTarget,

    /// Why it's being invalidated.
    pub reason: String,

    /// Which evaluator triggered the invalidation.
    pub evaluator: String,
}

impl std::fmt::Display for InvalidationScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalidate {:?} by {}: {}",
            self.target, self.evaluator, self.reason
        )
    }
}

/// What authority is being revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationTarget {
    /// Just this session.
    Session(Uuid),
    /// All sessions for this principal.
    Principal(String),
    /// All sessions matching a role.
    Role(String),
}
