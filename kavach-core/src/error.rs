use thiserror::Error;

/// Top-level error type for Kavach operations.
#[derive(Debug, Error)]
pub enum KavachError {
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("config error: {0}")]
    Config(String),

    #[error("execution error: {0}")]
    Execution(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("invariant violation: {name}, {reason}")]
    InvariantViolation { name: String, reason: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Errors during policy evaluation or loading.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    Parse(String),

    #[error("unknown condition type: {0}")]
    UnknownCondition(String),

    #[error("conflicting policies: {0} and {1}")]
    Conflict(String, String),
}

/// Errors during identity resolution.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("credentials missing")]
    Missing,

    #[error("credentials expired at {0}")]
    Expired(String),

    #[error("principal not recognized: {0}")]
    UnknownPrincipal(String),

    #[error("context mismatch: expected {expected}, got {actual}")]
    ContextMismatch { expected: String, actual: String },

    #[error("device fingerprint mismatch")]
    DeviceMismatch,
}

pub type Result<T> = std::result::Result<T, KavachError>;
