//! # Kavach Core
//!
//! Post-quantum execution boundary enforcement.
//!
//! Kavach separates **possession of credentials** from **permission to act**.
//! Every action passes through a [`Gate`] that evaluates identity, policy,
//! drift, and invariants before producing a [`Verdict`].
//!
//! The key type is [`Guarded<A>`] — a wrapper around an action that can only
//! be constructed by the gate, and can only be executed by consuming the wrapper.
//! Rust's type system makes it a **compile error** to skip the gate.
//!
//! # Quick start
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use kavach_core::{Gate, GateConfig, PolicyEngine, PolicySet, Evaluator};
//! # async fn demo() {
//! let policy_set = PolicySet::from_file("kavach.toml").unwrap();
//! let policy_engine = Arc::new(PolicyEngine::new(policy_set));
//! let evaluators: Vec<Arc<dyn Evaluator>> = vec![policy_engine];
//! let gate = Gate::new(evaluators, GateConfig::default());
//! # let _ = gate;
//! # }
//! ```

pub mod action;
pub mod audit;
pub mod context;
pub mod drift;
pub mod error;
pub mod evaluator;
pub mod gate;
pub mod invalidation;
pub mod invariant;
pub mod policy;
pub mod rate_limit;
pub mod session_store;
pub mod verdict;

#[cfg(feature = "watcher")]
pub mod watcher;

#[cfg(feature = "watcher")]
pub use watcher::{spawn_policy_watcher, WatcherError};

// Public API re-exports
pub use action::Action;
pub use audit::{AuditEntry, AuditLog, AuditSink};
pub use context::{
    ActionContext, ActionDescriptor, DeviceFingerprint, EnvContext, GeoLocation, Principal,
    PrincipalKind, SessionState,
};
pub use drift::{
    BehaviorDrift, DeviceDrift, DriftDetector, DriftEvaluator, DriftSignal, DriftViolation,
    DriftWarning, GeoLocationDrift, SessionAgeDrift,
};
pub use error::KavachError;
pub use evaluator::Evaluator;
pub use gate::{Gate, GateConfig, Guarded};
pub use invalidation::{
    spawn_invalidation_listener, spawn_session_store_listener, BroadcastError,
    InMemoryInvalidationBroadcaster, InvalidationBroadcaster, NoopInvalidationBroadcaster,
};
pub use invariant::{Invariant, InvariantSet};
pub use policy::{Condition, Effect, Policy, PolicyEngine, PolicySet};
pub use rate_limit::{InMemoryRateLimitStore, RateLimitStore, RateLimitStoreError};
pub use session_store::{InMemorySessionStore, SessionStore, SessionStoreError};
pub use verdict::{
    InvalidationScope, InvalidationTarget, PermitToken, RefuseCode, RefuseReason, TokenSigner,
    Verdict,
};
