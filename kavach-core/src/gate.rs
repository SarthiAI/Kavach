use crate::action::Action;
use crate::audit::{AuditEntry, AuditSink};
use crate::context::ActionContext;
use crate::error::KavachError;
use crate::evaluator::Evaluator;
use crate::invalidation::{InvalidationBroadcaster, NoopInvalidationBroadcaster};
use crate::verdict::{PermitToken, RefuseCode, RefuseReason, TokenSigner, Verdict};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// The execution gate.
///
/// Every action passes through this gate before it can execute.
/// The gate runs a chain of [`Evaluator`]s in priority order.
/// If **all** evaluators return Permit, the gate wraps the action
/// in a [`Guarded`] that allows execution. If **any** evaluator
/// returns Refuse or Invalidate, the action is blocked.
///
/// This is a **default-deny** system. An action with no matching
/// policy is refused, not permitted.
pub struct Gate {
    evaluators: Vec<Arc<dyn Evaluator>>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    token_signer: Option<Arc<dyn TokenSigner>>,
    broadcaster: Arc<dyn InvalidationBroadcaster>,
    config: GateConfig,
}

impl Gate {
    /// Create a gate with the given evaluators.
    ///
    /// The gate starts with a no-op invalidation broadcaster — suitable for
    /// single-node deployments where invalidations only need to be honored
    /// locally. Use [`Gate::with_broadcaster`] to plug in a distributed
    /// broadcaster so peers also see the invalidation.
    pub fn new(mut evaluators: Vec<Arc<dyn Evaluator>>, config: GateConfig) -> Self {
        // Sort by priority — lowest number runs first
        evaluators.sort_by_key(|e| e.priority());
        Self {
            evaluators,
            audit_sink: None,
            token_signer: None,
            broadcaster: Arc::new(NoopInvalidationBroadcaster::new()),
            config,
        }
    }

    /// Attach an audit sink for logging all verdicts.
    pub fn with_audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Attach an [`InvalidationBroadcaster`].
    ///
    /// When `Gate::evaluate` produces an `Invalidate` verdict, the scope is
    /// published to every subscriber via this broadcaster. Broadcast
    /// failures are logged but never downgrade the local verdict — the
    /// local node still treats the session as invalidated.
    pub fn with_broadcaster(mut self, broadcaster: Arc<dyn InvalidationBroadcaster>) -> Self {
        self.broadcaster = broadcaster;
        self
    }

    /// Attach a [`TokenSigner`] so issued permits carry a cryptographic signature.
    ///
    /// Without a signer, `PermitToken::signature` remains `None`. With one,
    /// every `Permit` verdict returned by [`Gate::evaluate`] has its
    /// `signature` field populated before the verdict leaves the gate.
    ///
    /// If the signer fails (e.g., key unavailable, crypto error), the gate
    /// converts the `Permit` into a `Refuse` — failing closed. A gate that
    /// was configured for signed permits must not silently downgrade to
    /// unsigned permits.
    pub fn with_token_signer(mut self, signer: Arc<dyn TokenSigner>) -> Self {
        self.token_signer = Some(signer);
        self
    }

    /// Evaluate an action context against all evaluators.
    ///
    /// Returns the verdict. On Permit, the verdict contains a
    /// [`PermitToken`] that can be used to construct a [`Guarded`] action.
    pub async fn evaluate(&self, ctx: &ActionContext) -> Verdict {
        info!(
            evaluation_id = %ctx.evaluation_id,
            principal = %ctx.principal.id,
            action = %ctx.action.name,
            "gate evaluation started"
        );

        // Check if session is already invalidated
        if ctx.session.invalidated {
            let verdict = Verdict::Refuse(RefuseReason {
                evaluator: "gate".to_string(),
                reason: "session has been invalidated".to_string(),
                code: RefuseCode::SessionInvalid,
                evaluation_id: ctx.evaluation_id,
            });
            self.record_verdict(ctx, &verdict).await;
            return verdict;
        }

        // Run evaluators in priority order
        for evaluator in &self.evaluators {
            debug!(
                evaluator = evaluator.name(),
                priority = evaluator.priority(),
                "running evaluator"
            );

            let verdict = evaluator.evaluate(ctx).await;

            match &verdict {
                Verdict::Permit(_) => {
                    debug!(evaluator = evaluator.name(), "evaluator permits");
                    continue; // Next evaluator
                }
                Verdict::Refuse(reason) => {
                    warn!(
                        evaluator = evaluator.name(),
                        reason = %reason,
                        "action refused"
                    );
                    self.record_verdict(ctx, &verdict).await;
                    return verdict;
                }
                Verdict::Invalidate(scope) => {
                    error!(
                        evaluator = evaluator.name(),
                        scope = %scope,
                        "authority invalidated"
                    );
                    // Fan out to peer nodes. Failures are logged but do not
                    // downgrade the local verdict — local invalidation stands
                    // regardless of whether peers were notified.
                    if let Err(err) = self.broadcaster.publish(scope.clone()).await {
                        warn!(
                            error = %err,
                            scope = %scope,
                            "invalidation broadcast failed — local verdict unaffected"
                        );
                    }
                    self.record_verdict(ctx, &verdict).await;
                    return verdict;
                }
            }
        }

        // All evaluators passed — issue permit
        let mut token = PermitToken::new(ctx.evaluation_id, ctx.action.name.clone());

        // If a token signer is configured, sign the permit before it leaves
        // the gate. On signing failure, fail closed: convert to Refuse.
        if let Some(signer) = &self.token_signer {
            match signer.sign(&token) {
                Ok(sig) => token.signature = Some(sig),
                Err(e) => {
                    error!(error = %e, "token signing failed — refusing action (fail-closed)");
                    let verdict = Verdict::Refuse(RefuseReason {
                        evaluator: "gate".to_string(),
                        reason: format!("token signing failed: {e}"),
                        code: RefuseCode::IdentityFailed,
                        evaluation_id: ctx.evaluation_id,
                    });
                    self.record_verdict(ctx, &verdict).await;
                    return verdict;
                }
            }
        }

        let verdict = Verdict::Permit(token);

        info!(
            evaluation_id = %ctx.evaluation_id,
            "all evaluators passed — action permitted"
        );

        self.record_verdict(ctx, &verdict).await;
        verdict
    }

    /// Evaluate and wrap an action in a Guarded container.
    ///
    /// This is the primary API. If the verdict is Permit, the action
    /// is wrapped in a Guarded that allows execution. Otherwise,
    /// the verdict is returned as an error.
    pub async fn guard<A: Action>(
        &self,
        ctx: &ActionContext,
        action: A,
    ) -> Result<Guarded<A>, Verdict> {
        let verdict = self.evaluate(ctx).await;
        match verdict {
            Verdict::Permit(token) => Ok(Guarded {
                action,
                token,
                _private: (),
            }),
            other => Err(other),
        }
    }

    /// Record a verdict to the audit sink.
    async fn record_verdict(&self, ctx: &ActionContext, verdict: &Verdict) {
        if let Some(sink) = &self.audit_sink {
            let entry = AuditEntry::from_verdict(ctx, verdict);
            if let Err(e) = sink.record(entry).await {
                error!(error = %e, "failed to record audit entry");
            }
        }
    }

    /// Returns the number of evaluators in the chain.
    pub fn evaluator_count(&self) -> usize {
        self.evaluators.len()
    }

    /// Check if the gate is in observe-only mode (audit without enforcement).
    pub fn is_observe_only(&self) -> bool {
        self.config.observe_only
    }

    /// Evaluate but never block — useful for Phase 1 rollout.
    ///
    /// Runs all evaluators and logs the verdict, but always returns Permit.
    /// Use this to see what *would* be blocked before turning enforcement on.
    pub async fn evaluate_observe_only(&self, ctx: &ActionContext) -> Verdict {
        let actual_verdict = self.evaluate(ctx).await;

        if !actual_verdict.is_permit() {
            info!(
                evaluation_id = %ctx.evaluation_id,
                action = %ctx.action.name,
                "observe-only: would have blocked this action"
            );
        }

        // Always permit in observe-only mode
        let token = PermitToken::new(ctx.evaluation_id, ctx.action.name.clone());
        Verdict::Permit(token)
    }
}

/// A guarded action that has been approved by the gate.
///
/// This type has **no public constructor**. The only way to obtain one
/// is through [`Gate::guard`], which requires all evaluators to Permit.
///
/// Rust's type system enforces this: if your code compiles, the gate
/// was consulted. There is no way to skip it.
pub struct Guarded<A: Action> {
    action: A,
    token: PermitToken,
    /// Private field prevents external construction.
    _private: (),
}

impl<A: Action> Guarded<A> {
    /// Execute the guarded action, consuming the permit.
    ///
    /// This checks that the permit hasn't expired (permits are short-lived,
    /// typically 30 seconds) and that the action name matches.
    ///
    /// The Guarded wrapper is consumed — a permit cannot be reused.
    pub async fn execute(self) -> Result<A::Output, KavachError> {
        // Verify the permit is still valid
        if self.token.is_expired() {
            return Err(KavachError::Execution(format!(
                "permit {} expired at {}",
                self.token.token_id, self.token.expires_at
            )));
        }

        let action_name = self.action.descriptor().name;
        if !self.token.matches_action(&action_name) {
            return Err(KavachError::Execution(format!(
                "permit is for '{}', not '{}'",
                self.token.action_name, action_name
            )));
        }

        debug!(
            token_id = %self.token.token_id,
            action = %action_name,
            "executing guarded action"
        );

        self.action.execute().await
    }

    /// Access the permit token (for downstream verification).
    pub fn token(&self) -> &PermitToken {
        &self.token
    }
}

/// Configuration for the gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateConfig {
    /// If true, the gate logs verdicts but never blocks (Phase 1 rollout).
    #[serde(default)]
    pub observe_only: bool,

    /// Maximum time a permit token is valid (in seconds). Default: 30.
    #[serde(default = "default_permit_ttl")]
    pub permit_ttl_seconds: u64,

    /// Whether to fail open (permit on evaluator error) or fail closed (refuse).
    /// Default: false (fail closed — refuse on error).
    #[serde(default)]
    pub fail_open: bool,
}

fn default_permit_ttl() -> u64 {
    30
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            observe_only: false,
            permit_ttl_seconds: 30,
            fail_open: false,
        }
    }
}
