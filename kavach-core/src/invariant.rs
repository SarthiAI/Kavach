use crate::context::ActionContext;
use crate::evaluator::Evaluator;
use crate::verdict::{PermitToken, RefuseCode, RefuseReason, Verdict};
use async_trait::async_trait;

/// A structural invariant, a hard limit that cannot be overridden by policy.
///
/// Invariants are the last line of defense. Even if identity checks pass,
/// policy permits, and no drift is detected, an invariant violation still
/// blocks the action. They represent absolute architectural constraints:
///
/// - "No single refund can exceed ₹50,000"
/// - "No agent can make more than 100 tool calls per session"  
/// - "No deployment can happen between 22:00 and 06:00"
///
/// Unlike policies, invariants cannot be overridden, waived, or bypassed.
/// They are structural properties of the system.
#[derive(Clone)]
pub struct Invariant {
    /// Name of this invariant.
    pub name: String,

    /// Human-readable description.
    pub description: String,

    /// The check function. Returns true if the invariant holds (action is OK).
    /// Returns false if violated (action must be blocked).
    check: InvariantCheck,
}

/// The actual check, either a built-in kind or a custom function.
#[derive(Clone)]
enum InvariantCheck {
    /// Maximum value for a numeric parameter.
    ParamMax { field: String, max: f64 },

    /// Minimum value for a numeric parameter.
    ParamMin { field: String, min: f64 },

    /// Maximum actions per session.
    MaxActionsPerSession(u64),

    /// Maximum session age in seconds.
    MaxSessionAge(i64),

    /// Action must match one of these names.
    AllowedActions(Vec<String>),

    /// Action must NOT match any of these names.
    BlockedActions(Vec<String>),

    /// Custom function (boxed for Clone via Arc).
    Custom(std::sync::Arc<dyn Fn(&ActionContext) -> bool + Send + Sync>),
}

impl Invariant {
    /// Create an invariant that limits a numeric parameter.
    ///
    /// Example: No refund over ₹50,000
    /// ```
    /// use kavach_core::Invariant;
    /// let _ = Invariant::param_max("max_refund", "amount", 50_000.0);
    /// ```
    pub fn param_max(name: impl Into<String>, field: impl Into<String>, max: f64) -> Self {
        let name = name.into();
        let field = field.into();
        Self {
            description: format!("parameter '{}' must be at most {}", field, max),
            name,
            check: InvariantCheck::ParamMax { field, max },
        }
    }

    /// Create an invariant that requires a minimum parameter value.
    pub fn param_min(name: impl Into<String>, field: impl Into<String>, min: f64) -> Self {
        let name = name.into();
        let field = field.into();
        Self {
            description: format!("parameter '{}' must be at least {}", field, min),
            name,
            check: InvariantCheck::ParamMin { field, min },
        }
    }

    /// Create an invariant limiting actions per session.
    pub fn max_actions_per_session(name: impl Into<String>, max: u64) -> Self {
        Self {
            name: name.into(),
            description: format!("maximum {} actions per session", max),
            check: InvariantCheck::MaxActionsPerSession(max),
        }
    }

    /// Create an invariant limiting session age.
    pub fn max_session_age(name: impl Into<String>, max_seconds: i64) -> Self {
        Self {
            name: name.into(),
            description: format!("maximum session age: {}s", max_seconds),
            check: InvariantCheck::MaxSessionAge(max_seconds),
        }
    }

    /// Create an invariant with only specific actions allowed.
    pub fn allowed_actions(name: impl Into<String>, actions: Vec<String>) -> Self {
        Self {
            name: name.into(),
            description: format!("only these actions are allowed: {:?}", actions),
            check: InvariantCheck::AllowedActions(actions),
        }
    }

    /// Create an invariant blocking specific actions.
    pub fn blocked_actions(name: impl Into<String>, actions: Vec<String>) -> Self {
        Self {
            name: name.into(),
            description: format!("these actions are blocked: {:?}", actions),
            check: InvariantCheck::BlockedActions(actions),
        }
    }

    /// Create a custom invariant with an arbitrary check function.
    pub fn custom(
        name: impl Into<String>,
        description: impl Into<String>,
        check: impl Fn(&ActionContext) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            check: InvariantCheck::Custom(std::sync::Arc::new(check)),
        }
    }

    /// Check if the invariant holds for the given context.
    pub fn holds(&self, ctx: &ActionContext) -> bool {
        match &self.check {
            InvariantCheck::ParamMax { field, max } => ctx
                .action
                .param_as_f64(field)
                .map(|v| v <= *max)
                .unwrap_or(true),
            InvariantCheck::ParamMin { field, min } => ctx
                .action
                .param_as_f64(field)
                .map(|v| v >= *min)
                .unwrap_or(true),
            InvariantCheck::MaxActionsPerSession(max) => ctx.session.action_count <= *max,
            InvariantCheck::MaxSessionAge(max_secs) => ctx.session.age().num_seconds() <= *max_secs,
            InvariantCheck::AllowedActions(actions) => actions.contains(&ctx.action.name),
            InvariantCheck::BlockedActions(actions) => !actions.contains(&ctx.action.name),
            InvariantCheck::Custom(f) => f(ctx),
        }
    }
}

impl std::fmt::Debug for Invariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invariant")
            .field("name", &self.name)
            .field("description", &self.description)
            .finish()
    }
}

/// A collection of invariants that acts as a gate evaluator.
pub struct InvariantSet {
    invariants: Vec<Invariant>,
}

impl InvariantSet {
    pub fn new(invariants: Vec<Invariant>) -> Self {
        Self { invariants }
    }

    pub fn add(&mut self, invariant: Invariant) {
        self.invariants.push(invariant);
    }

    pub fn len(&self) -> usize {
        self.invariants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }
}

#[async_trait]
impl Evaluator for InvariantSet {
    fn name(&self) -> &str {
        "invariants"
    }

    fn priority(&self) -> u32 {
        150
    }

    async fn evaluate(&self, ctx: &ActionContext) -> Verdict {
        for invariant in &self.invariants {
            if !invariant.holds(ctx) {
                tracing::error!(
                    invariant = %invariant.name,
                    description = %invariant.description,
                    "invariant violation"
                );
                return Verdict::Refuse(RefuseReason {
                    evaluator: "invariants".to_string(),
                    reason: format!(
                        "invariant '{}' violated: {}",
                        invariant.name, invariant.description
                    ),
                    code: RefuseCode::InvariantViolation,
                    evaluation_id: ctx.evaluation_id,
                });
            }
        }

        Verdict::Permit(PermitToken::new(ctx.evaluation_id, ctx.action.name.clone()))
    }
}
