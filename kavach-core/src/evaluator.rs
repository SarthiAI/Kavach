use crate::context::ActionContext;
use crate::verdict::Verdict;
use async_trait::async_trait;

/// A single evaluation step in the gate's pipeline.
///
/// Evaluators are composable, the gate runs them in sequence and stops
/// at the first Refuse or Invalidate. All evaluators must return Permit
/// for the action to proceed.
///
/// Built-in evaluators: [`PolicyEvaluator`](crate::policy::PolicyEngine),
/// [`DriftEvaluator`](crate::drift), [`InvariantEvaluator`](crate::invariant::InvariantSet).
///
/// Custom evaluators can be added for domain-specific logic.
///
/// # Example
///
/// ```ignore
/// use kavach_core::{Evaluator, ActionContext, Verdict};
///
/// struct BusinessHoursOnly;
///
/// #[async_trait::async_trait]
/// impl Evaluator for BusinessHoursOnly {
///     fn name(&self) -> &str { "business_hours" }
///
///     async fn evaluate(&self, ctx: &ActionContext) -> Verdict {
///         let hour = ctx.evaluated_at.hour();
///         if (9..18).contains(&hour) {
///             Verdict::Permit(/* ... */)
///         } else {
///             Verdict::Refuse(/* ... */)
///         }
///     }
/// }
/// ```
#[async_trait]
pub trait Evaluator: Send + Sync {
    /// A short, unique name for this evaluator (used in audit logs and refuse reasons).
    fn name(&self) -> &str;

    /// Evaluate the action context and return a verdict.
    ///
    /// The evaluator should examine the context and decide:
    /// - `Permit`, this evaluator has no objection
    /// - `Refuse`, this evaluator blocks the action
    /// - `Invalidate`, this evaluator revokes broader authority
    async fn evaluate(&self, ctx: &ActionContext) -> Verdict;

    /// Priority order (lower = evaluated first). Default is 100.
    ///
    /// Suggested ranges:
    /// - 0-49: identity resolution and session validation
    /// - 50-99: policy evaluation
    /// - 100-149: drift detection
    /// - 150-199: invariant enforcement
    /// - 200+: custom evaluators
    fn priority(&self) -> u32 {
        100
    }
}
