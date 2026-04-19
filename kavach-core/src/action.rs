use crate::context::ActionDescriptor;
use crate::error::KavachError;
use async_trait::async_trait;

/// An action that can be gated by Kavach.
///
/// Any operation with side effects should implement this trait.
/// The gate wraps the action in a [`Guarded<A>`](crate::gate::Guarded) that
/// can only be executed after receiving a Permit verdict.
///
/// # Example
///
/// ```ignore
/// use kavach_core::{Action, ActionDescriptor};
///
/// struct IssueRefund {
///     order_id: String,
///     amount: f64,
///     currency: String,
/// }
///
/// #[async_trait::async_trait]
/// impl Action for IssueRefund {
///     type Output = RefundResult;
///
///     fn descriptor(&self) -> ActionDescriptor {
///         ActionDescriptor::new("issue_refund")
///             .with_resource(&self.order_id)
///             .with_param("amount", serde_json::json!(self.amount))
///             .with_param("currency", serde_json::json!(self.currency))
///     }
///
///     async fn execute(self) -> Result<Self::Output, KavachError> {
///         // Actually process the refund
///         todo!()
///     }
/// }
/// ```
#[async_trait]
pub trait Action: Send + Sync + 'static {
    /// The output type produced by successful execution.
    type Output: Send;

    /// Describe this action for the gate to evaluate.
    ///
    /// The descriptor includes the action name, the resource being
    /// acted upon, and any parameters relevant to policy/invariant checks.
    fn descriptor(&self) -> ActionDescriptor;

    /// Execute the action.
    ///
    /// This is only called after the gate issues a Permit verdict.
    /// You should never call this directly, use [`Guarded::execute`](crate::gate::Guarded::execute).
    async fn execute(self) -> Result<Self::Output, KavachError>;
}
