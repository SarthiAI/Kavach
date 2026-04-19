use crate::context::{ActionContext, PrincipalKind};
use crate::error::PolicyError;
use crate::evaluator::Evaluator;
use crate::rate_limit::{InMemoryRateLimitStore, RateLimitStore};
use crate::verdict::{PermitToken, RefuseCode, RefuseReason, Verdict};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// A set of policies loaded from configuration.
///
/// The canonical wire-name for the policy list is `policy` (singular,
/// inherited from TOML's `[[policy]]` array-of-tables convention). The
/// alias `policies` (plural) is also accepted on deserialization so JSON
/// and dict callers can use the more natural plural name without breaking
/// existing TOML files.
///
/// `deny_unknown_fields` rejects typos at the top level (e.g. `polciies`,
/// `policys`) so a misspelled wrapper key produces a clear error instead
/// of yielding an empty PolicySet that default-denies every action.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicySet {
    #[serde(rename = "policy", alias = "policies", default)]
    pub policies: Vec<Policy>,
}

impl PolicySet {
    /// Load policies from a TOML string.
    pub fn from_toml(source: &str) -> Result<Self, PolicyError> {
        toml::from_str(source).map_err(|e| PolicyError::Parse(e.to_string()))
    }

    /// Load policies from a TOML file.
    pub fn from_file(path: &str) -> Result<Self, PolicyError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| PolicyError::Parse(e.to_string()))?;
        Self::from_toml(&content)
    }
}

/// A single policy rule.
///
/// `deny_unknown_fields` makes typos in policy field names (e.g. `naem` instead
/// of `name`, `efect` instead of `effect`) produce a clear deserialize error
/// instead of being silently dropped, which previously could weaken a policy
/// without any signal. Applies uniformly to TOML, dict, and JSON loaders.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Human-readable name for this policy.
    pub name: String,

    /// What happens when all conditions match: permit or refuse.
    pub effect: Effect,

    /// All conditions must be true for this policy to apply.
    pub conditions: Vec<Condition>,

    /// Optional description.
    pub description: Option<String>,

    /// Priority (lower = evaluated first). Default: 100.
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_priority() -> u32 {
    100
}

/// The effect of a matching policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Permit,
    Refuse,
}

/// A condition that must hold for a policy to apply.
///
/// Externally tagged: each TOML / dict / JSON inline-table has exactly one key
/// that names the variant (`identity_kind`, `param_max`, etc.) and a value with
/// the variant's payload. `deny_unknown_fields` rejects typos such as
/// `idnetity_kind`, which previously parsed silently and dropped the condition,
/// resulting in a more permissive policy than the author intended.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// Principal must have this role.
    IdentityRole(String),

    /// Principal must be of this kind.
    IdentityKind(PrincipalKind),

    /// Principal ID must match.
    IdentityId(String),

    /// Action name must match (supports glob patterns: "refund.*").
    Action(String),

    /// A numeric parameter must be present AND at most this value.
    ///
    /// **Fail-closed on missing field**: if the action context has no
    /// `params[field]`, the condition evaluates to `false` (the policy
    /// does not match, and the gate's default-deny floor kicks in).
    /// This matches the product's fail-closed contract, do not rely
    /// on `ParamMax` to vacuously permit when a field is absent.
    ParamMax { field: String, max: f64 },

    /// A numeric parameter must be present AND at least this value.
    ///
    /// **Fail-closed on missing field**: same semantics as
    /// [`Condition::ParamMax`], a missing field fails the condition.
    ParamMin { field: String, min: f64 },

    /// A string parameter must match one of these values.
    ParamIn { field: String, values: Vec<String> },

    /// Rate limit: max N actions of this type within a time window.
    RateLimit { max: u32, window: String },

    /// Session must be younger than this duration.
    SessionAgeMax(String),

    /// Resource must match this pattern.
    Resource(String),

    /// Action must happen within this time window (e.g., "09:00-18:00").
    TimeWindow(String),
}

impl Condition {
    /// Evaluate this condition against an action context.
    ///
    /// Most conditions are purely synchronous. [`Condition::RateLimit`] is the
    /// exception, it queries the pluggable [`RateLimitStore`], which may be
    /// a remote backend. On any store error the condition evaluates to
    /// `false` (fail-closed): the gate refuses to attest that the caller is
    /// under the limit when the backend can't prove it.
    pub async fn matches(
        &self,
        ctx: &ActionContext,
        rate_store: &dyn RateLimitStore,
        now: i64,
    ) -> bool {
        match self {
            Condition::IdentityRole(role) => ctx.principal.roles.contains(role),

            Condition::IdentityKind(kind) => &ctx.principal.kind == kind,

            Condition::IdentityId(id) => ctx.principal.id == *id,

            Condition::Action(pattern) => match_pattern(pattern, &ctx.action.name),

            Condition::ParamMax { field, max } => ctx
                .action
                .param_as_f64(field)
                .map(|v| v <= *max)
                .unwrap_or(false), // fail-closed on missing field (see doc on variant)

            Condition::ParamMin { field, min } => ctx
                .action
                .param_as_f64(field)
                .map(|v| v >= *min)
                .unwrap_or(false),

            Condition::ParamIn { field, values } => ctx
                .action
                .param_as_str(field)
                .map(|v| values.iter().any(|allowed| allowed == v))
                .unwrap_or(false),

            Condition::RateLimit { max, window } => {
                // The current call has already been recorded by `PolicyEngine::evaluate`
                // before policies are checked. So `count` here is inclusive of this
                // attempt, use `<=` so that `max = N` allows exactly N calls per window.
                let window_secs = parse_duration_secs(window).unwrap_or(3600);
                let key = format!("{}:{}", ctx.principal.id, ctx.action.name);
                match rate_store.count_in_window(&key, now, window_secs).await {
                    Ok(count) => count <= *max as u64,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            key = %key,
                            "rate-limit store error, failing closed",
                        );
                        false
                    }
                }
            }

            Condition::SessionAgeMax(max_age) => {
                let max_secs = parse_duration_secs(max_age).unwrap_or(86400);
                ctx.session.age().num_seconds() <= max_secs as i64
            }

            Condition::Resource(pattern) => ctx
                .action
                .resource
                .as_ref()
                .map(|r| match_pattern(pattern, r))
                .unwrap_or(false),

            Condition::TimeWindow(window) => evaluate_time_window(window, ctx.evaluated_at),
        }
    }
}

/// The policy evaluation engine.
///
/// Implements the [`Evaluator`] trait so it plugs directly into the gate.
/// Policies are evaluated in priority order. The first matching policy
/// determines the verdict. If no policy matches, the default is **Refuse**
/// (default-deny).
pub struct PolicyEngine {
    policies: RwLock<Vec<Policy>>,
    rate_store: Arc<dyn RateLimitStore>,
}

impl PolicyEngine {
    /// Build a policy engine backed by the process-local in-memory rate-limit
    /// store. Behavior identical to pre-refactor single-node deployments.
    pub fn new(policy_set: PolicySet) -> Self {
        Self::with_rate_store(policy_set, Arc::new(InMemoryRateLimitStore::new()))
    }

    /// Build a policy engine with a user-supplied [`RateLimitStore`]. Use this
    /// to plug in a distributed backend (Redis, etc.) so rate-limit counts
    /// are consistent across nodes.
    pub fn with_rate_store(policy_set: PolicySet, rate_store: Arc<dyn RateLimitStore>) -> Self {
        let mut policies = policy_set.policies;
        policies.sort_by_key(|p| p.priority);
        Self {
            policies: RwLock::new(policies),
            rate_store,
        }
    }

    /// Hot-reload the policy set.
    ///
    /// Takes `&self` (not `&mut self`) so it is callable through an
    /// `Arc<PolicyEngine>` that is shared with a `Gate`. Interior mutability
    /// is provided by an `RwLock` around the policy list, in-flight
    /// evaluations continue to see the old set until they finish and release
    /// their read lock; subsequent evaluations pick up the new set.
    pub fn reload(&self, policy_set: PolicySet) {
        let mut new_policies = policy_set.policies;
        new_policies.sort_by_key(|p| p.priority);
        let new_len = new_policies.len();
        let mut guard = self.policies.write().unwrap();
        *guard = new_policies;
        tracing::info!("policies reloaded: {} rules", new_len);
    }

    /// Number of policies currently loaded (for observability / tests).
    pub fn policy_count(&self) -> usize {
        self.policies.read().unwrap().len()
    }

    /// Find the first matching policy for the given context.
    ///
    /// Clones the policy list under the read lock, then releases the lock
    /// before awaiting any store I/O. This avoids holding the policy-list
    /// lock across `.await` points, which would be unsound with
    /// `std::sync::RwLock` (not `Send` across awaits) and would also block
    /// hot-reload waiters on slow rate-limit backends.
    async fn find_matching_policy(&self, ctx: &ActionContext, now: i64) -> Option<Policy> {
        let snapshot: Vec<Policy> = {
            let guard = self.policies.read().unwrap();
            guard.clone()
        };

        for policy in snapshot {
            let mut all_match = true;
            for cond in &policy.conditions {
                if !cond.matches(ctx, &*self.rate_store, now).await {
                    all_match = false;
                    break;
                }
            }
            if all_match {
                return Some(policy);
            }
        }
        None
    }
}

#[async_trait]
impl Evaluator for PolicyEngine {
    fn name(&self) -> &str {
        "policy"
    }

    fn priority(&self) -> u32 {
        50
    }

    async fn evaluate(&self, ctx: &ActionContext) -> Verdict {
        // Record this action for rate limiting. `now` is captured once and
        // used for both the record and any in-window counts so every
        // condition sees the same clock, this matters because record and
        // count can race against each other across async awaits.
        let now = chrono::Utc::now().timestamp();
        let key = format!("{}:{}", ctx.principal.id, ctx.action.name);
        if let Err(err) = self.rate_store.record(&key, now).await {
            // Recording failed, we must decide whether to refuse the action
            // entirely. Default-deny: refuse, because any subsequent
            // rate-limit check would be based on under-counted state.
            tracing::warn!(
                error = %err,
                key = %key,
                "rate-limit store record failed, refusing action",
            );
            return Verdict::Refuse(RefuseReason {
                evaluator: "policy".to_string(),
                reason: "rate-limit backend unavailable".to_string(),
                code: RefuseCode::PolicyDenied,
                evaluation_id: ctx.evaluation_id,
            });
        }

        match self.find_matching_policy(ctx, now).await {
            Some(policy) if policy.effect == Effect::Permit => {
                tracing::debug!(policy = %policy.name, "policy permits action");
                Verdict::Permit(PermitToken::new(ctx.evaluation_id, ctx.action.name.clone()))
            }
            Some(policy) => {
                tracing::debug!(policy = %policy.name, "policy refuses action");
                Verdict::Refuse(RefuseReason {
                    evaluator: "policy".to_string(),
                    reason: format!("denied by policy '{}'", policy.name),
                    code: RefuseCode::PolicyDenied,
                    evaluation_id: ctx.evaluation_id,
                })
            }
            None => {
                // Default deny, no matching policy means no permission
                tracing::debug!(action = %ctx.action.name, "no matching policy (default deny)");
                Verdict::Refuse(RefuseReason {
                    evaluator: "policy".to_string(),
                    reason: format!(
                        "no policy permits '{}' for principal '{}'",
                        ctx.action.name, ctx.principal.id
                    ),
                    code: RefuseCode::NoPolicyMatch,
                    evaluation_id: ctx.evaluation_id,
                })
            }
        }
    }
}

/// Simple glob-style pattern matching.
/// Supports only trailing wildcard: "refund.*" matches "refund.create", "refund.cancel".
fn match_pattern(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix(".*") {
        value.starts_with(prefix)
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

/// Evaluate a `TimeWindow` condition.
///
/// Accepted formats:
/// - `"09:00-18:00"`, UTC comparison (legacy, kept for backward compat).
/// - `"09:00-18:00 Asia/Kolkata"`, `evaluated_at` is converted to the named
///   IANA timezone before comparison. The timezone portion is everything
///   after the first whitespace; it must be a valid `chrono-tz` identifier.
///
/// Supports overnight windows like `"22:00-06:00"` (wraps midnight) by
/// taking the union of `[start, 24:00)` and `[00:00, end]`.
///
/// **Fail-closed on malformed input.** A window that doesn't match the
/// expected shape, has an unparseable tz, or has malformed HH:MM values
/// returns `false`, the policy does not match. Earlier behavior returned
/// `true` on malformed windows, which was fail-open.
fn evaluate_time_window(window: &str, evaluated_at: chrono::DateTime<chrono::Utc>) -> bool {
    use chrono::{NaiveTime, TimeZone};

    // Split off an optional timezone suffix after whitespace.
    let (range, tz_name) = match window.split_once(char::is_whitespace) {
        Some((range, rest)) => (range.trim(), Some(rest.trim())),
        None => (window.trim(), None),
    };

    let Some((start_str, end_str)) = range.split_once('-') else {
        tracing::warn!(window, "TimeWindow: malformed (missing '-'), refusing");
        return false;
    };
    let Ok(start) = NaiveTime::parse_from_str(start_str.trim(), "%H:%M") else {
        tracing::warn!(window, "TimeWindow: malformed start HH:MM, refusing");
        return false;
    };
    let Ok(end) = NaiveTime::parse_from_str(end_str.trim(), "%H:%M") else {
        tracing::warn!(window, "TimeWindow: malformed end HH:MM, refusing");
        return false;
    };

    // Convert evaluated_at to the target timezone if one was supplied.
    let now_time: NaiveTime = match tz_name {
        Some(name) => {
            let Ok(tz) = name.parse::<chrono_tz::Tz>() else {
                tracing::warn!(window, tz = name, "TimeWindow: unknown timezone, refusing");
                return false;
            };
            tz.from_utc_datetime(&evaluated_at.naive_utc()).time()
        }
        None => evaluated_at.time(),
    };

    if start <= end {
        // Same-day window: [start, end]
        now_time >= start && now_time <= end
    } else {
        // Overnight window (e.g., 22:00-06:00): union of [start, 23:59:59.999]
        // and [00:00, end]
        now_time >= start || now_time <= end
    }
}

/// Parse a human-readable duration string to seconds.
/// Supports: "30s", "5m", "1h", "24h", "1d"
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        n.parse().ok()
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<u64>().ok().map(|n| n * 60)
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<u64>().ok().map(|n| n * 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        n.parse::<u64>().ok().map(|n| n * 86400)
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(match_pattern("refund.*", "refund.create"));
        assert!(match_pattern("refund.*", "refund.cancel"));
        assert!(!match_pattern("refund.*", "payment.create"));
        assert!(match_pattern("issue_refund", "issue_refund"));
        assert!(!match_pattern("issue_refund", "issue_credit"));
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("24h"), Some(86400));
        assert_eq!(parse_duration_secs("1d"), Some(86400));
    }

    mod time_window {
        use super::super::evaluate_time_window;
        use chrono::{TimeZone, Utc};

        fn at_utc(h: u32, m: u32) -> chrono::DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 6, 15, h, m, 0).unwrap()
        }

        #[test]
        fn utc_same_day_inside() {
            assert!(evaluate_time_window("09:00-18:00", at_utc(12, 0)));
        }

        #[test]
        fn utc_same_day_before() {
            assert!(!evaluate_time_window("09:00-18:00", at_utc(8, 0)));
        }

        #[test]
        fn utc_same_day_after() {
            assert!(!evaluate_time_window("09:00-18:00", at_utc(19, 0)));
        }

        #[test]
        fn utc_boundary_inclusive_at_start() {
            assert!(evaluate_time_window("09:00-18:00", at_utc(9, 0)));
        }

        #[test]
        fn utc_boundary_inclusive_at_end() {
            assert!(evaluate_time_window("09:00-18:00", at_utc(18, 0)));
        }

        #[test]
        fn overnight_window_wraps_midnight() {
            // 22:00 to 06:00 the next day (UTC).
            assert!(evaluate_time_window("22:00-06:00", at_utc(23, 30)));
            assert!(evaluate_time_window("22:00-06:00", at_utc(1, 0)));
            assert!(evaluate_time_window("22:00-06:00", at_utc(6, 0)));
            assert!(!evaluate_time_window("22:00-06:00", at_utc(12, 0)));
            assert!(!evaluate_time_window("22:00-06:00", at_utc(21, 59)));
        }

        #[test]
        fn timezone_converts_before_comparing() {
            // 12:00 UTC == 17:30 IST (UTC+05:30). Window expressed in IST.
            assert!(evaluate_time_window(
                "09:00-18:00 Asia/Kolkata",
                at_utc(12, 0)
            ));
            // 06:00 UTC == 11:30 IST, still inside the IST window.
            assert!(evaluate_time_window(
                "09:00-18:00 Asia/Kolkata",
                at_utc(6, 0)
            ));
            // 00:00 UTC == 05:30 IST, outside the IST window.
            assert!(!evaluate_time_window(
                "09:00-18:00 Asia/Kolkata",
                at_utc(0, 0)
            ));
        }

        #[test]
        fn timezone_us_vs_utc_divergence() {
            // 22:00 UTC == 18:00 US/Eastern (EDT). The US window should
            // treat this as at-end-boundary. If we were still doing UTC
            // comparison, 22:00 would be outside a 09:00-18:00 window.
            assert!(evaluate_time_window(
                "09:00-18:00 US/Eastern",
                at_utc(22, 0)
            ));
        }

        #[test]
        fn malformed_missing_dash_fails_closed() {
            assert!(!evaluate_time_window("nonsense", at_utc(12, 0)));
        }

        #[test]
        fn malformed_bad_start_time_fails_closed() {
            assert!(!evaluate_time_window("nope-18:00", at_utc(12, 0)));
        }

        #[test]
        fn malformed_bad_end_time_fails_closed() {
            assert!(!evaluate_time_window("09:00-lolwut", at_utc(12, 0)));
        }

        #[test]
        fn unknown_timezone_fails_closed() {
            assert!(!evaluate_time_window("09:00-18:00 Not/Real", at_utc(12, 0)));
        }

        #[test]
        fn empty_window_fails_closed() {
            assert!(!evaluate_time_window("", at_utc(12, 0)));
        }
    }

    #[test]
    fn test_policy_from_toml() {
        let toml = r#"
[[policy]]
name = "allow_small_refunds"
effect = "permit"
conditions = [
    { identity_role = "support_agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 50000.0 } },
]
"#;
        let set = PolicySet::from_toml(toml).unwrap();
        assert_eq!(set.policies.len(), 1);
        assert_eq!(set.policies[0].name, "allow_small_refunds");
        assert_eq!(set.policies[0].effect, Effect::Permit);
        assert_eq!(set.policies[0].conditions.len(), 3);
    }
}
