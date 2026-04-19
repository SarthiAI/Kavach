use crate::context::ActionContext;
use crate::evaluator::Evaluator;
use crate::verdict::{
    InvalidationScope, InvalidationTarget, PermitToken, RefuseCode, RefuseReason, Verdict,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Signal from a drift detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriftSignal {
    /// No drift detected, context is coherent.
    Stable,

    /// Warning, context is shifting but not yet critical.
    Warning(DriftWarning),

    /// Violation, context has drifted beyond tolerance. Authority should be revoked.
    Violation(DriftViolation),
}

/// A non-critical drift warning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftWarning {
    pub detector: String,
    pub message: String,
    /// 0.0 = no drift, 1.0 = maximum drift
    pub severity: f64,
}

/// A critical drift violation that should trigger invalidation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftViolation {
    pub detector: String,
    pub message: String,
    pub evidence: String,
}

/// Trait for drift detection implementations.
#[async_trait]
pub trait DriftDetector: Send + Sync {
    /// Name of this detector.
    fn name(&self) -> &str;

    /// Check the action context for drift.
    async fn detect(&self, ctx: &ActionContext) -> DriftSignal;
}

// ─── Built-in drift detectors ────────────────────────────────────────

/// Detects when the caller's IP address changes mid-session.
///
/// Behavior is configurable via `max_distance_km`:
/// - `None` (default, strict): any IP change is a Violation. geoip is lossy, so
///   the safe default refuses to trust "nearby" lookups and invalidates on any change.
/// - `Some(km)` (tolerant): if both origin_geo and current geo are available, an IP
///   change within `km` becomes a Warning (surfaced, stacks toward the warning-refusal
///   threshold), and beyond `km` is a Violation. Fail-closed: if a threshold is set but
///   either origin_geo or current geo is missing, the change is a Violation, the gate
///   never silently permits an IP change on unverifiable distance.
#[derive(Default)]
pub struct GeoLocationDrift {
    /// If set, an IP change within this many km downgrades from Violation to Warning.
    /// If `None`, any IP change is a Violation.
    pub max_distance_km: Option<f64>,
}

impl GeoLocationDrift {
    /// Build a strict detector: any IP change is a Violation (same as `default()`).
    pub fn strict() -> Self {
        Self {
            max_distance_km: None,
        }
    }

    /// Build a detector that tolerates IP changes within `km` (downgraded to Warning).
    pub fn with_max_distance_km(km: f64) -> Self {
        Self {
            max_distance_km: Some(km),
        }
    }
}

#[async_trait]
impl DriftDetector for GeoLocationDrift {
    fn name(&self) -> &str {
        "geo_drift"
    }

    async fn detect(&self, ctx: &ActionContext) -> DriftSignal {
        let current_ip = ctx.environment.ip;
        let origin_ip = ctx.session.origin_ip;

        let (current, origin) = match (current_ip, origin_ip) {
            (Some(c), Some(o)) if c != o => (c, o),
            _ => return DriftSignal::Stable,
        };

        let geo_note = ctx
            .environment
            .geo
            .as_ref()
            .map(|g| {
                format!(
                    " (current geo: {}{})",
                    g.country_code,
                    g.city
                        .as_deref()
                        .map(|c| format!("/{c}"))
                        .unwrap_or_default()
                )
            })
            .unwrap_or_default();

        // Strict mode: any IP change is a violation.
        let Some(max_km) = self.max_distance_km else {
            return DriftSignal::Violation(DriftViolation {
                detector: self.name().to_string(),
                message: format!("IP changed mid-session: {origin} → {current}{geo_note}"),
                evidence: format!("origin_ip={origin}, current_ip={current}"),
            });
        };

        // Tolerant mode: need both origin_geo and current geo to compute distance.
        // If either is missing, we can't verify the distance → fail closed.
        let distance = ctx
            .session
            .origin_geo
            .as_ref()
            .zip(ctx.environment.geo.as_ref())
            .and_then(|(o, c)| o.distance_km(c));

        match distance {
            None => DriftSignal::Violation(DriftViolation {
                detector: self.name().to_string(),
                message: format!(
                    "IP changed mid-session and geo distance is unverifiable: {origin} → {current}{geo_note}"
                ),
                evidence: format!(
                    "origin_ip={origin}, current_ip={current}, max_distance_km={max_km}, origin_geo_present={}, current_geo_present={}",
                    ctx.session.origin_geo.is_some(),
                    ctx.environment.geo.is_some()
                ),
            }),
            Some(d) if d > max_km => DriftSignal::Violation(DriftViolation {
                detector: self.name().to_string(),
                message: format!(
                    "IP changed mid-session and moved {d:.1}km (> {max_km:.1}km threshold): {origin} → {current}{geo_note}"
                ),
                evidence: format!(
                    "origin_ip={origin}, current_ip={current}, distance_km={d:.1}, max_distance_km={max_km}"
                ),
            }),
            Some(d) => DriftSignal::Warning(DriftWarning {
                detector: self.name().to_string(),
                message: format!(
                    "IP changed mid-session but within {max_km:.1}km threshold ({d:.1}km): {origin} → {current}{geo_note}"
                ),
                severity: (d / max_km).min(1.0),
            }),
        }
    }
}

/// Detects when a session has exceeded its maximum age.
pub struct SessionAgeDrift {
    /// Maximum session age in seconds (default: 4 hours).
    pub max_age_seconds: i64,
}

impl Default for SessionAgeDrift {
    fn default() -> Self {
        Self {
            max_age_seconds: 4 * 3600,
        }
    }
}

#[async_trait]
impl DriftDetector for SessionAgeDrift {
    fn name(&self) -> &str {
        "session_age_drift"
    }

    async fn detect(&self, ctx: &ActionContext) -> DriftSignal {
        let age = ctx.session.age().num_seconds();

        if age > self.max_age_seconds {
            DriftSignal::Violation(DriftViolation {
                detector: self.name().to_string(),
                message: format!(
                    "session age ({age}s) exceeds maximum ({}s)",
                    self.max_age_seconds
                ),
                evidence: format!(
                    "session_started={}, max_age={}s",
                    ctx.session.started_at, self.max_age_seconds
                ),
            })
        } else if age > self.max_age_seconds * 3 / 4 {
            // Warning at 75% of max age
            DriftSignal::Warning(DriftWarning {
                detector: self.name().to_string(),
                message: format!(
                    "session approaching max age ({age}s / {}s)",
                    self.max_age_seconds
                ),
                severity: age as f64 / self.max_age_seconds as f64,
            })
        } else {
            DriftSignal::Stable
        }
    }
}

/// Detects when the device fingerprint changes mid-session.
pub struct DeviceDrift;

#[async_trait]
impl DriftDetector for DeviceDrift {
    fn name(&self) -> &str {
        "device_drift"
    }

    async fn detect(&self, ctx: &ActionContext) -> DriftSignal {
        if let (Some(current), Some(origin)) = (&ctx.environment.device, &ctx.session.origin_device)
        {
            if current != origin {
                return DriftSignal::Violation(DriftViolation {
                    detector: self.name().to_string(),
                    message: "device fingerprint changed mid-session".to_string(),
                    evidence: format!(
                        "origin_device={}, current_device={}",
                        origin.hash, current.hash
                    ),
                });
            }
        }
        DriftSignal::Stable
    }
}

/// Detects unusual action patterns (simple frequency-based).
pub struct BehaviorDrift {
    /// Maximum actions per minute before warning.
    pub warn_threshold: u64,
    /// Maximum actions per minute before violation.
    pub violation_threshold: u64,
}

impl Default for BehaviorDrift {
    fn default() -> Self {
        Self {
            warn_threshold: 30,
            violation_threshold: 100,
        }
    }
}

#[async_trait]
impl DriftDetector for BehaviorDrift {
    fn name(&self) -> &str {
        "behavior_drift"
    }

    async fn detect(&self, ctx: &ActionContext) -> DriftSignal {
        let age_minutes = ctx.session.age().num_minutes().max(1) as u64;
        let rate = ctx.session.action_count / age_minutes;

        if rate > self.violation_threshold {
            DriftSignal::Violation(DriftViolation {
                detector: self.name().to_string(),
                message: format!(
                    "action rate ({rate}/min) exceeds violation threshold ({})",
                    self.violation_threshold
                ),
                evidence: format!(
                    "actions={}, session_age_min={age_minutes}, rate={rate}/min",
                    ctx.session.action_count
                ),
            })
        } else if rate > self.warn_threshold {
            DriftSignal::Warning(DriftWarning {
                detector: self.name().to_string(),
                message: format!("elevated action rate: {rate}/min"),
                severity: rate as f64 / self.violation_threshold as f64,
            })
        } else {
            DriftSignal::Stable
        }
    }
}

// ─── Composite evaluator ─────────────────────────────────────────────

/// Wraps multiple drift detectors into a single gate evaluator.
///
/// Runs all detectors. A single Violation → Invalidate.
/// Accumulated warnings above a threshold → Refuse.
pub struct DriftEvaluator {
    detectors: Vec<Box<dyn DriftDetector>>,
    /// Number of simultaneous warnings that trigger a refusal.
    pub warning_threshold: usize,
}

impl DriftEvaluator {
    pub fn new(detectors: Vec<Box<dyn DriftDetector>>) -> Self {
        Self {
            detectors,
            warning_threshold: 3,
        }
    }

    /// Create with all default built-in detectors.
    pub fn with_defaults() -> Self {
        Self::new(vec![
            Box::new(GeoLocationDrift::default()),
            Box::new(SessionAgeDrift::default()),
            Box::new(DeviceDrift),
            Box::new(BehaviorDrift::default()),
        ])
    }
}

#[async_trait]
impl Evaluator for DriftEvaluator {
    fn name(&self) -> &str {
        "drift"
    }

    fn priority(&self) -> u32 {
        100
    }

    async fn evaluate(&self, ctx: &ActionContext) -> Verdict {
        let mut warnings = Vec::new();

        for detector in &self.detectors {
            match detector.detect(ctx).await {
                DriftSignal::Stable => {}
                DriftSignal::Warning(w) => {
                    tracing::warn!(detector = w.detector, message = %w.message, "drift warning");
                    warnings.push(w);
                }
                DriftSignal::Violation(v) => {
                    tracing::error!(detector = v.detector, message = %v.message, "drift violation");
                    return Verdict::Invalidate(InvalidationScope {
                        target: InvalidationTarget::Session(ctx.session.session_id),
                        reason: v.message,
                        evaluator: self.name().to_string(),
                    });
                }
            }
        }

        // Too many simultaneous warnings = refuse
        if warnings.len() >= self.warning_threshold {
            return Verdict::Refuse(RefuseReason {
                evaluator: self.name().to_string(),
                reason: format!(
                    "{} concurrent drift warnings (threshold: {})",
                    warnings.len(),
                    self.warning_threshold
                ),
                code: RefuseCode::DriftDetected,
                evaluation_id: ctx.evaluation_id,
            });
        }

        Verdict::Permit(PermitToken::new(ctx.evaluation_id, ctx.action.name.clone()))
    }
}
