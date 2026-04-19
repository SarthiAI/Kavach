use crate::context::ActionContext;
use crate::error::KavachError;
use crate::verdict::Verdict;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single audit log entry recording a gate evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID.
    pub id: Uuid,

    /// The evaluation this entry records.
    pub evaluation_id: Uuid,

    /// When the evaluation occurred.
    pub timestamp: DateTime<Utc>,

    /// Who attempted the action.
    pub principal_id: String,

    /// What action was attempted.
    pub action_name: String,

    /// What resource was targeted.
    pub resource: Option<String>,

    /// The verdict: "permit", "refuse", or "invalidate".
    pub verdict: String,

    /// Details of the verdict.
    pub verdict_detail: String,

    /// The evaluator that determined the verdict (for refuse/invalidate).
    pub decided_by: Option<String>,

    /// Session ID.
    pub session_id: Uuid,

    /// IP address of the caller.
    pub ip: Option<String>,

    /// Full context snapshot (optional, for forensics).
    pub context_snapshot: Option<serde_json::Value>,
}

impl AuditEntry {
    /// Create an audit entry from an evaluation context and verdict.
    pub fn from_verdict(ctx: &ActionContext, verdict: &Verdict) -> Self {
        let (verdict_str, detail, decided_by) = match verdict {
            Verdict::Permit(token) => (
                "permit".to_string(),
                format!("token_id={}", token.token_id),
                None,
            ),
            Verdict::Refuse(reason) => (
                "refuse".to_string(),
                format!("[{}] {}", reason.code, reason.reason),
                Some(reason.evaluator.clone()),
            ),
            Verdict::Invalidate(scope) => (
                "invalidate".to_string(),
                format!("{}", scope),
                Some(scope.evaluator.clone()),
            ),
        };

        Self {
            id: Uuid::new_v4(),
            evaluation_id: ctx.evaluation_id,
            timestamp: ctx.evaluated_at,
            principal_id: ctx.principal.id.clone(),
            action_name: ctx.action.name.clone(),
            resource: ctx.action.resource.clone(),
            verdict: verdict_str,
            verdict_detail: detail,
            decided_by,
            session_id: ctx.session.session_id,
            ip: ctx.environment.ip.map(|ip| ip.to_string()),
            context_snapshot: None,
        }
    }

    /// Attach a full context snapshot for forensic analysis.
    pub fn with_context_snapshot(mut self, ctx: &ActionContext) -> Self {
        self.context_snapshot = serde_json::to_value(ctx).ok();
        self
    }
}

/// Trait for audit log sinks.
///
/// Implementations write audit entries to a backing store.
/// The gate calls this for every evaluation, permits, refusals, and invalidations.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Record an audit entry.
    async fn record(&self, entry: AuditEntry) -> Result<(), KavachError>;

    /// Query recent entries (optional, not all sinks support queries).
    ///
    /// The default implementation returns an empty slice; persistent stores
    /// (Postgres, Elastic, etc.) should override with their own ordered read.
    async fn query_recent(&self, _limit: usize) -> Result<Vec<AuditEntry>, KavachError> {
        Ok(Vec::new())
    }
}

/// In-memory audit log for development and testing.
pub struct AuditLog {
    entries: std::sync::RwLock<Vec<AuditEntry>>,
    max_entries: usize,
}

impl AuditLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: std::sync::RwLock::new(Vec::new()),
            max_entries,
        }
    }

    /// Get all entries (for testing).
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.read().unwrap().clone()
    }

    /// Count entries matching a verdict type.
    pub fn count_by_verdict(&self, verdict: &str) -> usize {
        self.entries
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.verdict == verdict)
            .count()
    }
}

#[async_trait]
impl AuditSink for AuditLog {
    async fn record(&self, entry: AuditEntry) -> Result<(), KavachError> {
        let mut entries = self.entries.write().unwrap();
        entries.push(entry);

        // Keep bounded
        if entries.len() > self.max_entries {
            let drain_count = entries.len() - self.max_entries;
            entries.drain(..drain_count);
        }

        Ok(())
    }

    async fn query_recent(&self, limit: usize) -> Result<Vec<AuditEntry>, KavachError> {
        let entries = self.entries.read().unwrap();
        let start = entries.len().saturating_sub(limit);
        Ok(entries[start..].to_vec())
    }
}

/// Stdout audit sink, prints entries as JSON lines (for debugging/piping).
pub struct StdoutAuditSink;

#[async_trait]
impl AuditSink for StdoutAuditSink {
    async fn record(&self, entry: AuditEntry) -> Result<(), KavachError> {
        let json =
            serde_json::to_string(&entry).map_err(|e| KavachError::Serialization(e.to_string()))?;
        println!("{json}");
        Ok(())
    }
}
