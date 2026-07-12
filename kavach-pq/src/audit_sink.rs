//! Bounded-memory audit: sink trait, file sink, and the managed chain.
//!
//! [`SignedAuditChain`] retains every entry by default. For sustained,
//! high-volume workloads (one signed entry per request, forever) that grows
//! resident memory without bound. [`ManagedAuditChain`] wraps a chain and keeps
//! memory flat: a background worker durably writes the oldest entries through an
//! [`AuditSink`] and then prunes them from memory, under a configurable
//! [`RetentionPolicy`].
//!
//! The retention policy supports three eviction triggers, any combination of
//! which can be set at once:
//! - `max_entries`: evict when the in-memory window exceeds N entries.
//! - `max_bytes`: evict when the estimated in-memory bytes exceed M.
//! - `flush_interval`: evict on a timer, even below the size thresholds.
//!
//! Eviction is transactional: entries are pruned from memory only after the
//! sink confirms a durable (fsynced) write, so a sink failure never loses data.
//! When the sink is down, [`SinkFailurePolicy`] decides how backpressure is
//! applied so the process pushes back instead of growing until it is OOM-killed.
//!
//! ## Full-chain verification
//!
//! [`FileAuditSink`] writes one continuous JSONL of the evicted prefix
//! `[0, base_index)`. The in-memory tail is `[base_index, len)`. Concatenating
//! the on-disk bytes with [`SignedAuditChain::export_jsonl`] of the retained
//! window yields one contiguous chain from genesis that
//! [`verify_chain`](crate::audit::verify_chain) accepts unchanged. For several
//! rolling files use [`verify_segments`](crate::audit::verify_segments).

use crate::audit::{export_jsonl, SignedAuditChain, SignedAuditEntry};
use crate::error::{PqError, Result};
use crate::sign::Signer;
use kavach_core::audit::AuditEntry;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// A durable destination for evicted audit entries.
///
/// The contract: when `append_segment` returns `Ok`, the entries are durably
/// persisted (an implementation that writes to disk must `fsync` before
/// returning). The managed chain prunes an entry from memory only after the
/// sink confirms it is safe elsewhere. `append_segment` is called with a
/// contiguous, ascending-index slice and may be called concurrently only under
/// the managed chain's internal flush lock (never re-entrantly).
pub trait AuditSink: Send + Sync {
    /// Durably persist a contiguous batch of entries. Empty input is a no-op.
    fn append_segment(&self, entries: &[SignedAuditEntry]) -> Result<()>;
}

/// An [`AuditSink`] that appends entries to a JSONL file, fsyncing each batch.
///
/// The file is opened per batch (append mode), written, fsynced, and closed.
/// Flushes are batched, so open-per-batch overhead is negligible, and it
/// tolerates external log rotation of the target path between batches.
pub struct FileAuditSink {
    path: PathBuf,
}

impl FileAuditSink {
    /// Persist to `path`, creating it if missing and appending if it exists.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// The target path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileAuditSink {
    fn append_segment(&self, entries: &[SignedAuditEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        use std::io::Write;
        let buf = export_jsonl(entries)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| PqError::Serialization(format!("audit sink open: {e}")))?;
        file.write_all(&buf)
            .map_err(|e| PqError::Serialization(format!("audit sink write: {e}")))?;
        file.sync_all()
            .map_err(|e| PqError::Serialization(format!("audit sink fsync: {e}")))?;
        Ok(())
    }
}

/// How the managed chain applies backpressure when its sink cannot keep up.
#[derive(Debug, Clone)]
pub enum SinkFailurePolicy {
    /// Keep unflushed entries in memory and retry on the next cycle. Once the
    /// resident set reaches `buffer_ceiling` entries, `append` starts failing
    /// (a hard ceiling) until the sink drains the backlog.
    Buffer {
        /// Maximum entries the in-memory buffer may hold before `append` errors.
        buffer_ceiling: u64,
    },
    /// The moment the sink cannot accept a due flush (resident set over
    /// threshold and the last flush failed), `append` fails so the caller
    /// applies backpressure immediately. Tighter memory bound than `Buffer`.
    RejectAppends,
}

/// Configurable retention policy for a [`ManagedAuditChain`].
///
/// `max_entries`, `max_bytes`, and `flush_interval` are the three eviction
/// triggers. Any combination may be set; whichever fires first runs one
/// flush-then-prune cycle down to `min_retained` most-recent entries.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Evict when the in-memory window exceeds this many entries.
    pub max_entries: Option<u64>,
    /// Evict when the estimated in-memory bytes exceed this.
    pub max_bytes: Option<u64>,
    /// Evict on this interval even below the size thresholds.
    pub flush_interval: Option<Duration>,
    /// Always keep at least this many most-recent entries in memory so tail
    /// verify/export stays cheap and a burst never evicts down to zero.
    pub min_retained: u64,
    /// Backpressure shape when the sink cannot keep up.
    pub on_sink_failure: SinkFailurePolicy,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_entries: Some(10_000),
            max_bytes: None,
            flush_interval: Some(Duration::from_secs(1)),
            min_retained: 256,
            on_sink_failure: SinkFailurePolicy::Buffer {
                buffer_ceiling: 1_000_000,
            },
        }
    }
}

impl RetentionPolicy {
    /// Whether any eviction trigger is configured (used to decide whether the
    /// background worker needs to run).
    fn has_trigger(&self) -> bool {
        self.max_entries.is_some() || self.max_bytes.is_some() || self.flush_interval.is_some()
    }
}

/// A snapshot of a [`ManagedAuditChain`]'s counters.
#[derive(Debug, Clone)]
pub struct ManagedStats {
    /// Total entries ever appended.
    pub entries_appended: u64,
    /// Total entries durably evicted to the sink.
    pub entries_evicted: u64,
    /// Entries currently held in memory.
    pub resident_entries: u64,
    /// Estimated bytes currently held in memory.
    pub resident_bytes: u64,
    /// Number of failed flush attempts.
    pub sink_failures: u64,
    /// Whether the last flush attempt succeeded (true if none attempted yet).
    pub sink_healthy: bool,
    /// Logical index up to which entries have been durably evicted.
    pub last_flush_index: u64,
}

/// Mutable counters guarded by their own lock (small, contended only at flush).
struct Counters {
    entries_evicted: u64,
    sink_failures: u64,
    sink_healthy: bool,
    last_flush_index: u64,
}

struct ManagedInner {
    chain: SignedAuditChain,
    sink: Arc<dyn AuditSink>,
    policy: RetentionPolicy,
    /// Logical index up to which entries have been flushed (== chain base_index
    /// after a successful prune). Also the low end of the next flush batch.
    last_flushed: Mutex<u64>,
    /// Serializes worker and manual flush cycles so no segment is written twice.
    flush_guard: Mutex<()>,
    counters: Mutex<Counters>,
    stop: AtomicBool,
    /// Wakeup signaling for the background worker.
    wake_flag: Mutex<bool>,
    wake: Condvar,
}

impl ManagedInner {
    fn signal(&self) {
        let mut g = self.wake_flag.lock().unwrap();
        *g = true;
        self.wake.notify_one();
    }

    /// Whether the resident window is over a size threshold.
    fn over_threshold(&self) -> bool {
        let (n, bytes) = self.chain.resident_stats();
        let over_n = self.policy.max_entries.is_some_and(|m| n > m);
        let over_b = self.policy.max_bytes.is_some_and(|m| bytes > m);
        over_n || over_b
    }

    /// Run one flush-then-prune cycle. Flushes the batch
    /// `[last_flushed, len - keep)` through the sink, then prunes it. Returns
    /// the number of entries evicted (0 if nothing was due). `final_drain`
    /// ignores `min_retained` so a shutdown flush empties the buffer.
    fn run_flush_cycle(&self, final_drain: bool) -> Result<u64> {
        // One flush at a time: prevents a worker cycle and a manual flush from
        // both writing the same batch (which would duplicate on-disk entries).
        let _guard = self.flush_guard.lock().unwrap();

        let head = self.chain.len();
        let last = *self.last_flushed.lock().unwrap();
        let keep = if final_drain { 0 } else { self.policy.min_retained };
        let flush_target = head.saturating_sub(keep).max(last);
        if flush_target <= last {
            return Ok(0);
        }

        let batch = self.chain.entries_since(last)?;
        let take = ((flush_target - last) as usize).min(batch.len());
        if take == 0 {
            return Ok(0);
        }
        let segment = &batch[..take];

        match self.sink.append_segment(segment) {
            Ok(()) => {
                self.chain.prune_before(flush_target);
                *self.last_flushed.lock().unwrap() = flush_target;
                let mut c = self.counters.lock().unwrap();
                c.entries_evicted += take as u64;
                c.sink_healthy = true;
                c.last_flush_index = flush_target;
                Ok(take as u64)
            }
            Err(e) => {
                let mut c = self.counters.lock().unwrap();
                c.sink_failures += 1;
                c.sink_healthy = false;
                Err(e)
            }
        }
    }

    fn run_worker(self: Arc<Self>) {
        // Poll at the flush interval, or a short default so threshold signals
        // are serviced promptly even if a wakeup is missed.
        let poll = self
            .policy
            .flush_interval
            .unwrap_or(Duration::from_millis(200));
        while !self.stop.load(Ordering::SeqCst) {
            {
                let g = self.wake_flag.lock().unwrap();
                let (mut g, _timeout) = self.wake.wait_timeout(g, poll).unwrap();
                *g = false;
            }
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            // Failures are recorded in counters; nothing to do here on Err.
            let _ = self.run_flush_cycle(false);
        }
        // Best-effort final drain on shutdown.
        let _ = self.run_flush_cycle(true);
    }
}

/// A [`SignedAuditChain`] that keeps resident memory bounded by durably
/// evicting old entries through an [`AuditSink`] under a [`RetentionPolicy`].
///
/// Construct it, append as usual, and a background worker moves old entries to
/// the sink and prunes them from memory. Drop it to stop the worker (it joins
/// on drop after a final drain).
pub struct ManagedAuditChain {
    inner: Arc<ManagedInner>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl ManagedAuditChain {
    /// Build a managed chain over a fresh [`SignedAuditChain`] backed by
    /// `signer`, evicting through `sink` under `policy`.
    pub fn new(signer: Signer, sink: Arc<dyn AuditSink>, policy: RetentionPolicy) -> Self {
        let inner = Arc::new(ManagedInner {
            chain: SignedAuditChain::new(signer),
            sink,
            policy,
            last_flushed: Mutex::new(0),
            flush_guard: Mutex::new(()),
            counters: Mutex::new(Counters {
                entries_evicted: 0,
                sink_failures: 0,
                sink_healthy: true,
                last_flush_index: 0,
            }),
            stop: AtomicBool::new(false),
            wake_flag: Mutex::new(false),
            wake: Condvar::new(),
        });

        let worker = if inner.policy.has_trigger() {
            let w = Arc::clone(&inner);
            Some(std::thread::spawn(move || w.run_worker()))
        } else {
            None
        };

        Self {
            inner,
            worker: Mutex::new(worker),
        }
    }

    /// Convenience: a managed chain writing to a JSONL file at `path`.
    pub fn with_file_sink(
        signer: Signer,
        path: impl AsRef<Path>,
        policy: RetentionPolicy,
    ) -> Self {
        Self::new(signer, Arc::new(FileAuditSink::new(path)), policy)
    }

    /// Append an entry. Enforces the configured backpressure before accepting
    /// it, so an accepted entry is always either in memory or (after a flush
    /// cycle) durably on the sink, never lost.
    pub fn append(&self, entry: &AuditEntry) -> Result<SignedAuditEntry> {
        match &self.inner.policy.on_sink_failure {
            SinkFailurePolicy::Buffer { buffer_ceiling } => {
                if self.inner.chain.resident_entries() >= *buffer_ceiling {
                    return Err(PqError::Serialization(format!(
                        "audit buffer ceiling {buffer_ceiling} reached (sink not draining); append rejected"
                    )));
                }
            }
            SinkFailurePolicy::RejectAppends => {
                let unhealthy = !self.inner.counters.lock().unwrap().sink_healthy;
                if unhealthy && self.inner.over_threshold() {
                    return Err(PqError::Serialization(
                        "audit sink unavailable and buffer over threshold; append rejected (backpressure)"
                            .into(),
                    ));
                }
            }
        }

        let signed = self.inner.chain.append(entry)?;
        if self.inner.over_threshold() {
            self.inner.signal();
        }
        Ok(signed)
    }

    /// Force one flush-then-prune cycle synchronously and return the number of
    /// entries evicted. Useful for deterministic control and shutdown.
    pub fn flush(&self) -> Result<u64> {
        self.inner.run_flush_cycle(false)
    }

    /// Flush everything down to zero retained entries (ignores `min_retained`).
    pub fn drain(&self) -> Result<u64> {
        self.inner.run_flush_cycle(true)
    }

    /// A snapshot of the chain's counters.
    pub fn stats(&self) -> ManagedStats {
        let (resident_entries, resident_bytes) = self.inner.chain.resident_stats();
        let c = self.inner.counters.lock().unwrap();
        ManagedStats {
            entries_appended: self.inner.chain.len(),
            entries_evicted: c.entries_evicted,
            resident_entries,
            resident_bytes,
            sink_failures: c.sink_failures,
            sink_healthy: c.sink_healthy,
            last_flush_index: c.last_flush_index,
        }
    }

    /// Borrow the underlying chain for read/verify/primitive access.
    pub fn chain(&self) -> &SignedAuditChain {
        &self.inner.chain
    }

    // ─── Delegated read surface ──────────────────────────────────

    /// Total entries ever appended.
    pub fn len(&self) -> u64 {
        self.inner.chain.len()
    }

    /// Whether nothing has been appended yet.
    pub fn is_empty(&self) -> bool {
        self.inner.chain.is_empty()
    }

    /// Head hash of the full logical chain.
    pub fn head_hash(&self) -> String {
        self.inner.chain.head_hash()
    }

    /// Logical index of the oldest entry still in memory.
    pub fn base_index(&self) -> u64 {
        self.inner.chain.base_index()
    }

    /// Entries currently held in memory (`len - base_index`).
    pub fn resident_entries(&self) -> u64 {
        self.inner.chain.resident_entries()
    }

    /// Estimated heap bytes held by the in-memory window.
    pub fn resident_bytes(&self) -> u64 {
        self.inner.chain.resident_bytes()
    }

    /// The anchor hash the in-memory tail chains from.
    pub fn anchor_hash(&self) -> String {
        self.inner.chain.anchor_hash()
    }

    /// The in-memory tail as JSONL (concatenate after the on-disk file to
    /// verify the full chain).
    pub fn export_tail_jsonl(&self) -> Result<Vec<u8>> {
        self.inner.chain.export_jsonl()
    }
}

impl Drop for ManagedAuditChain {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        self.inner.signal();
        if let Some(h) = self.worker.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}
