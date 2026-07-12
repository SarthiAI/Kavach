//! PQ-signed audit chain.
//!
//! Each audit entry is signed and linked to the previous entry via
//! a hash chain. This means:
//! - No entry can be modified after signing (signature breaks)
//! - No entry can be deleted without breaking the chain
//! - No entry can be inserted out of order (hash chain breaks)
//! - No entry can be mixed across modes, the chain is either pure
//!   PQ-only (ML-DSA-65) or pure hybrid (ML-DSA-65 + Ed25519), never
//!   both. Verification enforces this, closing the downgrade surface
//!   where a caller might otherwise verify a hybrid chain with a
//!   PQ-only verifier and silently ignore the Ed25519 signatures.
//!
//! This gives you a tamper-evident audit log that survives even if
//! the log storage is compromised.
//!
//! ## Bounded memory
//!
//! By default the chain retains every entry it has appended. A process that
//! appends at a steady rate would grow resident memory without bound. Two
//! additive tools keep memory flat:
//!
//! - **The prune primitive** ([`SignedAuditChain::prune_before`] +
//!   [`SignedAuditChain::entries_since`] + [`SignedAuditChain::anchor_hash`]).
//!   After you durably persist entries `[0, k)`, call `prune_before(k)` to drop
//!   them from memory. The hash chain is preserved: entry `k` still chains from
//!   `hash(entry k-1)`, so concatenating the persisted prefix with the
//!   in-memory tail reproduces one continuous chain that verifies from genesis.
//! - **The managed chain** ([`crate::audit_sink::ManagedAuditChain`]) runs the
//!   flush-then-prune cycle for you under a configurable
//!   [`RetentionPolicy`](crate::audit_sink::RetentionPolicy) (by entry count, by
//!   bytes, on a timer, or any combination).
//!
//! Verifying a segment that starts mid-chain (the in-memory tail, or one of
//! several on-disk files) uses [`verify_chain_from`] / [`verify_segments`].

use crate::error::{PqError, Result};
use crate::sign::{SignedPayload, Signer, Verifier};
use kavach_core::audit::AuditEntry;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;

/// The cryptographic mode a chain was signed under.
///
/// Inferred per-entry from whether the signed payload carries an Ed25519
/// signature. A chain must be uniformly one mode, mixing is a chain break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainMode {
    /// ML-DSA-65 only.
    PqOnly,
    /// ML-DSA-65 + Ed25519.
    Hybrid,
}

impl ChainMode {
    /// Matches the `bool hybrid` flag used throughout the SDK surface.
    pub fn is_hybrid(self) -> bool {
        matches!(self, ChainMode::Hybrid)
    }

    /// Convenience constructor mirroring the SDK `hybrid: bool` surface.
    pub fn from_hybrid(hybrid: bool) -> Self {
        if hybrid {
            ChainMode::Hybrid
        } else {
            ChainMode::PqOnly
        }
    }
}

impl std::fmt::Display for ChainMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainMode::PqOnly => f.write_str("pq-only"),
            ChainMode::Hybrid => f.write_str("hybrid"),
        }
    }
}

/// A single entry in the signed audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuditEntry {
    /// Index in the chain (0-based).
    pub index: u64,

    /// Hash of the previous entry (empty for the genesis entry).
    pub previous_hash: String,

    /// The signed audit data.
    pub signed_payload: SignedPayload,

    /// Hash of this entry (covers index + previous_hash + signed_payload).
    pub entry_hash: String,
}

impl SignedAuditEntry {
    /// The cryptographic mode this entry was signed under.
    pub fn mode(&self) -> ChainMode {
        if self.signed_payload.ed25519_signature.is_some() {
            ChainMode::Hybrid
        } else {
            ChainMode::PqOnly
        }
    }
}

/// Internal mutable state, guarded by a single mutex so `append` and
/// `prune_before` are atomic with respect to each other. Signing happens
/// *before* the lock is taken, so the lock is held only for the O(1)
/// index/hash/push update.
struct ChainState {
    /// Retained entries, logical range `[base_index, current_index)`.
    /// A `VecDeque` so eviction from the front is O(1) amortized.
    entries: VecDeque<SignedAuditEntry>,
    /// Head hash: the `entry_hash` of the most recent entry (or `"genesis"`).
    current_hash: String,
    /// Total number of entries ever appended. Strictly monotonic.
    current_index: u64,
    /// Logical index of `entries.front()`. Advances as eviction drops the front.
    base_index: u64,
    /// Running estimate of the heap bytes held by the retained window.
    resident_bytes: u64,
}

/// A tamper-evident audit chain with PQ signatures.
///
/// Retains every entry by default. For sustained, high-volume workloads,
/// persist the oldest entries and call [`prune_before`](Self::prune_before), or
/// wrap this in a [`ManagedAuditChain`](crate::audit_sink::ManagedAuditChain)
/// which does the flush-then-prune cycle for you.
pub struct SignedAuditChain {
    signer: Signer,
    mode: ChainMode,
    state: Mutex<ChainState>,
}

impl SignedAuditChain {
    /// Create a new empty chain. The chain's mode is fixed by the signer,
    /// swapping signers mid-chain would break verification.
    pub fn new(signer: Signer) -> Self {
        let mode = ChainMode::from_hybrid(signer.is_hybrid());
        Self {
            signer,
            mode,
            state: Mutex::new(ChainState {
                entries: VecDeque::new(),
                current_hash: "genesis".to_string(),
                current_index: 0,
                base_index: 0,
                resident_bytes: 0,
            }),
        }
    }

    /// Append an audit entry to the chain.
    ///
    /// The entry is:
    /// 1. Serialized
    /// 2. Signed with ML-DSA (+ Ed25519 in hybrid mode)
    /// 3. Linked to the previous entry via hash chain
    pub fn append(&self, entry: &AuditEntry) -> Result<SignedAuditEntry> {
        let data = serde_json::to_vec(entry).map_err(|e| PqError::Serialization(e.to_string()))?;

        // Sign outside the lock: signing is the expensive part and needs no
        // shared state. Order between concurrent appends is fixed by which
        // thread acquires the state lock first.
        let signed_payload = self.signer.sign(&data)?;

        let mut st = self.state.lock().unwrap();
        let index = st.current_index;
        let previous_hash = st.current_hash.clone();

        // Compute this entry's hash: H(index || previous_hash || signed_data)
        let entry_hash = compute_chain_hash(index, &previous_hash, &signed_payload);

        let signed_entry = SignedAuditEntry {
            index,
            previous_hash,
            signed_payload,
            entry_hash: entry_hash.clone(),
        };

        // Update chain state.
        st.current_hash = entry_hash;
        st.current_index = index + 1;
        st.resident_bytes = st
            .resident_bytes
            .saturating_add(estimated_entry_size(&signed_entry));
        st.entries.push_back(signed_entry.clone());

        Ok(signed_entry)
    }

    /// Total number of entries ever appended (unaffected by pruning).
    pub fn len(&self) -> u64 {
        self.state.lock().unwrap().current_index
    }

    /// Whether the chain has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The cryptographic mode this chain was built under.
    pub fn mode(&self) -> ChainMode {
        self.mode
    }

    /// All entries currently retained in memory (the window
    /// `[base_index, len)`), cloned.
    ///
    /// For a chain that has never been pruned this is the whole chain,
    /// identical to previous behavior. After pruning it is the unevicted tail
    /// only; use [`entries_since`](Self::entries_since) when you need to reason
    /// about logical indices.
    pub fn entries(&self) -> Vec<SignedAuditEntry> {
        self.state.lock().unwrap().entries.iter().cloned().collect()
    }

    /// Get the latest chain hash (for verification anchoring).
    pub fn head_hash(&self) -> String {
        self.state.lock().unwrap().current_hash.clone()
    }

    /// Logical index of the oldest entry still held in memory. 0 until the
    /// first prune; equal to [`len`](Self::len) once everything is evicted.
    pub fn base_index(&self) -> u64 {
        self.state.lock().unwrap().base_index
    }

    /// Number of entries currently held in memory (`len - base_index`).
    pub fn resident_entries(&self) -> u64 {
        let st = self.state.lock().unwrap();
        st.current_index - st.base_index
    }

    /// Estimated heap bytes held by the retained window (approximate; drives
    /// the `max_bytes` retention trigger).
    pub fn resident_bytes(&self) -> u64 {
        self.state.lock().unwrap().resident_bytes
    }

    /// `(resident_entries, resident_bytes)` read together under one lock.
    pub fn resident_stats(&self) -> (u64, u64) {
        let st = self.state.lock().unwrap();
        (st.current_index - st.base_index, st.resident_bytes)
    }

    /// The `previous_hash` the oldest retained entry chains from: the anchor
    /// needed to verify the in-memory tail (or any segment starting here) in
    /// isolation via [`verify_chain_from`]. `"genesis"` when nothing has been
    /// evicted; `hash(entry base_index - 1)` after eviction.
    pub fn anchor_hash(&self) -> String {
        let st = self.state.lock().unwrap();
        match st.entries.front() {
            Some(e) => e.previous_hash.clone(),
            None => st.current_hash.clone(),
        }
    }

    /// Entries with logical index `>= from` that are still in memory.
    ///
    /// Returns `Err` if `from < base_index` (the requested entries have already
    /// been evicted) so a persist/prune bug surfaces loudly instead of silently
    /// returning a partial tail. `from >= len` yields an empty vec.
    pub fn entries_since(&self, from: u64) -> Result<Vec<SignedAuditEntry>> {
        let st = self.state.lock().unwrap();
        if from < st.base_index {
            return Err(PqError::AuditChainBroken {
                index: from,
                reason: format!(
                    "entries_since({from}) requested an evicted index; base_index is {}",
                    st.base_index
                ),
            });
        }
        let offset = (from - st.base_index) as usize;
        Ok(st.entries.iter().skip(offset).cloned().collect())
    }

    /// Drop in-memory entries with logical index `< before`.
    ///
    /// Does not touch the head hash or total length, so appending continues the
    /// same hash chain: entry `before` still carries
    /// `previous_hash = hash(entry before-1)`. No-op returning 0 if
    /// `before <= base_index`; clamped to [`len`](Self::len). Returns the number
    /// of entries dropped.
    ///
    /// **Contract:** the caller MUST have durably persisted every entry with
    /// index `< before` first. Pruning is the caller's explicit statement that
    /// those entries are safe elsewhere; there is no way to recover them from
    /// the chain afterwards.
    pub fn prune_before(&self, before: u64) -> u64 {
        let mut st = self.state.lock().unwrap();
        let target = before.min(st.current_index);
        if target <= st.base_index {
            return 0;
        }
        let drop_count = (target - st.base_index) as usize;
        let mut dropped = 0u64;
        for _ in 0..drop_count {
            match st.entries.pop_front() {
                Some(e) => {
                    let sz = estimated_entry_size(&e);
                    st.resident_bytes = st.resident_bytes.saturating_sub(sz);
                    dropped += 1;
                }
                None => break,
            }
        }
        st.base_index += dropped;
        dropped
    }

    /// Export the retained window as newline-delimited JSON (`.jsonl`). One
    /// [`SignedAuditEntry`] per line, trailing newline included.
    pub fn export_jsonl(&self) -> Result<Vec<u8>> {
        export_jsonl(&self.entries())
    }
}

/// Cheap O(1) estimate of the heap footprint of one retained entry. Used for
/// the `max_bytes` retention trigger; approximate, not exact allocator
/// accounting.
fn estimated_entry_size(entry: &SignedAuditEntry) -> u64 {
    let p = &entry.signed_payload;
    let ed = p.ed25519_signature.as_ref().map_or(0, |s| s.len());
    (entry.previous_hash.len()
        + entry.entry_hash.len()
        + p.data.len()
        + p.ml_dsa_signature.len()
        + ed
        + p.key_id.len()
        + p.nonce.len()
        + 96) as u64
}

/// Inspect a sequence of entries and return the chain's mode.
///
/// - Empty slice returns `Ok(None)`, nothing to infer.
/// - All entries must agree on mode; any mix returns an
///   [`PqError::AuditChainBroken`] naming the first inconsistent index.
pub fn detect_mode(entries: &[SignedAuditEntry]) -> Result<Option<ChainMode>> {
    let mut mode: Option<ChainMode> = None;
    for entry in entries {
        let entry_mode = entry.mode();
        match mode {
            None => mode = Some(entry_mode),
            Some(m) if m != entry_mode => {
                return Err(PqError::AuditChainBroken {
                    index: entry.index,
                    reason: format!(
                        "chain mode inconsistent: started as {m}, entry is {entry_mode} (possible splice)"
                    ),
                });
            }
            Some(_) => {}
        }
    }
    Ok(mode)
}

/// Verify the integrity of a full audit chain that starts at the genesis
/// anchor (logical index 0).
///
/// Checks:
/// 1. The chain starts at index 0.
/// 2. Chain mode is consistent across entries (no hybrid/PQ-only splice).
/// 3. Verifier mode matches the chain mode (no downgrade attack).
/// 4. Every signature is valid.
/// 5. Every hash chain link is correct.
/// 6. Indices are sequential, no gaps or duplicates.
///
/// Equivalent to [`verify_chain_from`] with `expected_previous_hash =
/// "genesis"`, plus the first-index-0 assertion. Use [`verify_chain_from`] /
/// [`verify_segments`] to verify a segment that begins mid-chain (for example
/// the in-memory tail of a pruned chain).
pub fn verify_chain(entries: &[SignedAuditEntry], verifier: &Verifier) -> Result<()> {
    if let Some(first) = entries.first() {
        if first.index != 0 {
            return Err(PqError::AuditChainBroken {
                index: 0,
                reason: format!(
                    "full-chain verification expects the chain to start at index 0, got {}",
                    first.index
                ),
            });
        }
    }
    verify_chain_from(entries, verifier, "genesis")
}

/// Verify a contiguous chain segment whose first entry is expected to chain
/// from `expected_previous_hash`.
///
/// `"genesis"` for the head segment; the previous segment's last `entry_hash`
/// for any later segment; [`SignedAuditChain::anchor_hash`] for the in-memory
/// tail of a pruned chain. Unlike [`verify_chain`], the first entry may carry
/// any logical index (it need not be 0); indices must then increase by exactly
/// one across the segment. All other checks are identical: mode consistency,
/// verifier/chain mode parity, every signature, every hash link.
pub fn verify_chain_from(
    entries: &[SignedAuditEntry],
    verifier: &Verifier,
    expected_previous_hash: &str,
) -> Result<()> {
    // Determine chain mode and enforce verifier parity before any crypto work.
    let chain_mode = detect_mode(entries)?;
    let verifier_mode = ChainMode::from_hybrid(verifier.is_hybrid());
    if let Some(cm) = chain_mode {
        if cm != verifier_mode {
            return Err(PqError::AuditChainBroken {
                index: entries.first().map(|e| e.index).unwrap_or(0),
                reason: format!(
                    "verifier/chain mode mismatch: chain is {cm}, verifier is {verifier_mode}"
                ),
            });
        }
    }

    let mut expected_hash = expected_previous_hash.to_string();
    let mut expected_index: Option<u64> = None;

    for entry in entries {
        // Indices must be contiguous. The first entry sets the starting index.
        let want_index = expected_index.unwrap_or(entry.index);
        if entry.index != want_index {
            return Err(PqError::AuditChainBroken {
                index: want_index,
                reason: format!("expected index {want_index}, got {}", entry.index),
            });
        }

        // Check hash chain link.
        if entry.previous_hash != expected_hash {
            return Err(PqError::AuditChainBroken {
                index: entry.index,
                reason: format!(
                    "hash chain broken: expected '{}', got '{}'",
                    expected_hash, entry.previous_hash
                ),
            });
        }

        // Verify cryptographic signature.
        verifier
            .verify(&entry.signed_payload)
            .map_err(|e| PqError::AuditChainBroken {
                index: entry.index,
                reason: format!("signature verification failed: {}", e),
            })?;

        // Verify entry hash.
        let computed_hash =
            compute_chain_hash(entry.index, &entry.previous_hash, &entry.signed_payload);
        if computed_hash != entry.entry_hash {
            return Err(PqError::AuditChainBroken {
                index: entry.index,
                reason: "entry hash mismatch".into(),
            });
        }

        expected_hash = entry.entry_hash.clone();
        expected_index = Some(entry.index + 1);
    }

    Ok(())
}

/// Verify a chain that has been split into ordered segments (for example
/// several on-disk JSONL files followed by the in-memory tail), stitching them
/// into one logical chain.
///
/// The first non-empty segment is anchored at `"genesis"` and must start at
/// index 0; each subsequent segment must start exactly one index past the
/// previous segment's last entry and chain from its `entry_hash`. Reports the
/// first break, whether inside a segment or at a boundary (gap, overlap, or
/// hash mismatch). Empty segments are skipped.
pub fn verify_segments(segments: &[&[SignedAuditEntry]], verifier: &Verifier) -> Result<()> {
    let mut expected_prev = "genesis".to_string();
    let mut expected_index = 0u64;

    for seg in segments {
        if seg.is_empty() {
            continue;
        }
        if seg[0].index != expected_index {
            return Err(PqError::AuditChainBroken {
                index: expected_index,
                reason: format!(
                    "segment boundary mismatch: expected next index {expected_index}, segment starts at {}",
                    seg[0].index
                ),
            });
        }
        verify_chain_from(seg, verifier, &expected_prev)?;
        let last = seg.last().unwrap();
        expected_prev = last.entry_hash.clone();
        expected_index = last.index + 1;
    }

    Ok(())
}

/// Serialize a slice of entries as newline-delimited JSON.
/// One [`SignedAuditEntry`] per line; a trailing newline is included.
pub fn export_jsonl(entries: &[SignedAuditEntry]) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(entries.len() * 256);
    for e in entries {
        let line = serde_json::to_string(e)
            .map_err(|err| PqError::Serialization(format!("export: {err}")))?;
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
    }
    Ok(buf)
}

/// Parse newline-delimited JSON into a vector of [`SignedAuditEntry`].
///
/// Blank lines are skipped. Parse errors report the 0-based entry index
/// (count of successfully parsed entries *before* the failure), which is
/// what verifiers care about, not the raw line number.
pub fn parse_jsonl(data: &[u8]) -> Result<Vec<SignedAuditEntry>> {
    let mut entries: Vec<SignedAuditEntry> = Vec::new();
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() || line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let entry: SignedAuditEntry = serde_json::from_slice(line).map_err(|e| {
            PqError::Serialization(format!("parse failed at entry #{}: {e}", entries.len()))
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Compute the SHA-256 hash for a chain entry.
///
/// Binds together the index, previous-entry hash, and the full signed payload
/// (data + ML-DSA signature + Ed25519 signature if present). Any mutation,
/// reordering, insertion, deletion, or tampering, breaks the chain.
fn compute_chain_hash(index: u64, previous_hash: &str, payload: &SignedPayload) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(index.to_le_bytes());
    hasher.update(previous_hash.as_bytes());
    hasher.update(&payload.data);
    hasher.update(&payload.ml_dsa_signature);
    if let Some(ed_sig) = &payload.ed25519_signature {
        hasher.update(ed_sig);
    }
    hasher.update(payload.nonce.as_bytes());
    hasher.update(payload.signed_at.to_rfc3339().as_bytes());
    hex::encode(hasher.finalize())
}
