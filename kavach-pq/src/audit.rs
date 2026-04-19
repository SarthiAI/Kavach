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

use crate::error::{PqError, Result};
use crate::sign::{SignedPayload, Signer, Verifier};
use kavach_core::audit::AuditEntry;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

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

/// A tamper-evident audit chain with PQ signatures.
pub struct SignedAuditChain {
    signer: Signer,
    mode: ChainMode,
    entries: RwLock<Vec<SignedAuditEntry>>,
    current_hash: RwLock<String>,
    current_index: RwLock<u64>,
}

impl SignedAuditChain {
    /// Create a new empty chain. The chain's mode is fixed by the signer,
    /// swapping signers mid-chain would break verification.
    pub fn new(signer: Signer) -> Self {
        let mode = ChainMode::from_hybrid(signer.is_hybrid());
        Self {
            signer,
            mode,
            entries: RwLock::new(Vec::new()),
            current_hash: RwLock::new("genesis".to_string()),
            current_index: RwLock::new(0),
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

        let signed_payload = self.signer.sign(&data)?;

        let mut index = self.current_index.write().unwrap();
        let previous_hash = self.current_hash.read().unwrap().clone();

        // Compute this entry's hash: H(index || previous_hash || signed_data)
        let entry_hash = compute_chain_hash(*index, &previous_hash, &signed_payload);

        let signed_entry = SignedAuditEntry {
            index: *index,
            previous_hash,
            signed_payload,
            entry_hash: entry_hash.clone(),
        };

        // Update chain state
        *self.current_hash.write().unwrap() = entry_hash;
        *index += 1;

        // Store
        self.entries.write().unwrap().push(signed_entry.clone());

        Ok(signed_entry)
    }

    /// Get the current chain length.
    pub fn len(&self) -> u64 {
        *self.current_index.read().unwrap()
    }

    /// Whether the chain has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The cryptographic mode this chain was built under.
    pub fn mode(&self) -> ChainMode {
        self.mode
    }

    /// Get all entries for export.
    pub fn entries(&self) -> Vec<SignedAuditEntry> {
        self.entries.read().unwrap().clone()
    }

    /// Get the latest chain hash (for verification anchoring).
    pub fn head_hash(&self) -> String {
        self.current_hash.read().unwrap().clone()
    }

    /// Export this chain as newline-delimited JSON (`.jsonl`). One
    /// [`SignedAuditEntry`] per line, trailing newline included.
    pub fn export_jsonl(&self) -> Result<Vec<u8>> {
        export_jsonl(&self.entries())
    }
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

/// Verify the integrity of an audit chain.
///
/// Checks:
/// 1. Chain mode is consistent across entries (no hybrid/PQ-only splice)
/// 2. Verifier mode matches the chain mode (no downgrade attack:
///    a PQ-only verifier cannot silently accept a hybrid chain, and
///    a hybrid verifier cannot accept a PQ-only chain)
/// 3. Every signature is valid
/// 4. Every hash chain link is correct
/// 5. Indices are sequential, no gaps or duplicates
pub fn verify_chain(entries: &[SignedAuditEntry], verifier: &Verifier) -> Result<()> {
    // Determine chain mode and enforce verifier parity before any crypto work.
    let chain_mode = detect_mode(entries)?;
    let verifier_mode = ChainMode::from_hybrid(verifier.is_hybrid());
    if let Some(cm) = chain_mode {
        if cm != verifier_mode {
            return Err(PqError::AuditChainBroken {
                index: 0,
                reason: format!(
                    "verifier/chain mode mismatch: chain is {cm}, verifier is {verifier_mode}"
                ),
            });
        }
    }

    let mut expected_hash = "genesis".to_string();

    for (i, entry) in entries.iter().enumerate() {
        // Check index
        if entry.index != i as u64 {
            return Err(PqError::AuditChainBroken {
                index: i as u64,
                reason: format!("expected index {}, got {}", i, entry.index),
            });
        }

        // Check hash chain
        if entry.previous_hash != expected_hash {
            return Err(PqError::AuditChainBroken {
                index: entry.index,
                reason: format!(
                    "hash chain broken: expected '{}', got '{}'",
                    expected_hash, entry.previous_hash
                ),
            });
        }

        // Verify cryptographic signature
        verifier
            .verify(&entry.signed_payload)
            .map_err(|e| PqError::AuditChainBroken {
                index: entry.index,
                reason: format!("signature verification failed: {}", e),
            })?;

        // Verify entry hash
        let computed_hash =
            compute_chain_hash(entry.index, &entry.previous_hash, &entry.signed_payload);
        if computed_hash != entry.entry_hash {
            return Err(PqError::AuditChainBroken {
                index: entry.index,
                reason: "entry hash mismatch".into(),
            });
        }

        expected_hash = entry.entry_hash.clone();
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
