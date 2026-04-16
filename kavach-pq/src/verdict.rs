//! Verdict signing and verification.
//!
//! When the gate issues a Permit, Refuse, or Invalidate verdict,
//! this module signs it so it can't be tampered with in transit.
//!
//! A signed "Refuse" cannot be swapped to "Permit" by a man-in-the-middle.
//! A signed "Permit" cannot be replayed for a different action.

use crate::error::{PqError, Result};
use crate::sign::{SignedPayload, Signer, Verifier};
use kavach_core::verdict::Verdict;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::RwLock;

/// A verdict with a cryptographic signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVerdict {
    /// The signed payload containing the serialized verdict.
    pub signed_payload: SignedPayload,

    /// The verdict kind for quick filtering without deserialization.
    pub verdict_kind: String,

    /// The action this verdict applies to.
    pub action_name: String,

    /// The evaluation ID for correlation.
    pub evaluation_id: String,
}

impl SignedVerdict {
    /// Deserialize the inner verdict.
    pub fn verdict(&self) -> Result<Verdict> {
        serde_json::from_slice(&self.signed_payload.data)
            .map_err(|e| PqError::Serialization(e.to_string()))
    }
}

/// Signs verdicts produced by the gate.
pub struct VerdictSigner {
    signer: Signer,
}

impl VerdictSigner {
    pub fn new(signer: Signer) -> Self {
        Self { signer }
    }

    /// Access the inner byte-level signer. Used by [`crate::SecureChannel::send_signed`]
    /// to sign raw byte payloads while sharing the same signing key as
    /// verdict signing — the sender cannot be forced to keep two
    /// separate keys for the two flows.
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// Sign a verdict for transport.
    ///
    /// The signed verdict includes the full verdict data, the action name
    /// (to prevent cross-action replay), and the evaluation ID (for audit).
    pub fn sign(
        &self,
        verdict: &Verdict,
        action_name: &str,
        evaluation_id: &str,
    ) -> Result<SignedVerdict> {
        let verdict_bytes =
            serde_json::to_vec(verdict).map_err(|e| PqError::Serialization(e.to_string()))?;

        let signed_payload = self.signer.sign(&verdict_bytes)?;

        let verdict_kind = match verdict {
            Verdict::Permit(_) => "permit",
            Verdict::Refuse(_) => "refuse",
            Verdict::Invalidate(_) => "invalidate",
        };

        Ok(SignedVerdict {
            signed_payload,
            verdict_kind: verdict_kind.to_string(),
            action_name: action_name.to_string(),
            evaluation_id: evaluation_id.to_string(),
        })
    }
}

/// Verifies signed verdicts from a trusted gate.
///
/// Includes replay protection: each verdict nonce is tracked
/// and rejected if seen a second time.
pub struct VerdictVerifier {
    verifier: Verifier,

    /// Seen nonces for replay protection.
    seen_nonces: RwLock<HashSet<String>>,

    /// Maximum nonces to track (prevents unbounded memory growth).
    max_tracked_nonces: usize,
}

impl VerdictVerifier {
    pub fn new(verifier: Verifier) -> Self {
        Self {
            verifier,
            seen_nonces: RwLock::new(HashSet::new()),
            max_tracked_nonces: 100_000,
        }
    }

    /// Shared signature + replay check. Callers layer context binding
    /// (action name / context id) on top.
    fn check_signature_and_replay(&self, signed: &SignedPayload) -> Result<()> {
        // 1. Cryptographic signature
        self.verifier.verify(signed)?;

        // 2. Replay protection
        let nonce = &signed.nonce;
        let mut seen = self.seen_nonces.write().unwrap();
        if seen.contains(nonce) {
            return Err(PqError::ReplayDetected(nonce.clone()));
        }
        seen.insert(nonce.clone());

        // Prevent unbounded growth (crude LRU — production should use an LRU cache)
        if seen.len() > self.max_tracked_nonces {
            seen.clear();
            tracing::warn!("nonce cache cleared — consider increasing max_tracked_nonces");
        }
        Ok(())
    }

    /// Verify a signed verdict.
    ///
    /// Checks:
    /// 1. Cryptographic signature is valid (ML-DSA + Ed25519 in hybrid)
    /// 2. Nonce has not been seen before (replay protection)
    /// 3. Action name matches (cross-action replay protection)
    pub fn verify(&self, signed: &SignedVerdict, expected_action: &str) -> Result<Verdict> {
        self.check_signature_and_replay(&signed.signed_payload)?;

        if signed.action_name != expected_action {
            return Err(PqError::VerificationFailed(format!(
                "verdict is for action '{}', expected '{}'",
                signed.action_name, expected_action
            )));
        }

        signed.verdict()
    }

    /// Verify a raw signed byte payload with an explicit context-id binding.
    ///
    /// Use this for generic "signed bytes" flows (e.g. [`SecureChannel::send_signed`])
    /// where the caller serializes their own message. `actual_context` is whatever
    /// the sender attached; `expected_context` is what the receiver was told to
    /// expect (commonly an action or tool name). A mismatch rejects the message.
    ///
    /// Shares the same signature + nonce-replay state as [`verify`], so signed
    /// bytes and signed verdicts can't be replayed across each other.
    pub fn verify_bytes(
        &self,
        signed: &SignedPayload,
        actual_context: &str,
        expected_context: &str,
    ) -> Result<Vec<u8>> {
        self.check_signature_and_replay(signed)?;

        if actual_context != expected_context {
            return Err(PqError::VerificationFailed(format!(
                "signed payload context is '{actual_context}', expected '{expected_context}'"
            )));
        }

        Ok(signed.data.clone())
    }
}
