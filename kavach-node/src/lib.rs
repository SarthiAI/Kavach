//! # Kavach Node.js Bindings
//!
//! napi-rs bridge that exposes kavach-core's Rust engine to Node.js/TypeScript.
//! All evaluation logic runs in Rust — JS calls across the native addon boundary.
//!
//! The compiled addon is loaded by the `kavach` npm package.

use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use kavach_core::{
    self as core, audit::AuditEntry as CoreAuditEntry, Evaluator, TokenSigner as CoreTokenSigner,
};
use kavach_pq::{
    audit::{self as pq_audit, SignedAuditChain as SignedAuditChainInner},
    directory::{
        FilePublicKeyDirectory as FilePublicKeyDirectoryInner,
        InMemoryPublicKeyDirectory as InMemoryPublicKeyDirectoryInner,
        PublicKeyDirectory as PublicKeyDirectoryTrait,
    },
    encrypt::EncryptedPayload,
    sign::{Signer as PqSigner, Verifier as PqVerifier},
    token::DirectoryTokenVerifier as DirectoryTokenVerifierInner,
    KavachKeyPair as KavachKeyPairInner, PqTokenSigner as PqTokenSignerInner,
    PublicKeyBundle as PublicKeyBundleInner, SecureChannel as SecureChannelInner,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;
use uuid::Uuid;

fn runtime() -> &'static Runtime {
    use std::sync::OnceLock;
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| Runtime::new().expect("failed to create tokio runtime"))
}

// ─── Types exposed to JavaScript ─────────────────────────────────

#[napi(object)]
pub struct VerdictResult {
    pub kind: String,
    pub evaluator: Option<String>,
    pub reason: Option<String>,
    pub code: Option<String>,
    pub token_id: Option<String>,
    pub is_permit: bool,
    pub is_refuse: bool,
    pub is_invalidate: bool,

    /// Full PermitToken (with optional signature) when verdict is Permit.
    /// `null` for Refuse / Invalidate.
    pub permit_token: Option<PermitTokenView>,

    /// Convenience: signature bytes (or null) — same as `permit_token.signature`.
    pub signature: Option<Buffer>,
}

/// JS-visible view of a PermitToken. Use the standalone `PermitToken` class
/// when you need to construct one from received-over-the-wire fields (for
/// verification on a downstream service).
#[napi(object)]
pub struct PermitTokenView {
    pub token_id: String,
    pub evaluation_id: String,
    /// Issued-at unix-epoch seconds.
    pub issued_at: i64,
    /// Expires-at unix-epoch seconds.
    pub expires_at: i64,
    pub action_name: String,
    pub signature: Option<Buffer>,
}

impl From<core::PermitToken> for PermitTokenView {
    fn from(t: core::PermitToken) -> Self {
        Self {
            token_id: t.token_id.to_string(),
            evaluation_id: t.evaluation_id.to_string(),
            issued_at: t.issued_at.timestamp(),
            expires_at: t.expires_at.timestamp(),
            action_name: t.action_name,
            signature: t.signature.map(Buffer::from),
        }
    }
}

impl From<core::Verdict> for VerdictResult {
    fn from(v: core::Verdict) -> Self {
        match v {
            core::Verdict::Permit(token) => {
                let sig = token.signature.clone().map(Buffer::from);
                let view = PermitTokenView::from(token.clone());
                VerdictResult {
                    kind: "permit".into(),
                    evaluator: None,
                    reason: None,
                    code: None,
                    token_id: Some(token.token_id.to_string()),
                    is_permit: true,
                    is_refuse: false,
                    is_invalidate: false,
                    permit_token: Some(view),
                    signature: sig,
                }
            }
            core::Verdict::Refuse(r) => VerdictResult {
                kind: "refuse".into(),
                evaluator: Some(r.evaluator),
                reason: Some(r.reason),
                code: Some(r.code.to_string()),
                token_id: None,
                is_permit: false,
                is_refuse: true,
                is_invalidate: false,
                permit_token: None,
                signature: None,
            },
            core::Verdict::Invalidate(s) => VerdictResult {
                kind: "invalidate".into(),
                evaluator: Some(s.evaluator),
                reason: Some(s.reason),
                code: None,
                token_id: None,
                is_permit: false,
                is_refuse: false,
                is_invalidate: true,
                permit_token: None,
                signature: None,
            },
        }
    }
}

#[napi(object)]
pub struct ActionContextInput {
    pub principal_id: String,
    pub principal_kind: String,
    pub action_name: String,
    pub roles: Option<Vec<String>>,
    pub resource: Option<String>,
    pub params: Option<HashMap<String, f64>>,
    pub ip: Option<String>,
    pub session_id: Option<String>,
    /// Current geographic location (→ `EnvContext.geo`). Set this plus
    /// `originGeo` and a tolerant-mode `GeoLocationDrift` evaluator to
    /// downgrade same-country IP hops from Violation to Warning.
    pub current_geo: Option<GeoLocationInput>,
    /// Geographic location captured at session start
    /// (→ `SessionState.origin_geo`). Needed alongside `currentGeo` for
    /// tolerant-mode `GeoLocationDrift`.
    pub origin_geo: Option<GeoLocationInput>,
}

/// Plain-object view of `kavach_core::GeoLocation`. `countryCode` is
/// required; `latitude` + `longitude` unlock Haversine distance (needed
/// for tolerant-mode drift). `region` / `city` are free-text annotations.
#[napi(object)]
pub struct GeoLocationInput {
    pub country_code: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

fn geo_input_to_core(g: GeoLocationInput) -> core::GeoLocation {
    core::GeoLocation {
        country_code: g.country_code,
        region: g.region,
        city: g.city,
        latitude: g.latitude,
        longitude: g.longitude,
    }
}

#[napi(object)]
pub struct InvariantInput {
    pub name: String,
    pub field: String,
    pub max_value: f64,
}

/// Fields needed to (re)construct a PermitToken on the verifier side.
/// Matches what `PermitToken` uses internally; pass this when calling
/// `signer.verifyToken(...)` from JS.
#[napi(object)]
pub struct PermitTokenInput {
    pub token_id: String,
    pub evaluation_id: String,
    /// Unix-epoch seconds.
    pub issued_at: i64,
    /// Unix-epoch seconds.
    pub expires_at: i64,
    pub action_name: String,
}

fn permit_token_from_input(input: &PermitTokenInput) -> Result<core::PermitToken> {
    let token_id = Uuid::parse_str(&input.token_id)
        .map_err(|e| Error::from_reason(format!("token_id not a UUID: {e}")))?;
    let evaluation_id = Uuid::parse_str(&input.evaluation_id)
        .map_err(|e| Error::from_reason(format!("evaluation_id not a UUID: {e}")))?;
    let issued_at = Utc
        .timestamp_opt(input.issued_at, 0)
        .single()
        .ok_or_else(|| Error::from_reason("issued_at out of range"))?;
    let expires_at = Utc
        .timestamp_opt(input.expires_at, 0)
        .single()
        .ok_or_else(|| Error::from_reason("expires_at out of range"))?;
    Ok(core::PermitToken {
        token_id,
        evaluation_id,
        issued_at,
        expires_at,
        action_name: input.action_name.clone(),
        signature: None,
    })
}

// ─── KavachKeyPair + PublicKeyBundle ─────────────────────────────

/// A Kavach keypair — ML-DSA-65 + ML-KEM-768 + Ed25519 + X25519.
///
/// Holds *both* signing/decapsulation/secret keys and their public counterparts.
/// Use `publicKeys()` to extract the safe-to-share `PublicKeyBundle` and
/// share *that* with verifiers — never the keypair itself.
#[napi]
pub struct KavachKeyPair {
    inner: Arc<KavachKeyPairInner>,
}

#[napi]
impl KavachKeyPair {
    /// Generate a fresh random keypair (no expiry).
    #[napi(factory)]
    pub fn generate() -> Result<Self> {
        let inner = KavachKeyPairInner::generate()
            .map_err(|e| Error::from_reason(format!("keypair generation: {e}")))?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Generate a fresh random keypair that expires after `seconds`.
    #[napi(factory, js_name = "generateWithExpiry")]
    pub fn generate_with_expiry(seconds: i64) -> Result<Self> {
        let inner =
            KavachKeyPairInner::generate_with_expiry(Some(ChronoDuration::seconds(seconds)))
                .map_err(|e| Error::from_reason(format!("keypair generation: {e}")))?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[napi(getter)]
    pub fn created_at(&self) -> i64 {
        self.inner.created_at.timestamp()
    }

    #[napi(getter)]
    pub fn expires_at(&self) -> Option<i64> {
        self.inner.expires_at.map(|d| d.timestamp())
    }

    /// True if this keypair has passed its expiry.
    #[napi(getter)]
    pub fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// The safe-to-share half — share this with verifiers / KEM senders.
    #[napi]
    pub fn public_keys(&self) -> PublicKeyBundleView {
        PublicKeyBundleView::from(self.inner.public_keys())
    }

    /// Sign a `PublicKeyDirectory` manifest with this keypair's ML-DSA-65
    /// seed, returning the JSON bytes of a root-signed manifest.
    ///
    /// Load on a verifier with
    /// `PublicKeyDirectory.fromSignedFile(path, rootMlDsaVerifyingKey)`,
    /// where `rootMlDsaVerifyingKey` is this keypair's public
    /// `mlDsaVerifyingKey`. The signing seed never crosses the FFI.
    #[napi]
    pub fn build_signed_manifest(&self, bundles: Vec<PublicKeyBundleView>) -> Result<Buffer> {
        let raw: Vec<PublicKeyBundleInner> = bundles.iter().map(bundle_view_to_inner).collect();
        let manifest = FilePublicKeyDirectoryInner::build_signed_manifest(
            &raw,
            &self.inner.ml_dsa_signing_key,
        )
        .map_err(|e| Error::from_reason(format!("build manifest: {e}")))?;
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|e| Error::from_reason(format!("serialize manifest: {e}")))?;
        Ok(Buffer::from(bytes))
    }
}

/// JS-visible public-key bundle. Plain object so JS can pluck fields directly.
#[napi(object)]
pub struct PublicKeyBundleView {
    pub id: String,
    pub ml_dsa_verifying_key: Buffer,
    pub ml_kem_encapsulation_key: Buffer,
    pub ed25519_verifying_key: Buffer,
    pub x25519_public_key: Buffer,
    /// Created-at unix-epoch seconds.
    pub created_at: i64,
    /// Expires-at unix-epoch seconds (null if no expiry).
    pub expires_at: Option<i64>,
}

impl From<PublicKeyBundleInner> for PublicKeyBundleView {
    fn from(b: PublicKeyBundleInner) -> Self {
        Self {
            id: b.id,
            ml_dsa_verifying_key: Buffer::from(b.ml_dsa_verifying_key),
            ml_kem_encapsulation_key: Buffer::from(b.ml_kem_encapsulation_key),
            ed25519_verifying_key: Buffer::from(b.ed25519_verifying_key),
            x25519_public_key: Buffer::from(b.x25519_public_key),
            created_at: b.created_at.timestamp(),
            expires_at: b.expires_at.map(|d| d.timestamp()),
        }
    }
}

// ─── PqTokenSigner class ─────────────────────────────────────────

/// PQ token signer — wraps `kavach_pq::PqTokenSigner` and exposes
/// sign/verify across the FFI.
///
/// Construct via `PqTokenSigner.pqOnly(...)` (ML-DSA-65 only) or
/// `PqTokenSigner.hybridFromBytes(...)` (ML-DSA-65 + Ed25519). For tests
/// and quick starts, `PqTokenSigner.generatePqOnly()` /
/// `PqTokenSigner.generateHybrid()` produce a fresh keypair internally.
#[napi]
pub struct PqTokenSigner {
    inner: Arc<PqTokenSignerInner>,
    key_id: String,
    is_hybrid: bool,
}

#[napi]
impl PqTokenSigner {
    /// Build a PQ-only (ML-DSA-65) signer from raw key bytes.
    #[napi(factory, js_name = "pqOnly")]
    pub fn pq_only(
        ml_dsa_signing_key: Buffer,
        ml_dsa_verifying_key: Buffer,
        key_id: String,
    ) -> Self {
        let inner = PqTokenSignerInner::new(
            ml_dsa_signing_key.to_vec(),
            ml_dsa_verifying_key.to_vec(),
            key_id.clone(),
        );
        Self {
            inner: Arc::new(inner),
            key_id,
            is_hybrid: false,
        }
    }

    /// Build a hybrid (ML-DSA-65 + Ed25519) signer from raw key bytes.
    #[napi(factory, js_name = "hybridFromBytes")]
    pub fn hybrid_from_bytes(
        ml_dsa_signing_key: Buffer,
        ml_dsa_verifying_key: Buffer,
        ed25519_signing_key: Buffer,
        ed25519_verifying_key: Buffer,
        key_id: String,
    ) -> Self {
        let inner = PqTokenSignerInner::hybrid(
            ml_dsa_signing_key.to_vec(),
            ml_dsa_verifying_key.to_vec(),
            ed25519_signing_key.to_vec(),
            ed25519_verifying_key.to_vec(),
            key_id.clone(),
        );
        Self {
            inner: Arc::new(inner),
            key_id,
            is_hybrid: true,
        }
    }

    /// Generate a fresh PQ-only signer (random ML-DSA-65 keypair).
    /// Convenience for tests / quick starts. For production key management
    /// you'll want to persist the keypair — use `pqOnly(...)` instead.
    #[napi(factory, js_name = "generatePqOnly")]
    pub fn generate_pq_only(key_id: Option<String>) -> Result<Self> {
        let kp = KavachKeyPairInner::generate()
            .map_err(|e| Error::from_reason(format!("keypair generation: {e}")))?;
        let id = key_id.unwrap_or_else(|| kp.id.clone());
        let inner = PqTokenSignerInner::new(
            kp.ml_dsa_signing_key.clone(),
            kp.ml_dsa_verifying_key.clone(),
            id.clone(),
        );
        Ok(Self {
            inner: Arc::new(inner),
            key_id: id,
            is_hybrid: false,
        })
    }

    /// Generate a fresh hybrid signer (random ML-DSA-65 + Ed25519 keypair).
    #[napi(factory, js_name = "generateHybrid")]
    pub fn generate_hybrid(key_id: Option<String>) -> Result<Self> {
        let kp = KavachKeyPairInner::generate()
            .map_err(|e| Error::from_reason(format!("keypair generation: {e}")))?;
        let id = key_id.unwrap_or_else(|| kp.id.clone());
        let inner = PqTokenSignerInner::hybrid(
            kp.ml_dsa_signing_key.clone(),
            kp.ml_dsa_verifying_key.clone(),
            kp.ed25519_signing_key.clone(),
            kp.ed25519_verifying_key.clone(),
            id.clone(),
        );
        Ok(Self {
            inner: Arc::new(inner),
            key_id: id,
            is_hybrid: true,
        })
    }

    /// Build a PQ-only signer from an existing `KavachKeyPair`.
    /// Forwards `kp.id` as the key_id (override with `keyId`).
    #[napi(factory, js_name = "fromKeypairPqOnly")]
    pub fn from_keypair_pq_only(keypair: &KavachKeyPair, key_id: Option<String>) -> Self {
        let kp = &keypair.inner;
        let id = key_id.unwrap_or_else(|| kp.id.clone());
        let inner = PqTokenSignerInner::new(
            kp.ml_dsa_signing_key.clone(),
            kp.ml_dsa_verifying_key.clone(),
            id.clone(),
        );
        Self {
            inner: Arc::new(inner),
            key_id: id,
            is_hybrid: false,
        }
    }

    /// Build a hybrid signer from an existing `KavachKeyPair`.
    #[napi(factory, js_name = "fromKeypairHybrid")]
    pub fn from_keypair_hybrid(keypair: &KavachKeyPair, key_id: Option<String>) -> Self {
        let kp = &keypair.inner;
        let id = key_id.unwrap_or_else(|| kp.id.clone());
        let inner = PqTokenSignerInner::hybrid(
            kp.ml_dsa_signing_key.clone(),
            kp.ml_dsa_verifying_key.clone(),
            kp.ed25519_signing_key.clone(),
            kp.ed25519_verifying_key.clone(),
            id.clone(),
        );
        Self {
            inner: Arc::new(inner),
            key_id: id,
            is_hybrid: true,
        }
    }

    #[napi(getter)]
    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }

    #[napi(getter)]
    pub fn is_hybrid(&self) -> bool {
        self.is_hybrid
    }

    /// Sign a PermitToken (described by its primitive fields).
    /// Returns the JSON-encoded `SignedTokenEnvelope` bytes.
    #[napi]
    pub fn sign(&self, token: PermitTokenInput) -> Result<Buffer> {
        let pt = permit_token_from_input(&token)?;
        let sig = self
            .inner
            .sign(&pt)
            .map_err(|e| Error::from_reason(format!("sign failed: {e}")))?;
        Ok(Buffer::from(sig))
    }

    /// Verify `signature` against the supplied PermitToken fields.
    /// Throws on any failure (tampering, wrong key, malformed envelope,
    /// algorithm mismatch).
    #[napi]
    pub fn verify(&self, token: PermitTokenInput, signature: Buffer) -> Result<()> {
        let pt = permit_token_from_input(&token)?;
        self.inner
            .verify(&pt, signature.as_ref())
            .map_err(|e| Error::from_reason(format!("verify failed: {e}")))
    }
}

// ─── Audit chain ─────────────────────────────────────────────────

/// A single audit-log entry. Pass these to `SignedAuditChain.append`.
///
/// Required fields: `principalId`, `actionName`, `verdict`
/// (`"permit"` / `"refuse"` / `"invalidate"`), and `verdictDetail`.
/// All other fields default sensibly: a fresh UUID for `id` /
/// `evaluationId` / `sessionId`, and `Date.now()` for `timestamp`.
#[napi]
pub struct AuditEntry {
    inner: CoreAuditEntry,
}

/// Optional fields for `AuditEntry.new`.
#[napi(object)]
pub struct AuditEntryOptions {
    pub resource: Option<String>,
    pub decided_by: Option<String>,
    pub ip: Option<String>,
    pub evaluation_id: Option<String>,
    pub session_id: Option<String>,
}

#[napi]
impl AuditEntry {
    /// Construct an audit entry. `verdict` must be one of
    /// `"permit"`, `"refuse"`, `"invalidate"`.
    #[napi(factory, js_name = "new")]
    pub fn new(
        principal_id: String,
        action_name: String,
        verdict: String,
        verdict_detail: String,
        options: Option<AuditEntryOptions>,
    ) -> Result<Self> {
        match verdict.as_str() {
            "permit" | "refuse" | "invalidate" => {}
            other => {
                return Err(Error::from_reason(format!(
                    "verdict must be 'permit'|'refuse'|'invalidate', got '{other}'"
                )))
            }
        }
        let opts = options.unwrap_or(AuditEntryOptions {
            resource: None,
            decided_by: None,
            ip: None,
            evaluation_id: None,
            session_id: None,
        });
        let evaluation_id = match opts.evaluation_id {
            Some(s) => Uuid::parse_str(&s)
                .map_err(|e| Error::from_reason(format!("evaluationId not a UUID: {e}")))?,
            None => Uuid::new_v4(),
        };
        let session_id = match opts.session_id {
            Some(s) => Uuid::parse_str(&s)
                .map_err(|e| Error::from_reason(format!("sessionId not a UUID: {e}")))?,
            None => Uuid::new_v4(),
        };
        Ok(Self {
            inner: CoreAuditEntry {
                id: Uuid::new_v4(),
                evaluation_id,
                timestamp: Utc::now(),
                principal_id,
                action_name,
                resource: opts.resource,
                verdict,
                verdict_detail,
                decided_by: opts.decided_by,
                session_id,
                ip: opts.ip,
                context_snapshot: None,
            },
        })
    }

    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id.to_string()
    }

    #[napi(getter)]
    pub fn principal_id(&self) -> String {
        self.inner.principal_id.clone()
    }

    #[napi(getter)]
    pub fn action_name(&self) -> String {
        self.inner.action_name.clone()
    }

    #[napi(getter)]
    pub fn verdict(&self) -> String {
        self.inner.verdict.clone()
    }
}

fn bundle_view_to_inner(view: &PublicKeyBundleView) -> PublicKeyBundleInner {
    PublicKeyBundleInner {
        id: view.id.clone(),
        ml_dsa_verifying_key: view.ml_dsa_verifying_key.to_vec(),
        ml_kem_encapsulation_key: view.ml_kem_encapsulation_key.to_vec(),
        ed25519_verifying_key: view.ed25519_verifying_key.to_vec(),
        x25519_public_key: view.x25519_public_key.to_vec(),
        created_at: Utc
            .timestamp_opt(view.created_at, 0)
            .single()
            .unwrap_or_else(Utc::now),
        expires_at: view
            .expires_at
            .and_then(|s| Utc.timestamp_opt(s, 0).single()),
    }
}

/// A tamper-evident PQ-signed audit log.
///
/// Each appended entry is signed (ML-DSA-65, plus Ed25519 in hybrid mode)
/// and linked to the previous entry via a SHA-256 hash chain. Reordering,
/// inserting, deleting, mutating, or splicing across modes is detected at
/// `verify` time. The verifier's mode must match the chain's mode —
/// `verify` and `verifyJsonl` refuse to silently accept a hybrid chain
/// under a PQ-only verifier (and vice versa), closing the
/// signature-downgrade surface.
#[napi]
pub struct SignedAuditChain {
    inner: Arc<SignedAuditChainInner>,
    is_hybrid: bool,
}

#[napi]
impl SignedAuditChain {
    /// Construct a chain backed by the supplied keypair. `hybrid` defaults
    /// to true (ML-DSA-65 + Ed25519). The verifier mode at `verify` time
    /// must match.
    #[napi(constructor)]
    pub fn new(keypair: &KavachKeyPair, hybrid: Option<bool>) -> Self {
        let h = hybrid.unwrap_or(true);
        let signer = PqSigner::from_keypair(&keypair.inner, h);
        Self {
            inner: Arc::new(SignedAuditChainInner::new(signer)),
            is_hybrid: h,
        }
    }

    /// Append an audit entry. Returns the new chain length.
    #[napi]
    pub fn append(&self, entry: &AuditEntry) -> Result<u32> {
        self.inner
            .append(&entry.inner)
            .map_err(|e| Error::from_reason(format!("append failed: {e}")))?;
        Ok(self.inner.len() as u32)
    }

    #[napi(getter)]
    pub fn length(&self) -> u32 {
        self.inner.len() as u32
    }

    #[napi(getter)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[napi(getter)]
    pub fn head_hash(&self) -> String {
        self.inner.head_hash()
    }

    #[napi(getter)]
    pub fn is_hybrid(&self) -> bool {
        self.is_hybrid
    }

    /// Verify all entries in-place using the supplied public-key bundle.
    /// Throws on any tamper / signature mismatch / chain break / verifier
    /// mode mismatch.
    #[napi]
    pub fn verify(&self, public_keys: PublicKeyBundleView) -> Result<()> {
        let bundle = bundle_view_to_inner(&public_keys);
        let verifier = PqVerifier::from_bundle(&bundle, self.is_hybrid);
        let entries = self.inner.entries();
        pq_audit::verify_chain(&entries, &verifier)
            .map_err(|e| Error::from_reason(format!("audit chain verification failed: {e}")))
    }

    /// Export the chain as newline-delimited JSON bytes (`.jsonl`).
    /// One `SignedAuditEntry` per line. Trailing newline included.
    #[napi]
    pub fn export_jsonl(&self) -> Result<Buffer> {
        let buf = pq_audit::export_jsonl(&self.inner.entries())
            .map_err(|err| Error::from_reason(format!("export: {err}")))?;
        Ok(Buffer::from(buf))
    }

    /// Verify a previously-exported JSONL chain against the supplied
    /// public-key bundle. Returns the number of verified entries.
    ///
    /// The chain's mode is inferred from the blob. When `hybrid` is passed
    /// explicitly it acts as a strict assertion: an expectation mismatch
    /// throws *before* any crypto is attempted, preventing a caller from
    /// silently verifying a hybrid chain with a PQ-only verifier (or vice
    /// versa). Omit `hybrid` to trust the blob.
    ///
    /// Throws on tamper / signature mismatch / chain break / mode mismatch.
    #[napi]
    pub fn verify_jsonl(
        data: Buffer,
        public_keys: PublicKeyBundleView,
        hybrid: Option<bool>,
    ) -> Result<u32> {
        let entries = pq_audit::parse_jsonl(data.as_ref())
            .map_err(|e| Error::from_reason(format!("audit chain parse failed: {e}")))?;
        let detected = pq_audit::detect_mode(&entries)
            .map_err(|e| Error::from_reason(format!("audit chain parse failed: {e}")))?;
        let effective = match (hybrid, detected) {
            (Some(expected), Some(chain_mode)) if expected != chain_mode.is_hybrid() => {
                return Err(Error::from_reason(format!(
                    "audit chain mode mismatch: caller expected hybrid={expected} but chain is {chain_mode}"
                )));
            }
            (Some(expected), _) => expected,
            (None, Some(chain_mode)) => chain_mode.is_hybrid(),
            (None, None) => return Ok(0),
        };
        let bundle = bundle_view_to_inner(&public_keys);
        let verifier = PqVerifier::from_bundle(&bundle, effective);
        pq_audit::verify_chain(&entries, &verifier)
            .map_err(|e| Error::from_reason(format!("audit chain verification failed: {e}")))?;
        Ok(entries.len() as u32)
    }
}

// ─── Gate class ──────────────────────────────────────────────────

#[napi]
pub struct KavachGate {
    inner: Arc<core::Gate>,
    /// Held alongside the gate so `reload(policyToml)` can swap the
    /// PolicySet without rebuilding the gate. The same `Arc` is also
    /// inside `inner.evaluators` (PolicyEngine implements Evaluator).
    policy_engine: Arc<core::PolicyEngine>,
}

#[napi]
impl KavachGate {
    /// Create a new Kavach gate from TOML policy configuration.
    ///
    /// All evaluation logic runs in compiled Rust.
    /// When a `tokenSigner` is supplied, every Permit verdict carries a
    /// signed envelope on `verdict.signature` / `verdict.permitToken.signature`.
    /// Sign failures fail closed (Refuse).
    ///
    /// `geoDriftMaxKm`: tolerance (km) for `GeoLocationDrift`. When unset,
    /// any mid-session IP change is a Violation. When set, an IP change
    /// within this distance downgrades to a Warning — requires both
    /// `currentGeo` and `originGeo` to carry latitude/longitude. Missing
    /// geo with a threshold set fails closed.
    #[napi(constructor)]
    pub fn new(
        policy_toml: String,
        invariants: Option<Vec<InvariantInput>>,
        observe_only: Option<bool>,
        max_session_actions: Option<u32>,
        enable_drift: Option<bool>,
        token_signer: Option<&PqTokenSigner>,
        geo_drift_max_km: Option<f64>,
    ) -> Result<Self> {
        let policies = core::PolicySet::from_toml(&policy_toml)
            .map_err(|e| Error::from_reason(format!("policy parse error: {e}")))?;

        let policy_engine = Arc::new(core::PolicyEngine::new(policies));

        let mut evaluators: Vec<Arc<dyn Evaluator>> = vec![policy_engine.clone()];

        if enable_drift.unwrap_or(true) {
            let geo: Box<dyn core::DriftDetector> = match geo_drift_max_km {
                Some(km) => Box::new(core::GeoLocationDrift::with_max_distance_km(km)),
                None => Box::new(core::GeoLocationDrift::default()),
            };
            let drift = core::DriftEvaluator::new(vec![
                geo,
                Box::new(core::SessionAgeDrift::default()),
                Box::new(core::DeviceDrift),
                Box::new(core::BehaviorDrift::default()),
            ]);
            evaluators.push(Arc::new(drift));
        }

        let mut inv_list: Vec<core::Invariant> = invariants
            .unwrap_or_default()
            .into_iter()
            .map(|i| core::Invariant::param_max(i.name, i.field, i.max_value))
            .collect();

        if let Some(max) = max_session_actions {
            inv_list.push(core::Invariant::max_actions_per_session(
                "max_session_actions",
                max as u64,
            ));
        }

        if !inv_list.is_empty() {
            evaluators.push(Arc::new(core::InvariantSet::new(inv_list)));
        }

        let config = core::GateConfig {
            observe_only: observe_only.unwrap_or(false),
            ..Default::default()
        };

        let mut gate = core::Gate::new(evaluators, config);
        if let Some(signer) = token_signer {
            let signer_arc: Arc<dyn CoreTokenSigner> = signer.inner.clone();
            gate = gate.with_token_signer(signer_arc);
        }

        Ok(Self {
            inner: Arc::new(gate),
            policy_engine,
        })
    }

    /// Hot-reload the policy set from a fresh TOML string.
    ///
    /// Parse errors throw and the previous good set stays in place — never
    /// wipe a running engine on a bad reload. An empty TOML is intentionally
    /// valid (= default-deny everything; useful as a kill-switch).
    #[napi]
    pub fn reload(&self, policy_toml: String) -> Result<()> {
        let policies = core::PolicySet::from_toml(&policy_toml)
            .map_err(|e| Error::from_reason(format!("policy parse error: {e}")))?;
        self.policy_engine.reload(policies);
        Ok(())
    }

    /// Evaluate an action context. Returns a VerdictResult.
    ///
    /// Crosses into Rust for all evaluation: policy, drift, invariants.
    #[napi]
    pub fn evaluate(&self, ctx: ActionContextInput) -> Result<VerdictResult> {
        let kind = match ctx.principal_kind.as_str() {
            "user" => core::PrincipalKind::User,
            "agent" => core::PrincipalKind::Agent,
            "service" => core::PrincipalKind::Service,
            "scheduler" => core::PrincipalKind::Scheduler,
            "external" => core::PrincipalKind::External,
            other => {
                return Err(Error::from_reason(format!(
                    "unknown principal kind: {other}"
                )))
            }
        };

        let principal = core::Principal {
            id: ctx.principal_id,
            kind,
            roles: ctx.roles.unwrap_or_default(),
            credentials_issued_at: chrono::Utc::now(),
            display_name: None,
        };

        let mut action = core::ActionDescriptor::new(ctx.action_name);
        if let Some(r) = ctx.resource {
            action = action.with_resource(r);
        }
        if let Some(params) = ctx.params {
            for (k, v) in params {
                action.params.insert(k, serde_json::json!(v));
            }
        }

        let mut session = core::SessionState::new();
        if let Some(sid) = ctx.session_id {
            session.session_id = uuid::Uuid::parse_str(&sid).unwrap_or(uuid::Uuid::new_v4());
        }

        let mut env = core::EnvContext::default();
        if let Some(ip_str) = ctx.ip {
            env.ip = ip_str.parse().ok();
            session.origin_ip = env.ip;
        }

        if let Some(g) = ctx.current_geo {
            env.geo = Some(geo_input_to_core(g));
        }
        if let Some(g) = ctx.origin_geo {
            session.origin_geo = Some(geo_input_to_core(g));
        }

        let inner_ctx = core::ActionContext::new(principal, action, session, env);

        let gate = self.inner.clone();
        let result = runtime().block_on(async move { gate.evaluate(&inner_ctx).await });

        Ok(result.into())
    }

    /// Number of evaluators in the gate chain.
    #[napi(getter)]
    pub fn evaluator_count(&self) -> u32 {
        self.inner.evaluator_count() as u32
    }
}

// ─── SecureChannel ───────────────────────────────────────────────

fn parse_sealed(data: &[u8]) -> Result<EncryptedPayload> {
    serde_json::from_slice(data)
        .map_err(|e| Error::from_reason(format!("sealed payload parse failed: {e}")))
}

fn serialize_sealed(payload: &EncryptedPayload) -> Result<Vec<u8>> {
    serde_json::to_vec(payload)
        .map_err(|e| Error::from_reason(format!("sealed payload serialize failed: {e}")))
}

/// A hybrid-encrypted, PQ-signed channel between two Kavach services.
///
/// Each side constructs a channel from their own `KavachKeyPair` (secret
/// material — never share) and the remote party's `PublicKeyBundle`
/// (safe to share). Sealed payloads are opaque `Buffer`s carrying the
/// full envelope; store or transmit them anywhere.
///
/// Three flows:
/// - `sendSigned(data, contextId, correlationId)` / `receiveSigned(sealed,
///   expectedContextId)` — sign + encrypt, with replay protection and
///   context binding. Throws on tamper, wrong recipient, replay, or
///   context mismatch.
/// - `sendData(data)` / `receiveData(sealed)` — encryption only, no
///   signing.
/// - `localKeyId` / `remoteKeyId` getters for diagnostics.
#[napi]
pub struct SecureChannel {
    inner: Arc<SecureChannelInner>,
}

#[napi]
impl SecureChannel {
    /// Construct a channel from this side's full keypair and the remote
    /// party's public-key bundle.
    #[napi(constructor)]
    pub fn new(local_keypair: &KavachKeyPair, remote_public_keys: PublicKeyBundleView) -> Self {
        let remote_inner = bundle_view_to_inner(&remote_public_keys);
        let inner = SecureChannelInner::establish_from_bundle(&local_keypair.inner, &remote_inner);
        Self {
            inner: Arc::new(inner),
        }
    }

    #[napi(getter)]
    pub fn local_key_id(&self) -> String {
        self.inner.local_key_id().to_string()
    }

    #[napi(getter)]
    pub fn remote_key_id(&self) -> String {
        self.inner.remote_key_id().to_string()
    }

    /// Sign + encrypt `data`, binding it to `contextId` and
    /// `correlationId`. Returns opaque sealed bytes — pass them to the
    /// remote side's `receiveSigned`.
    #[napi]
    pub fn send_signed(
        &self,
        data: Buffer,
        context_id: String,
        correlation_id: String,
    ) -> Result<Buffer> {
        let sealed = self
            .inner
            .send_signed(data.as_ref(), &context_id, &correlation_id)
            .map_err(|e| Error::from_reason(format!("sendSigned failed: {e}")))?;
        Ok(Buffer::from(serialize_sealed(&sealed)?))
    }

    /// Decrypt + signature/replay/context-verify. Throws on any failure
    /// (decrypt, tamper, replay, wrong context, wrong recipient).
    #[napi]
    pub fn receive_signed(&self, sealed: Buffer, expected_context_id: String) -> Result<Buffer> {
        let payload = parse_sealed(sealed.as_ref())?;
        let plaintext = self
            .inner
            .receive_signed(&payload, &expected_context_id)
            .map_err(|e| Error::from_reason(format!("receiveSigned failed: {e}")))?;
        Ok(Buffer::from(plaintext))
    }

    /// Encrypt `data` with no signing and no replay tracking. Use
    /// `sendSigned` when you need integrity + authenticity + replay
    /// protection.
    #[napi]
    pub fn send_data(&self, data: Buffer) -> Result<Buffer> {
        let sealed = self
            .inner
            .send_data(data.as_ref())
            .map_err(|e| Error::from_reason(format!("sendData failed: {e}")))?;
        Ok(Buffer::from(serialize_sealed(&sealed)?))
    }

    /// Decrypt a sealed payload. Throws on any failure.
    #[napi]
    pub fn receive_data(&self, sealed: Buffer) -> Result<Buffer> {
        let payload = parse_sealed(sealed.as_ref())?;
        let plaintext = self
            .inner
            .receive_data(&payload)
            .map_err(|e| Error::from_reason(format!("receiveData failed: {e}")))?;
        Ok(Buffer::from(plaintext))
    }
}

// ─── Public-key directory ────────────────────────────────────────

/// Backing store for [`PublicKeyDirectory`] — tracks the concrete
/// impl so type-specific ops (insert/remove/reload) stay reachable.
enum DirectoryKind {
    InMemory(Arc<InMemoryPublicKeyDirectoryInner>),
    File(Arc<FilePublicKeyDirectoryInner>),
}

/// Public-key distribution surface for downstream verifiers.
///
/// Three backings:
/// - `PublicKeyDirectory.inMemory(bundles)` — programmatic store,
///   mutable via `insert` / `remove`.
/// - `PublicKeyDirectory.fromFile(path)` — unsigned JSON array on
///   disk. Safe only when the file is local to the verifier.
/// - `PublicKeyDirectory.fromSignedFile(path, rootMlDsaVerifyingKey)`
///   — root-signed manifest. Any file whose ML-DSA-65 signature
///   doesn't verify against `rootMlDsaVerifyingKey` is rejected at
///   load time. Use this for cross-host trust.
///
/// `fetch(keyId)` throws on any failure (NotFound /
/// BackendUnavailable / RootSignatureInvalid / Corrupt) — fail-closed
/// so unverifiable tokens can't be silently accepted.
#[napi]
pub struct PublicKeyDirectory {
    inner: Arc<dyn PublicKeyDirectoryTrait>,
    kind: DirectoryKind,
}

#[napi]
impl PublicKeyDirectory {
    /// Build an in-memory directory, optionally pre-populated.
    #[napi(factory, js_name = "inMemory")]
    pub fn in_memory(bundles: Option<Vec<PublicKeyBundleView>>) -> Self {
        let raw: Vec<PublicKeyBundleInner> = bundles
            .unwrap_or_default()
            .iter()
            .map(bundle_view_to_inner)
            .collect();
        let dir = Arc::new(InMemoryPublicKeyDirectoryInner::from_bundles(raw));
        Self {
            inner: dir.clone(),
            kind: DirectoryKind::InMemory(dir),
        }
    }

    /// Load an unsigned bundle array from disk.
    #[napi(factory, js_name = "fromFile")]
    pub fn from_file(path: String) -> Result<Self> {
        let dir = FilePublicKeyDirectoryInner::load_unsigned(&path)
            .map_err(|e| Error::from_reason(format!("directory load: {e}")))?;
        let arc = Arc::new(dir);
        Ok(Self {
            inner: arc.clone(),
            kind: DirectoryKind::File(arc),
        })
    }

    /// Load a root-signed manifest; any manifest whose signature
    /// does not verify against `rootMlDsaVerifyingKey` is rejected.
    #[napi(factory, js_name = "fromSignedFile")]
    pub fn from_signed_file(path: String, root_ml_dsa_verifying_key: Buffer) -> Result<Self> {
        let dir =
            FilePublicKeyDirectoryInner::load_signed(&path, root_ml_dsa_verifying_key.to_vec())
                .map_err(|e| Error::from_reason(format!("directory load: {e}")))?;
        let arc = Arc::new(dir);
        Ok(Self {
            inner: arc.clone(),
            kind: DirectoryKind::File(arc),
        })
    }

    /// Fetch a bundle by `keyId`. Throws on any failure.
    #[napi]
    pub fn fetch(&self, key_id: String) -> Result<PublicKeyBundleView> {
        let dir = self.inner.clone();
        let bundle = runtime()
            .block_on(async move { dir.fetch(&key_id).await })
            .map_err(|e| Error::from_reason(format!("directory fetch: {e}")))?;
        Ok(PublicKeyBundleView::from(bundle))
    }

    /// Insert (or overwrite) a bundle. Throws on file-backed directories.
    #[napi]
    pub fn insert(&self, bundle: PublicKeyBundleView) -> Result<()> {
        match &self.kind {
            DirectoryKind::InMemory(dir) => {
                dir.insert(bundle_view_to_inner(&bundle));
                Ok(())
            }
            DirectoryKind::File(_) => Err(Error::from_reason(
                "insert only supported on in-memory directories",
            )),
        }
    }

    /// Remove a bundle by id. Throws on file-backed directories.
    #[napi]
    pub fn remove(&self, key_id: String) -> Result<bool> {
        match &self.kind {
            DirectoryKind::InMemory(dir) => Ok(dir.remove(&key_id).is_some()),
            DirectoryKind::File(_) => Err(Error::from_reason(
                "remove only supported on in-memory directories",
            )),
        }
    }

    /// Re-read the underlying file. No-op for in-memory directories.
    /// Parse / signature errors throw; the previous cache is preserved.
    #[napi]
    pub fn reload(&self) -> Result<()> {
        match &self.kind {
            DirectoryKind::File(f) => f
                .reload()
                .map_err(|e| Error::from_reason(format!("directory reload: {e}"))),
            DirectoryKind::InMemory(_) => Ok(()),
        }
    }

    #[napi(getter)]
    pub fn length(&self) -> u32 {
        match &self.kind {
            DirectoryKind::InMemory(d) => d.len() as u32,
            DirectoryKind::File(d) => d.len() as u32,
        }
    }

    #[napi(getter)]
    pub fn is_empty(&self) -> bool {
        self.length() == 0
    }

    /// Build the JSON bytes of an unsigned bundle array suitable for
    /// `fromFile(...)`.
    #[napi(js_name = "buildUnsignedManifest")]
    pub fn build_unsigned_manifest(bundles: Vec<PublicKeyBundleView>) -> Result<Buffer> {
        let raw: Vec<PublicKeyBundleInner> = bundles.iter().map(bundle_view_to_inner).collect();
        let bytes = serde_json::to_vec(&raw)
            .map_err(|e| Error::from_reason(format!("serialize bundles: {e}")))?;
        Ok(Buffer::from(bytes))
    }

    /// Build the JSON bytes of a root-signed manifest suitable for
    /// `fromSignedFile(...)`. `mlDsaSigningKey` is the 32-byte
    /// ML-DSA-65 seed of the root authority.
    #[napi(js_name = "buildSignedManifest")]
    pub fn build_signed_manifest(
        bundles: Vec<PublicKeyBundleView>,
        ml_dsa_signing_key: Buffer,
    ) -> Result<Buffer> {
        let raw: Vec<PublicKeyBundleInner> = bundles.iter().map(bundle_view_to_inner).collect();
        let manifest =
            FilePublicKeyDirectoryInner::build_signed_manifest(&raw, ml_dsa_signing_key.as_ref())
                .map_err(|e| Error::from_reason(format!("build manifest: {e}")))?;
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|e| Error::from_reason(format!("serialize manifest: {e}")))?;
        Ok(Buffer::from(bytes))
    }
}

/// Verifies `PermitToken` signatures by looking up the matching
/// `PublicKeyBundle` in a `PublicKeyDirectory` via the envelope's
/// `key_id`. Fail-closed — any failure throws.
#[napi]
pub struct DirectoryTokenVerifier {
    inner: Arc<DirectoryTokenVerifierInner>,
}

#[napi]
impl DirectoryTokenVerifier {
    /// `hybrid` defaults to true (ML-DSA-65 + Ed25519 required).
    /// Setting it to false makes this a PQ-only verifier that
    /// rejects hybrid envelopes.
    #[napi(constructor)]
    pub fn new(directory: &PublicKeyDirectory, hybrid: Option<bool>) -> Self {
        let inner = if hybrid.unwrap_or(true) {
            DirectoryTokenVerifierInner::hybrid(directory.inner.clone())
        } else {
            DirectoryTokenVerifierInner::pq_only(directory.inner.clone())
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Verify `signature` against the supplied PermitToken fields.
    /// Throws on any failure (envelope parse, algorithm mismatch,
    /// directory miss, signature invalid).
    #[napi]
    pub fn verify(&self, token: PermitTokenInput, signature: Buffer) -> Result<()> {
        let pt = permit_token_from_input(&token)?;
        let verifier = self.inner.clone();
        let sig = signature.to_vec();
        runtime()
            .block_on(async move { verifier.verify(&pt, &sig).await })
            .map_err(|e| Error::from_reason(format!("verify failed: {e}")))
    }
}
