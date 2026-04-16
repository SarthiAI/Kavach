//! # Kavach Python Bindings
//!
//! PyO3 bridge that exposes kavach-core's Rust engine to Python.
//! All evaluation logic runs in Rust — Python calls across FFI.
//!
//! The compiled module is `_kavach_engine`. The idiomatic Python
//! wrapper (`kavach` package) imports from this module.

// PyO3's `#[pymethods]` / `#[pyfunction]` / `#[classmethod]` macros emit
// `PyErr::from(e)` calls in generated code where `e` is already a `PyErr`.
// Clippy attributes these to the user-authored return-type spans, producing
// ~30 false-positive `useless_conversion` warnings. The file's own code has
// only 4 `.into()` calls and none are useless — suppressing at module scope.
#![allow(clippy::useless_conversion)]

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
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;
use uuid::Uuid;

// ─── Lazy Tokio runtime for async bridge ─────────────────────────

fn runtime() -> &'static Runtime {
    use std::sync::OnceLock;
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| Runtime::new().expect("failed to create tokio runtime"))
}

// ─── Python-facing types ─────────────────────────────────────────

/// A signed permit token — proof the gate ran.
///
/// Constructed either by reading a Verdict's `permit_token` property after
/// a Permit verdict, or directly from the wire fields (token_id, evaluation_id,
/// issued_at, expires_at, action_name) on the verifier side. The `signature`
/// field carries the JSON `SignedTokenEnvelope` produced by `PqTokenSigner.sign`.
#[pyclass]
#[derive(Clone)]
struct PermitToken {
    inner: core::PermitToken,
}

#[pymethods]
impl PermitToken {
    /// Construct a PermitToken from its primitive fields.
    ///
    /// `issued_at` and `expires_at` are unix-epoch seconds.
    #[new]
    #[pyo3(signature = (token_id, evaluation_id, issued_at, expires_at, action_name, signature=None))]
    fn new(
        token_id: &str,
        evaluation_id: &str,
        issued_at: i64,
        expires_at: i64,
        action_name: String,
        signature: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let token_id = Uuid::parse_str(token_id)
            .map_err(|e| PyValueError::new_err(format!("token_id not a UUID: {e}")))?;
        let evaluation_id = Uuid::parse_str(evaluation_id)
            .map_err(|e| PyValueError::new_err(format!("evaluation_id not a UUID: {e}")))?;
        let issued_at = Utc
            .timestamp_opt(issued_at, 0)
            .single()
            .ok_or_else(|| PyValueError::new_err("issued_at out of range"))?;
        let expires_at = Utc
            .timestamp_opt(expires_at, 0)
            .single()
            .ok_or_else(|| PyValueError::new_err("expires_at out of range"))?;
        Ok(Self {
            inner: core::PermitToken {
                token_id,
                evaluation_id,
                issued_at,
                expires_at,
                action_name,
                signature,
            },
        })
    }

    #[getter]
    fn token_id(&self) -> String {
        self.inner.token_id.to_string()
    }

    #[getter]
    fn evaluation_id(&self) -> String {
        self.inner.evaluation_id.to_string()
    }

    #[getter]
    fn issued_at(&self) -> i64 {
        self.inner.issued_at.timestamp()
    }

    #[getter]
    fn expires_at(&self) -> i64 {
        self.inner.expires_at.timestamp()
    }

    #[getter]
    fn action_name(&self) -> String {
        self.inner.action_name.clone()
    }

    #[getter]
    fn signature<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .signature
            .as_ref()
            .map(|s| PyBytes::new_bound(py, s))
    }

    /// Canonical signable bytes — the exact bytes the signer signs.
    /// Exposed for diagnostics and for callers who want to drive a custom signer.
    fn canonical_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.canonical_bytes())
    }

    fn __repr__(&self) -> String {
        format!(
            "PermitToken(token_id={}, action={}, signed={})",
            self.inner.token_id,
            self.inner.action_name,
            self.inner.signature.is_some()
        )
    }
}

/// The gate verdict returned to Python.
#[pyclass]
#[derive(Clone)]
struct Verdict {
    #[pyo3(get)]
    kind: String, // "permit", "refuse", "invalidate"
    #[pyo3(get)]
    evaluator: Option<String>,
    #[pyo3(get)]
    reason: Option<String>,
    #[pyo3(get)]
    code: Option<String>,
    #[pyo3(get)]
    token_id: Option<String>,
    permit_token_inner: Option<core::PermitToken>,
}

#[pymethods]
impl Verdict {
    #[getter]
    fn is_permit(&self) -> bool {
        self.kind == "permit"
    }

    #[getter]
    fn is_refuse(&self) -> bool {
        self.kind == "refuse"
    }

    #[getter]
    fn is_invalidate(&self) -> bool {
        self.kind == "invalidate"
    }

    /// The full PermitToken (with signature) when the verdict is Permit.
    /// Returns None for Refuse / Invalidate.
    #[getter]
    fn permit_token(&self) -> Option<PermitToken> {
        self.permit_token_inner
            .clone()
            .map(|inner| PermitToken { inner })
    }

    /// Convenience: raw signature bytes (or None if unsigned / not Permit).
    #[getter]
    fn signature<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.permit_token_inner
            .as_ref()
            .and_then(|t| t.signature.as_ref())
            .map(|s| PyBytes::new_bound(py, s))
    }

    fn __repr__(&self) -> String {
        match self.kind.as_str() {
            "permit" => format!(
                "Verdict.Permit(token={})",
                self.token_id.as_deref().unwrap_or("?")
            ),
            "refuse" => format!(
                "Verdict.Refuse(evaluator={}, reason={})",
                self.evaluator.as_deref().unwrap_or("?"),
                self.reason.as_deref().unwrap_or("?")
            ),
            "invalidate" => format!(
                "Verdict.Invalidate(reason={})",
                self.reason.as_deref().unwrap_or("?")
            ),
            _ => "Verdict.Unknown".to_string(),
        }
    }
}

impl From<core::Verdict> for Verdict {
    fn from(v: core::Verdict) -> Self {
        match v {
            core::Verdict::Permit(token) => Verdict {
                kind: "permit".into(),
                evaluator: None,
                reason: None,
                code: None,
                token_id: Some(token.token_id.to_string()),
                permit_token_inner: Some(token),
            },
            core::Verdict::Refuse(r) => Verdict {
                kind: "refuse".into(),
                evaluator: Some(r.evaluator),
                reason: Some(r.reason),
                code: Some(r.code.to_string()),
                token_id: None,
                permit_token_inner: None,
            },
            core::Verdict::Invalidate(s) => Verdict {
                kind: "invalidate".into(),
                evaluator: Some(s.evaluator),
                reason: Some(s.reason),
                code: None,
                token_id: None,
                permit_token_inner: None,
            },
        }
    }
}

/// Public-key bundle — the safe-to-share half of a [`KavachKeyPair`].
///
/// Holds raw bytes for ML-DSA-65 (signing) verifying key, ML-KEM-768
/// (KEM) encapsulation key, Ed25519 verifying key, and X25519 public key.
/// Use this on downstream services that only need to *verify* signatures
/// or *encrypt* to the gate — never expose the full keypair.
#[pyclass]
#[derive(Clone)]
struct PublicKeyBundle {
    inner: PublicKeyBundleInner,
}

#[pymethods]
impl PublicKeyBundle {
    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[getter]
    fn ml_dsa_verifying_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.ml_dsa_verifying_key)
    }

    #[getter]
    fn ml_kem_encapsulation_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.ml_kem_encapsulation_key)
    }

    #[getter]
    fn ed25519_verifying_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.ed25519_verifying_key)
    }

    #[getter]
    fn x25519_public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.x25519_public_key)
    }

    #[getter]
    fn created_at(&self) -> i64 {
        self.inner.created_at.timestamp()
    }

    #[getter]
    fn expires_at(&self) -> Option<i64> {
        self.inner.expires_at.map(|d| d.timestamp())
    }

    fn __repr__(&self) -> String {
        format!(
            "PublicKeyBundle(id={}, ml_dsa_vk={}B, ml_kem_ek={}B, ed25519_vk={}B, x25519_pk={}B)",
            self.inner.id,
            self.inner.ml_dsa_verifying_key.len(),
            self.inner.ml_kem_encapsulation_key.len(),
            self.inner.ed25519_verifying_key.len(),
            self.inner.x25519_public_key.len(),
        )
    }
}

/// A Kavach keypair — ML-DSA-65 + ML-KEM-768 + Ed25519 + X25519.
///
/// Holds *both* signing/decapsulation/secret keys and their public counterparts.
/// Use [`KavachKeyPair.public_keys`] to extract the safe-to-share
/// [`PublicKeyBundle`]; share that with verifiers, never the keypair itself.
///
/// Construct with `KavachKeyPair.generate()` (no expiry) or
/// `KavachKeyPair.generate_with_expiry(seconds)` (TTL in seconds).
#[pyclass]
struct KavachKeyPair {
    inner: Arc<KavachKeyPairInner>,
}

#[pymethods]
impl KavachKeyPair {
    /// Generate a fresh random keypair (no expiry).
    #[classmethod]
    fn generate(_cls: &Bound<'_, pyo3::types::PyType>) -> PyResult<Self> {
        let inner = KavachKeyPairInner::generate()
            .map_err(|e| PyRuntimeError::new_err(format!("keypair generation: {e}")))?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Generate a fresh random keypair that expires after `seconds`.
    #[classmethod]
    fn generate_with_expiry(_cls: &Bound<'_, pyo3::types::PyType>, seconds: i64) -> PyResult<Self> {
        let inner =
            KavachKeyPairInner::generate_with_expiry(Some(ChronoDuration::seconds(seconds)))
                .map_err(|e| PyRuntimeError::new_err(format!("keypair generation: {e}")))?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[getter]
    fn created_at(&self) -> i64 {
        self.inner.created_at.timestamp()
    }

    #[getter]
    fn expires_at(&self) -> Option<i64> {
        self.inner.expires_at.map(|d| d.timestamp())
    }

    /// True if this keypair has passed its expiry.
    #[getter]
    fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// The safe-to-share half — share this with verifiers / KEM senders.
    fn public_keys(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            inner: self.inner.public_keys(),
        }
    }

    /// Sign a [`PublicKeyDirectory`] manifest with this keypair's ML-DSA-65
    /// seed, returning the JSON bytes of a [`SignedDirectoryManifest`].
    ///
    /// The resulting bytes can be written to a file and loaded on a
    /// verifier with `PublicKeyDirectory.from_signed_file(path, root_vk)`,
    /// where `root_vk` is this keypair's public ML-DSA verifying key.
    ///
    /// The signing seed never crosses the FFI — you don't need to handle
    /// raw secret bytes in Python.
    fn build_signed_manifest<'py>(
        &self,
        py: Python<'py>,
        bundles: Vec<PublicKeyBundle>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let raw: Vec<PublicKeyBundleInner> = bundles.into_iter().map(|b| b.inner).collect();
        let manifest = FilePublicKeyDirectoryInner::build_signed_manifest(
            &raw,
            &self.inner.ml_dsa_signing_key,
        )
        .map_err(|e| PyRuntimeError::new_err(format!("build manifest: {e}")))?;
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|e| PyRuntimeError::new_err(format!("serialize manifest: {e}")))?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    fn __repr__(&self) -> String {
        format!(
            "KavachKeyPair(id={}, expired={})",
            self.inner.id,
            self.inner.is_expired(),
        )
    }
}

/// PQ token signer — wraps `kavach_pq::PqTokenSigner` and exposes
/// sign/verify across FFI.
///
/// Construct via `PqTokenSigner.pq_only(...)` (ML-DSA-65 only) or
/// `PqTokenSigner.hybrid(...)` (ML-DSA-65 + Ed25519). For tests and
/// quick starts, `PqTokenSigner.generate_pq_only()` /
/// `PqTokenSigner.generate_hybrid()` produce a fresh keypair internally.
#[pyclass]
#[derive(Clone)]
struct PqTokenSigner {
    inner: Arc<PqTokenSignerInner>,
    key_id_str: String,
    is_hybrid: bool,
}

#[pymethods]
impl PqTokenSigner {
    /// Build a PQ-only signer from raw key bytes.
    ///
    /// Args:
    ///     ml_dsa_signing_key: 32-byte ML-DSA-65 seed (`xi`).
    ///     ml_dsa_verifying_key: encoded ML-DSA-65 verifying key.
    ///     key_id: identifier stamped into every envelope.
    #[classmethod]
    fn pq_only(
        _cls: &Bound<'_, pyo3::types::PyType>,
        ml_dsa_signing_key: Vec<u8>,
        ml_dsa_verifying_key: Vec<u8>,
        key_id: String,
    ) -> PyResult<Self> {
        let inner =
            PqTokenSignerInner::new(ml_dsa_signing_key, ml_dsa_verifying_key, key_id.clone());
        Ok(Self {
            inner: Arc::new(inner),
            key_id_str: key_id,
            is_hybrid: false,
        })
    }

    /// Build a hybrid (ML-DSA-65 + Ed25519) signer from raw key bytes.
    #[classmethod]
    fn hybrid(
        _cls: &Bound<'_, pyo3::types::PyType>,
        ml_dsa_signing_key: Vec<u8>,
        ml_dsa_verifying_key: Vec<u8>,
        ed25519_signing_key: Vec<u8>,
        ed25519_verifying_key: Vec<u8>,
        key_id: String,
    ) -> PyResult<Self> {
        let inner = PqTokenSignerInner::hybrid(
            ml_dsa_signing_key,
            ml_dsa_verifying_key,
            ed25519_signing_key,
            ed25519_verifying_key,
            key_id.clone(),
        );
        Ok(Self {
            inner: Arc::new(inner),
            key_id_str: key_id,
            is_hybrid: true,
        })
    }

    /// Generate a fresh PQ-only signer (random ML-DSA-65 keypair).
    /// Convenience for tests / quick starts. For production key management
    /// you'll want to persist the keypair — use `pq_only(...)` instead.
    #[classmethod]
    #[pyo3(signature = (key_id=None))]
    fn generate_pq_only(
        _cls: &Bound<'_, pyo3::types::PyType>,
        key_id: Option<String>,
    ) -> PyResult<Self> {
        let kp = KavachKeyPairInner::generate()
            .map_err(|e| PyRuntimeError::new_err(format!("keypair generation: {e}")))?;
        let id = key_id.unwrap_or_else(|| kp.id.clone());
        let inner = PqTokenSignerInner::new(
            kp.ml_dsa_signing_key.clone(),
            kp.ml_dsa_verifying_key.clone(),
            id.clone(),
        );
        Ok(Self {
            inner: Arc::new(inner),
            key_id_str: id,
            is_hybrid: false,
        })
    }

    /// Generate a fresh hybrid signer (random ML-DSA-65 + Ed25519 keypair).
    #[classmethod]
    #[pyo3(signature = (key_id=None))]
    fn generate_hybrid(
        _cls: &Bound<'_, pyo3::types::PyType>,
        key_id: Option<String>,
    ) -> PyResult<Self> {
        let kp = KavachKeyPairInner::generate()
            .map_err(|e| PyRuntimeError::new_err(format!("keypair generation: {e}")))?;
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
            key_id_str: id,
            is_hybrid: true,
        })
    }

    /// Build a PQ-only signer from an existing `KavachKeyPair`.
    /// Convenience: extracts the ML-DSA-65 keypair and forwards `kp.id`
    /// as the key_id (override with `key_id=...`).
    #[classmethod]
    #[pyo3(signature = (keypair, key_id=None))]
    fn from_keypair_pq_only(
        _cls: &Bound<'_, pyo3::types::PyType>,
        keypair: &KavachKeyPair,
        key_id: Option<String>,
    ) -> PyResult<Self> {
        let kp = &keypair.inner;
        let id = key_id.unwrap_or_else(|| kp.id.clone());
        let inner = PqTokenSignerInner::new(
            kp.ml_dsa_signing_key.clone(),
            kp.ml_dsa_verifying_key.clone(),
            id.clone(),
        );
        Ok(Self {
            inner: Arc::new(inner),
            key_id_str: id,
            is_hybrid: false,
        })
    }

    /// Build a hybrid signer from an existing `KavachKeyPair`.
    #[classmethod]
    #[pyo3(signature = (keypair, key_id=None))]
    fn from_keypair_hybrid(
        _cls: &Bound<'_, pyo3::types::PyType>,
        keypair: &KavachKeyPair,
        key_id: Option<String>,
    ) -> PyResult<Self> {
        let kp = &keypair.inner;
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
            key_id_str: id,
            is_hybrid: true,
        })
    }

    #[getter]
    fn key_id(&self) -> String {
        self.key_id_str.clone()
    }

    /// True for ML-DSA-65 + Ed25519 hybrid signers, False for PQ-only.
    /// Exposed as `is_hybrid` because the bare `hybrid` name is taken by
    /// the `hybrid(...)` classmethod that constructs hybrid signers.
    #[getter]
    fn is_hybrid(&self) -> bool {
        self.is_hybrid
    }

    /// Sign a PermitToken; returns the JSON-encoded `SignedTokenEnvelope` bytes
    /// suitable for `PermitToken.signature` / wire transport.
    fn sign<'py>(&self, py: Python<'py>, token: &PermitToken) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self
            .inner
            .sign(&token.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("sign failed: {e}")))?;
        Ok(PyBytes::new_bound(py, &sig))
    }

    /// Verify `signature` against `token`. Raises ValueError on any failure
    /// (tampering, wrong key, malformed envelope, algorithm mismatch).
    fn verify(&self, token: &PermitToken, signature: &[u8]) -> PyResult<()> {
        self.inner
            .verify(&token.inner, signature)
            .map_err(|e| PyValueError::new_err(format!("verify failed: {e}")))
    }
}

/// Geographic location — used for tolerant-mode `GeoLocationDrift`.
///
/// `country_code` is the only required field. `latitude` / `longitude`
/// enable Haversine distance calculations (required for tolerant-mode
/// drift where `max_distance_km` is set); `region` / `city` are free-text
/// annotations for drift violation messages.
#[pyclass]
#[derive(Clone)]
struct GeoLocation {
    inner: core::GeoLocation,
}

#[pymethods]
impl GeoLocation {
    #[new]
    #[pyo3(signature = (country_code, region=None, city=None, latitude=None, longitude=None))]
    fn new(
        country_code: String,
        region: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
    ) -> Self {
        Self {
            inner: core::GeoLocation {
                country_code,
                region,
                city,
                latitude,
                longitude,
            },
        }
    }

    #[getter]
    fn country_code(&self) -> String {
        self.inner.country_code.clone()
    }

    #[getter]
    fn region(&self) -> Option<String> {
        self.inner.region.clone()
    }

    #[getter]
    fn city(&self) -> Option<String> {
        self.inner.city.clone()
    }

    #[getter]
    fn latitude(&self) -> Option<f64> {
        self.inner.latitude
    }

    #[getter]
    fn longitude(&self) -> Option<f64> {
        self.inner.longitude
    }

    /// Haversine distance (km) between this location and `other`.
    /// Returns `None` if either side is missing latitude/longitude.
    fn distance_km(&self, other: &GeoLocation) -> Option<f64> {
        self.inner.distance_km(&other.inner)
    }

    fn __repr__(&self) -> String {
        let coords = match (self.inner.latitude, self.inner.longitude) {
            (Some(lat), Some(lon)) => format!(", {lat:.4},{lon:.4}"),
            _ => String::new(),
        };
        let city = self
            .inner
            .city
            .as_deref()
            .map(|c| format!("/{c}"))
            .unwrap_or_default();
        format!("GeoLocation({}{}{})", self.inner.country_code, city, coords)
    }
}

/// Action context passed from Python to the Rust gate.
#[pyclass]
#[derive(Clone)]
struct ActionContext {
    inner: core::ActionContext,
}

#[pymethods]
impl ActionContext {
    #[new]
    #[pyo3(signature = (
        principal_id,
        principal_kind,
        action_name,
        roles=vec![],
        resource=None,
        params=None,
        ip=None,
        session_id=None,
        current_geo=None,
        origin_geo=None,
        origin_ip=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        principal_id: String,
        principal_kind: String,
        action_name: String,
        roles: Vec<String>,
        resource: Option<String>,
        params: Option<HashMap<String, f64>>,
        ip: Option<String>,
        session_id: Option<String>,
        current_geo: Option<GeoLocation>,
        origin_geo: Option<GeoLocation>,
        origin_ip: Option<String>,
    ) -> PyResult<Self> {
        let kind = match principal_kind.as_str() {
            "user" => core::PrincipalKind::User,
            "agent" => core::PrincipalKind::Agent,
            "service" => core::PrincipalKind::Service,
            "scheduler" => core::PrincipalKind::Scheduler,
            "external" => core::PrincipalKind::External,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown principal kind: {other}"
                )))
            }
        };

        let principal = core::Principal {
            id: principal_id,
            kind,
            roles,
            credentials_issued_at: chrono::Utc::now(),
            display_name: None,
        };

        let mut action = core::ActionDescriptor::new(action_name);
        if let Some(r) = resource {
            action = action.with_resource(r);
        }
        if let Some(p) = params {
            for (k, v) in p {
                action.params.insert(k, serde_json::json!(v));
            }
        }

        let mut session = core::SessionState::new();
        if let Some(sid) = session_id {
            session.session_id =
                uuid::Uuid::parse_str(&sid).unwrap_or_else(|_| uuid::Uuid::new_v4());
        }

        let mut env = core::EnvContext::default();
        if let Some(ip_str) = ip {
            env.ip = ip_str.parse().ok();
            session.origin_ip = env.ip;
        }
        // Explicit `origin_ip` overrides the `ip`-derived session origin —
        // lets callers model "session started from IP X, request coming
        // from IP Y" which is how geo-drift scenarios actually look.
        if let Some(origin_str) = origin_ip {
            session.origin_ip = origin_str.parse().ok();
        }

        // Geo — current on EnvContext, origin on SessionState.
        // Tolerant-mode GeoLocationDrift needs both sides set + both with lat/lon.
        if let Some(g) = current_geo {
            env.geo = Some(g.inner);
        }
        if let Some(g) = origin_geo {
            session.origin_geo = Some(g.inner);
        }

        Ok(Self {
            inner: core::ActionContext::new(principal, action, session, env),
        })
    }

    /// Add a string parameter for policy/invariant checks.
    fn with_param(&mut self, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let json_val = if let Ok(v) = value.extract::<f64>() {
            serde_json::json!(v)
        } else if let Ok(v) = value.extract::<String>() {
            serde_json::json!(v)
        } else if let Ok(v) = value.extract::<bool>() {
            serde_json::json!(v)
        } else {
            serde_json::json!(value.str()?.to_string())
        };
        self.inner.action.params.insert(key, json_val);
        Ok(())
    }
}

/// The Kavach gate — all evaluation runs in Rust.
#[pyclass]
struct Gate {
    inner: Arc<core::Gate>,
    /// Held alongside the gate so `reload(policy_toml)` can swap the
    /// PolicySet without rebuilding the gate. The same `Arc` is also
    /// inside `inner.evaluators` (it implements `Evaluator`).
    policy_engine: Arc<core::PolicyEngine>,
}

#[pymethods]
impl Gate {
    /// Create a gate from a TOML policy string.
    ///
    /// Args:
    ///     policy_toml: TOML string containing [[policy]] definitions
    ///     invariants: List of (name, field, max_value) tuples for param_max invariants
    ///     observe_only: If True, log but never block (Phase 1 rollout)
    ///     max_session_actions: Hard limit on actions per session (optional)
    ///     enable_drift: Include the built-in drift evaluator (default True)
    ///     token_signer: Optional `PqTokenSigner` — when set, every Permit
    ///         carries a signed envelope in `verdict.signature`. If signing
    ///         fails the gate fails closed (Refuse).
    ///     geo_drift_max_km: Optional tolerance (km) for `GeoLocationDrift`.
    ///         When unset (default), any mid-session IP change is a Violation.
    ///         When set, an IP change within this distance downgrades to a
    ///         Warning — but only when both `current_geo` and `origin_geo`
    ///         carry latitude/longitude. Missing geo with a threshold set
    ///         fails closed (Violation).
    #[new]
    #[pyo3(signature = (
        policy_toml,
        invariants=vec![],
        observe_only=false,
        max_session_actions=None,
        enable_drift=true,
        token_signer=None,
        geo_drift_max_km=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        policy_toml: &str,
        invariants: Vec<(String, String, f64)>,
        observe_only: bool,
        max_session_actions: Option<u64>,
        enable_drift: bool,
        token_signer: Option<PqTokenSigner>,
        geo_drift_max_km: Option<f64>,
    ) -> PyResult<Self> {
        let policies = core::PolicySet::from_toml(policy_toml)
            .map_err(|e| PyValueError::new_err(format!("policy parse error: {e}")))?;

        let policy_engine = Arc::new(core::PolicyEngine::new(policies));

        let mut evaluators: Vec<Arc<dyn Evaluator>> = vec![policy_engine.clone()];

        // Drift detection — swap the default strict GeoLocationDrift for a
        // tolerant one when geo_drift_max_km is set.
        if enable_drift {
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

        // Invariants
        let mut inv_list: Vec<core::Invariant> = invariants
            .into_iter()
            .map(|(name, field, max)| core::Invariant::param_max(name, field, max))
            .collect();

        if let Some(max_actions) = max_session_actions {
            inv_list.push(core::Invariant::max_actions_per_session(
                "max_session_actions",
                max_actions,
            ));
        }

        if !inv_list.is_empty() {
            evaluators.push(Arc::new(core::InvariantSet::new(inv_list)));
        }

        let config = core::GateConfig {
            observe_only,
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
    /// Parse errors raise `ValueError` and the previous good set stays in
    /// place — never wipe a running engine on a bad reload. An empty TOML
    /// is intentionally valid (= default-deny everything; useful as a
    /// kill-switch).
    fn reload(&self, policy_toml: &str) -> PyResult<()> {
        let policies = core::PolicySet::from_toml(policy_toml)
            .map_err(|e| PyValueError::new_err(format!("policy parse error: {e}")))?;
        self.policy_engine.reload(policies);
        Ok(())
    }

    /// Evaluate an action context. Returns a Verdict.
    ///
    /// This crosses into Rust for all evaluation logic:
    /// policy matching, drift detection, invariant checks.
    fn evaluate(&self, ctx: &ActionContext) -> Verdict {
        let gate = self.inner.clone();
        let inner_ctx = ctx.inner.clone();
        let result = runtime().block_on(async move { gate.evaluate(&inner_ctx).await });
        result.into()
    }

    /// Number of evaluators in the chain.
    #[getter]
    fn evaluator_count(&self) -> usize {
        self.inner.evaluator_count()
    }
}

// ─── Audit chain ─────────────────────────────────────────────────

/// A single audit-log entry. Pass these to [`SignedAuditChain.append`].
///
/// Required fields: `principal_id`, `action_name`, `verdict`
/// (`"permit"` / `"refuse"` / `"invalidate"`), and `verdict_detail`.
/// All other fields default sensibly: a fresh UUID for `id` /
/// `evaluation_id` / `session_id`, and `chrono::Utc::now()` for
/// `timestamp`.
#[pyclass]
#[derive(Clone)]
struct AuditEntry {
    inner: CoreAuditEntry,
}

#[pymethods]
impl AuditEntry {
    #[new]
    #[pyo3(signature = (
        principal_id,
        action_name,
        verdict,
        verdict_detail,
        resource=None,
        decided_by=None,
        ip=None,
        evaluation_id=None,
        session_id=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        principal_id: String,
        action_name: String,
        verdict: String,
        verdict_detail: String,
        resource: Option<String>,
        decided_by: Option<String>,
        ip: Option<String>,
        evaluation_id: Option<String>,
        session_id: Option<String>,
    ) -> PyResult<Self> {
        match verdict.as_str() {
            "permit" | "refuse" | "invalidate" => {}
            other => {
                return Err(PyValueError::new_err(format!(
                    "verdict must be 'permit'|'refuse'|'invalidate', got '{other}'"
                )));
            }
        }
        let evaluation_id = match evaluation_id {
            Some(s) => Uuid::parse_str(&s)
                .map_err(|e| PyValueError::new_err(format!("evaluation_id not a UUID: {e}")))?,
            None => Uuid::new_v4(),
        };
        let session_id = match session_id {
            Some(s) => Uuid::parse_str(&s)
                .map_err(|e| PyValueError::new_err(format!("session_id not a UUID: {e}")))?,
            None => Uuid::new_v4(),
        };
        Ok(Self {
            inner: CoreAuditEntry {
                id: Uuid::new_v4(),
                evaluation_id,
                timestamp: Utc::now(),
                principal_id,
                action_name,
                resource,
                verdict,
                verdict_detail,
                decided_by,
                session_id,
                ip,
                context_snapshot: None,
            },
        })
    }

    #[getter]
    fn id(&self) -> String {
        self.inner.id.to_string()
    }

    #[getter]
    fn principal_id(&self) -> String {
        self.inner.principal_id.clone()
    }

    #[getter]
    fn action_name(&self) -> String {
        self.inner.action_name.clone()
    }

    #[getter]
    fn verdict(&self) -> String {
        self.inner.verdict.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "AuditEntry(principal={}, action={}, verdict={})",
            self.inner.principal_id, self.inner.action_name, self.inner.verdict
        )
    }
}

/// A tamper-evident PQ-signed audit log.
///
/// Each appended entry is signed (ML-DSA-65, plus Ed25519 in hybrid mode)
/// and linked to the previous entry via a SHA-256 hash chain. Reordering,
/// inserting, deleting, mutating, or splicing across modes is detected at
/// `verify` time.
///
/// Construct with a `KavachKeyPair` and a `hybrid` flag (defaults to True).
/// The verifier's mode must match the chain's mode — `verify` / `verify_jsonl`
/// refuse to silently verify a hybrid chain under a PQ-only verifier (and
/// vice versa), closing the signature-downgrade surface.
#[pyclass]
struct SignedAuditChain {
    inner: Arc<SignedAuditChainInner>,
    is_hybrid: bool,
}

#[pymethods]
impl SignedAuditChain {
    #[new]
    #[pyo3(signature = (keypair, hybrid=true))]
    fn new(keypair: &KavachKeyPair, hybrid: bool) -> Self {
        let signer = PqSigner::from_keypair(&keypair.inner, hybrid);
        Self {
            inner: Arc::new(SignedAuditChainInner::new(signer)),
            is_hybrid: hybrid,
        }
    }

    /// Append an audit entry. Returns the new chain length.
    fn append(&self, entry: &AuditEntry) -> PyResult<u64> {
        self.inner
            .append(&entry.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("append failed: {e}")))?;
        Ok(self.inner.len())
    }

    #[getter]
    fn length(&self) -> u64 {
        self.inner.len()
    }

    fn __len__(&self) -> usize {
        self.inner.len() as usize
    }

    #[getter]
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[getter]
    fn head_hash(&self) -> String {
        self.inner.head_hash()
    }

    /// Whether this chain was built with hybrid (ML-DSA + Ed25519) signing.
    #[getter]
    fn is_hybrid(&self) -> bool {
        self.is_hybrid
    }

    /// Verify all entries in-place using the supplied public-key bundle.
    /// Raises `ValueError` on any tamper / signature mismatch / chain break /
    /// verifier-mode mismatch.
    fn verify(&self, public_keys: &PublicKeyBundle) -> PyResult<()> {
        let verifier = PqVerifier::from_bundle(&public_keys.inner, self.is_hybrid);
        let entries = self.inner.entries();
        pq_audit::verify_chain(&entries, &verifier)
            .map_err(|e| PyValueError::new_err(format!("audit chain verification failed: {e}")))
    }

    /// Export the chain as newline-delimited JSON bytes (`.jsonl`).
    /// One `SignedAuditEntry` per line. Trailing newline included.
    fn export_jsonl<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let buf = pq_audit::export_jsonl(&self.inner.entries())
            .map_err(|err| PyRuntimeError::new_err(format!("export: {err}")))?;
        Ok(PyBytes::new_bound(py, &buf))
    }

    /// Verify a previously-exported JSONL chain against the supplied
    /// public-key bundle. Returns the number of verified entries.
    ///
    /// The chain's mode is inferred from the blob. When `hybrid` is passed
    /// explicitly it acts as a strict assertion: an expectation mismatch
    /// raises `ValueError` *before* any crypto is attempted, preventing a
    /// caller from silently verifying a hybrid chain with a PQ-only
    /// verifier (or vice versa). Pass `hybrid=None` to trust the blob.
    ///
    /// Raises `ValueError` on tamper / signature mismatch / chain break /
    /// mode mismatch.
    #[staticmethod]
    #[pyo3(signature = (data, public_keys, hybrid=None))]
    fn verify_jsonl(
        data: &[u8],
        public_keys: &PublicKeyBundle,
        hybrid: Option<bool>,
    ) -> PyResult<usize> {
        let entries = pq_audit::parse_jsonl(data)
            .map_err(|e| PyValueError::new_err(format!("audit chain parse failed: {e}")))?;
        let detected = pq_audit::detect_mode(&entries)
            .map_err(|e| PyValueError::new_err(format!("audit chain parse failed: {e}")))?;
        let effective = match (hybrid, detected) {
            (Some(expected), Some(chain_mode)) if expected != chain_mode.is_hybrid() => {
                return Err(PyValueError::new_err(format!(
                    "audit chain mode mismatch: caller expected hybrid={expected} but chain is {chain_mode}"
                )));
            }
            (Some(expected), _) => expected,
            (None, Some(chain_mode)) => chain_mode.is_hybrid(),
            // Empty chain + caller didn't specify → no crypto to do; trivially OK.
            (None, None) => return Ok(0),
        };
        let verifier = PqVerifier::from_bundle(&public_keys.inner, effective);
        pq_audit::verify_chain(&entries, &verifier)
            .map_err(|e| PyValueError::new_err(format!("audit chain verification failed: {e}")))?;
        Ok(entries.len())
    }
}

// ─── Secure channel ──────────────────────────────────────────────

fn parse_encrypted_payload(data: &[u8]) -> PyResult<EncryptedPayload> {
    serde_json::from_slice(data)
        .map_err(|e| PyValueError::new_err(format!("sealed payload parse failed: {e}")))
}

fn serialize_encrypted_payload(payload: &EncryptedPayload) -> PyResult<Vec<u8>> {
    serde_json::to_vec(payload)
        .map_err(|e| PyRuntimeError::new_err(format!("sealed payload serialize failed: {e}")))
}

/// A hybrid-encrypted, PQ-signed channel between two Kavach services.
///
/// Each side constructs a channel from their own [`KavachKeyPair`] (secret
/// material, never shared) and the remote party's [`PublicKeyBundle`]
/// (safe to share). Sealed payloads are opaque `bytes` that carry the
/// full envelope (ML-KEM ciphertext, ephemeral X25519 public key, AEAD
/// nonce + ciphertext, recipient key id) — store or transmit them
/// anywhere.
///
/// Three flows:
///
/// - `send_signed(data, context_id, correlation_id) -> bytes` /
///   `receive_signed(sealed, expected_context_id) -> bytes` — sign +
///   encrypt, with replay protection and context binding. Rejects on
///   tamper, wrong recipient, replay, or context mismatch.
/// - `send_data(data) -> bytes` / `receive_data(sealed) -> bytes` —
///   encryption only, no signing.
/// - `local_key_id` / `remote_key_id` for diagnostics.
#[pyclass]
struct SecureChannel {
    inner: Arc<SecureChannelInner>,
}

#[pymethods]
impl SecureChannel {
    /// Construct a channel.
    ///
    /// Args:
    ///     local_keypair: this side's full [`KavachKeyPair`] (secret keys).
    ///     remote_public_keys: remote side's [`PublicKeyBundle`].
    #[new]
    fn new(local_keypair: &KavachKeyPair, remote_public_keys: &PublicKeyBundle) -> Self {
        let inner = SecureChannelInner::establish_from_bundle(
            &local_keypair.inner,
            &remote_public_keys.inner,
        );
        Self {
            inner: Arc::new(inner),
        }
    }

    #[getter]
    fn local_key_id(&self) -> String {
        self.inner.local_key_id().to_string()
    }

    #[getter]
    fn remote_key_id(&self) -> String {
        self.inner.remote_key_id().to_string()
    }

    /// Sign `data` (with a caller-defined `context_id` + `correlation_id`
    /// binding) and encrypt it for the remote party. Returns opaque
    /// sealed bytes — pass them to the remote side's
    /// `receive_signed(sealed, expected_context_id)`.
    fn send_signed<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        context_id: &str,
        correlation_id: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let sealed = self
            .inner
            .send_signed(data, context_id, correlation_id)
            .map_err(|e| PyRuntimeError::new_err(format!("send_signed failed: {e}")))?;
        let bytes = serialize_encrypted_payload(&sealed)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Decrypt + signature/replay/context-verify a sealed payload from
    /// the remote party. Raises `ValueError` on any failure (decrypt,
    /// tamper, replay, wrong context, wrong recipient).
    fn receive_signed<'py>(
        &self,
        py: Python<'py>,
        sealed: &[u8],
        expected_context_id: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let payload = parse_encrypted_payload(sealed)?;
        let plaintext = self
            .inner
            .receive_signed(&payload, expected_context_id)
            .map_err(|e| PyValueError::new_err(format!("receive_signed failed: {e}")))?;
        Ok(PyBytes::new_bound(py, &plaintext))
    }

    /// Encrypt `data` for the remote party (no signing, no replay
    /// tracking). Use `send_signed` when you need integrity +
    /// authenticity + replay protection.
    fn send_data<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let sealed = self
            .inner
            .send_data(data)
            .map_err(|e| PyRuntimeError::new_err(format!("send_data failed: {e}")))?;
        let bytes = serialize_encrypted_payload(&sealed)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Decrypt a sealed payload. Raises `ValueError` on any failure.
    fn receive_data<'py>(&self, py: Python<'py>, sealed: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let payload = parse_encrypted_payload(sealed)?;
        let plaintext = self
            .inner
            .receive_data(&payload)
            .map_err(|e| PyValueError::new_err(format!("receive_data failed: {e}")))?;
        Ok(PyBytes::new_bound(py, &plaintext))
    }

    fn __repr__(&self) -> String {
        format!(
            "SecureChannel(local={}, remote={})",
            self.inner.local_key_id(),
            self.inner.remote_key_id()
        )
    }
}

// ─── Public-key directory ────────────────────────────────────────

/// Backing store for a [`PublicKeyDirectory`] — tracks the concrete
/// implementation so we can still offer type-specific ops (insert /
/// remove for in-memory, reload for file-backed) on top of the
/// type-erased trait object used for `fetch`.
enum DirectoryKind {
    InMemory(Arc<InMemoryPublicKeyDirectoryInner>),
    File(Arc<FilePublicKeyDirectoryInner>),
}

/// Public-key distribution surface for downstream verifiers.
///
/// A directory resolves a `key_id` (stamped into every signed token
/// envelope) to the matching [`PublicKeyBundle`]. Three backings:
///
/// - `PublicKeyDirectory.in_memory(bundles=[...])` — programmatic
///   store. Mutable via `insert` / `remove`. Good for tests and for
///   deployments that build the directory from code at startup.
/// - `PublicKeyDirectory.from_file(path)` — loads an **unsigned**
///   JSON array of bundles from disk. Safe only when the file is
///   local to the verifier (no cross-host trust implied).
/// - `PublicKeyDirectory.from_signed_file(path, root_ml_dsa_verifying_key)`
///   — loads a root-signed manifest (ML-DSA-65 signature over the
///   bundle JSON). Any manifest whose signature does not verify
///   against `root_ml_dsa_verifying_key` is **rejected at load time**.
///   This is the production-grade cross-host path.
///
/// Any error (`NotFound`, `BackendUnavailable`, `RootSignatureInvalid`,
/// `Corrupt`) on `fetch` raises `ValueError` — fail-closed so that
/// unverifiable tokens are refused by downstream verifiers.
#[pyclass]
struct PublicKeyDirectory {
    inner: Arc<dyn PublicKeyDirectoryTrait>,
    kind: DirectoryKind,
}

#[pymethods]
impl PublicKeyDirectory {
    /// Build an in-memory directory, optionally pre-populated.
    #[classmethod]
    #[pyo3(signature = (bundles=vec![]))]
    fn in_memory(_cls: &Bound<'_, pyo3::types::PyType>, bundles: Vec<PublicKeyBundle>) -> Self {
        let raw: Vec<PublicKeyBundleInner> = bundles.into_iter().map(|b| b.inner).collect();
        let dir = Arc::new(InMemoryPublicKeyDirectoryInner::from_bundles(raw));
        Self {
            inner: dir.clone(),
            kind: DirectoryKind::InMemory(dir),
        }
    }

    /// Load an **unsigned** bundle array from a JSON file on disk.
    #[classmethod]
    fn from_file(_cls: &Bound<'_, pyo3::types::PyType>, path: &str) -> PyResult<Self> {
        let dir = FilePublicKeyDirectoryInner::load_unsigned(path)
            .map_err(|e| PyValueError::new_err(format!("directory load: {e}")))?;
        let arc = Arc::new(dir);
        Ok(Self {
            inner: arc.clone(),
            kind: DirectoryKind::File(arc),
        })
    }

    /// Load a **root-signed** manifest. The manifest's ML-DSA-65
    /// signature over its bundle JSON must verify against
    /// `root_ml_dsa_verifying_key`; anything else raises `ValueError`.
    #[classmethod]
    fn from_signed_file(
        _cls: &Bound<'_, pyo3::types::PyType>,
        path: &str,
        root_ml_dsa_verifying_key: Vec<u8>,
    ) -> PyResult<Self> {
        let dir = FilePublicKeyDirectoryInner::load_signed(path, root_ml_dsa_verifying_key)
            .map_err(|e| PyValueError::new_err(format!("directory load: {e}")))?;
        let arc = Arc::new(dir);
        Ok(Self {
            inner: arc.clone(),
            kind: DirectoryKind::File(arc),
        })
    }

    /// Fetch a bundle by `key_id`. Raises `ValueError` on
    /// NotFound / BackendUnavailable / Corrupt — the caller is
    /// expected to refuse downstream.
    fn fetch(&self, key_id: &str) -> PyResult<PublicKeyBundle> {
        let dir = self.inner.clone();
        let kid = key_id.to_string();
        let bundle = runtime()
            .block_on(async move { dir.fetch(&kid).await })
            .map_err(|e| PyValueError::new_err(format!("directory fetch: {e}")))?;
        Ok(PublicKeyBundle { inner: bundle })
    }

    /// Insert (or overwrite) a bundle. Only valid on in-memory directories;
    /// raises `ValueError` on file-backed ones.
    fn insert(&self, bundle: PublicKeyBundle) -> PyResult<()> {
        match &self.kind {
            DirectoryKind::InMemory(dir) => {
                dir.insert(bundle.inner);
                Ok(())
            }
            DirectoryKind::File(_) => Err(PyValueError::new_err(
                "insert only supported on in-memory directories",
            )),
        }
    }

    /// Remove a bundle. Only valid on in-memory directories.
    fn remove(&self, key_id: &str) -> PyResult<bool> {
        match &self.kind {
            DirectoryKind::InMemory(dir) => Ok(dir.remove(key_id).is_some()),
            DirectoryKind::File(_) => Err(PyValueError::new_err(
                "remove only supported on in-memory directories",
            )),
        }
    }

    /// Re-read the underlying file. Only valid on file-backed directories
    /// (no-op on in-memory). Parse / signature errors raise `ValueError`;
    /// the previous known-good cache is preserved on error.
    fn reload(&self) -> PyResult<()> {
        match &self.kind {
            DirectoryKind::File(f) => f
                .reload()
                .map_err(|e| PyValueError::new_err(format!("directory reload: {e}"))),
            DirectoryKind::InMemory(_) => Ok(()),
        }
    }

    #[getter]
    fn length(&self) -> usize {
        match &self.kind {
            DirectoryKind::InMemory(d) => d.len(),
            DirectoryKind::File(d) => d.len(),
        }
    }

    #[getter]
    fn is_empty(&self) -> bool {
        self.length() == 0
    }

    fn __len__(&self) -> usize {
        self.length()
    }

    /// Build the JSON bytes of an unsigned bundle array suitable for
    /// writing to disk and later loading with `from_file(...)`.
    #[staticmethod]
    fn build_unsigned_manifest<'py>(
        py: Python<'py>,
        bundles: Vec<PublicKeyBundle>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let raw: Vec<PublicKeyBundleInner> = bundles.into_iter().map(|b| b.inner).collect();
        let bytes = serde_json::to_vec(&raw)
            .map_err(|e| PyRuntimeError::new_err(format!("serialize bundles: {e}")))?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Build the JSON bytes of a **root-signed** manifest suitable for
    /// writing to disk and later loading with `from_signed_file(...)`.
    ///
    /// `ml_dsa_signing_key` is the 32-byte ML-DSA-65 seed of the root
    /// authority (never distributed). The matching verifying key must
    /// be pinned on every verifier as `root_ml_dsa_verifying_key`.
    #[staticmethod]
    fn build_signed_manifest<'py>(
        py: Python<'py>,
        bundles: Vec<PublicKeyBundle>,
        ml_dsa_signing_key: Vec<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let raw: Vec<PublicKeyBundleInner> = bundles.into_iter().map(|b| b.inner).collect();
        let manifest =
            FilePublicKeyDirectoryInner::build_signed_manifest(&raw, &ml_dsa_signing_key)
                .map_err(|e| PyRuntimeError::new_err(format!("build manifest: {e}")))?;
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|e| PyRuntimeError::new_err(format!("serialize manifest: {e}")))?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    fn __repr__(&self) -> String {
        let kind = match &self.kind {
            DirectoryKind::InMemory(_) => "in_memory",
            DirectoryKind::File(_) => "file",
        };
        format!("PublicKeyDirectory(kind={kind}, length={})", self.length())
    }
}

/// Verifies `PermitToken` signatures by looking up the matching
/// [`PublicKeyBundle`] in a [`PublicKeyDirectory`] — the `key_id`
/// comes from the token envelope, so rotated/distributed keys just
/// work as long as the directory is kept fresh.
///
/// `hybrid=True` (default) enforces ML-DSA-65 + Ed25519 and rejects
/// PQ-only envelopes (downgrade guard). `hybrid=False` rejects
/// hybrid envelopes.
///
/// Any failure (envelope parse, algorithm mismatch, directory miss,
/// signature invalid) raises `ValueError` — fail-closed.
#[pyclass]
struct DirectoryTokenVerifier {
    inner: Arc<DirectoryTokenVerifierInner>,
}

#[pymethods]
impl DirectoryTokenVerifier {
    #[new]
    #[pyo3(signature = (directory, hybrid=true))]
    fn new(directory: &PublicKeyDirectory, hybrid: bool) -> Self {
        let inner = if hybrid {
            DirectoryTokenVerifierInner::hybrid(directory.inner.clone())
        } else {
            DirectoryTokenVerifierInner::pq_only(directory.inner.clone())
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    fn verify(&self, token: &PermitToken, signature: &[u8]) -> PyResult<()> {
        let verifier = self.inner.clone();
        let tok = token.inner.clone();
        let sig = signature.to_vec();
        runtime()
            .block_on(async move { verifier.verify(&tok, &sig).await })
            .map_err(|e| PyValueError::new_err(format!("verify failed: {e}")))
    }
}

// ─── Python module definition ────────────────────────────────────

/// Kavach engine — compiled Rust core exposed to Python.
///
/// All gate evaluation runs natively in Rust for performance
/// and type-safety guarantees.
#[pymodule]
fn _kavach_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Gate>()?;
    m.add_class::<ActionContext>()?;
    m.add_class::<GeoLocation>()?;
    m.add_class::<Verdict>()?;
    m.add_class::<PermitToken>()?;
    m.add_class::<PqTokenSigner>()?;
    m.add_class::<KavachKeyPair>()?;
    m.add_class::<PublicKeyBundle>()?;
    m.add_class::<AuditEntry>()?;
    m.add_class::<SignedAuditChain>()?;
    m.add_class::<SecureChannel>()?;
    m.add_class::<PublicKeyDirectory>()?;
    m.add_class::<DirectoryTokenVerifier>()?;
    Ok(())
}
