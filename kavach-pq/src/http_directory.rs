//! HTTP-backed [`PublicKeyDirectory`] with ETag-aware caching.
//!
//! Fetches a `Vec<PublicKeyBundle>` (unsigned) or a
//! [`SignedDirectoryManifest`] (signed) from a URL and caches the result.
//! Subsequent refreshes send `If-None-Match`; a `304 Not Modified` response
//! keeps the existing cache without re-transferring the body.
//!
//! Gated behind the `http` feature flag. Enable with:
//!
//! ```toml
//! kavach-pq = { version = "0.1", features = ["http"] }
//! ```
//!
//! ## Trust model
//!
//! Same as [`FilePublicKeyDirectory`](super::directory::FilePublicKeyDirectory):
//! cross-host distribution **must** use a signed manifest with a pinned
//! ML-DSA-65 root verifying key. An attacker who MITMs the HTTP endpoint
//! cannot forge bundles without the root signing key. Unsigned mode trusts
//! the server entirely and is only appropriate for dev/testing.
//!
//! ## Failure semantics
//!
//! - **Cold cache, fetch fails** → `BackendUnavailable`. Fail closed.
//! - **Warm cache, fetch fails** → stale cache served, warning logged.
//!   Better to verify against a recently-good bundle than refuse the whole
//!   system because the key server is briefly down. The warning surfaces
//!   the outage to monitoring.
//! - **304 Not Modified** → cache served without refresh, `last_fetched`
//!   advances. This is the ETag happy path.
//! - **Invalid root signature** → `RootSignatureInvalid`. Fail closed.
//!   Cache is **not** replaced with the bad payload.

use crate::directory::{KeyDirectoryError, PublicKeyDirectory, SignedDirectoryManifest};
use crate::keys::{load_ml_dsa_verifying_key, PublicKeyBundle};
use async_trait::async_trait;
use hybrid_array::Array;
use ml_dsa::signature::Verifier as MlDsaVerifierTrait;
use ml_dsa::{EncodedSignature, MlDsa65, Signature as MlDsaSignature};
use reqwest::header::{HeaderMap, HeaderValue, ETAG, IF_NONE_MATCH};
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Default cache TTL, fetch at most every 5 minutes.
const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Default HTTP client request timeout. Short enough that a hanging key
/// server doesn't block every token verification for minutes.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP-backed public key directory with ETag caching.
///
/// Clone is cheap, the inner state is `Arc`-wrapped so clones share the
/// same cache + HTTP client.
#[derive(Clone)]
pub struct HttpPublicKeyDirectory {
    inner: Arc<Inner>,
}

struct Inner {
    url: String,
    root_verifying_key: Option<Vec<u8>>,
    ttl: Duration,
    client: Client,
    cache: RwLock<CacheState>,
}

struct CacheState {
    /// `None` until the first successful fetch.
    bundles: Option<HashMap<String, PublicKeyBundle>>,
    /// ETag from the most recent 200 OK. Sent back as `If-None-Match` on
    /// subsequent fetches.
    etag: Option<String>,
    /// When the cache was last refreshed (either by 200 OK or 304 Not Modified).
    last_fetched: Option<Instant>,
}

impl HttpPublicKeyDirectory {
    /// Build a directory that loads a **signed** manifest from `url`.
    ///
    /// `root_verifying_key` is the ML-DSA-65 encoded verifying key of the
    /// root authority. Any manifest whose signature doesn't verify against
    /// it is rejected, cache is left unchanged.
    ///
    /// The first fetch happens lazily on the first `fetch(key_id)` call, so
    /// construction never performs I/O and cannot fail on network issues.
    pub fn signed(url: impl Into<String>, root_verifying_key: Vec<u8>) -> Self {
        Self::build(url.into(), Some(root_verifying_key), DEFAULT_TTL, default_client())
    }

    /// Build an **unsigned** directory. Only safe when the transport is
    /// fully trusted (localhost dev server, TLS + mTLS against an internal
    /// issuer, etc.). Cross-host production should always use `signed`.
    pub fn unsigned(url: impl Into<String>) -> Self {
        Self::build(url.into(), None, DEFAULT_TTL, default_client())
    }

    /// Override the cache TTL. Shorter = fresher at the cost of more
    /// network round-trips; most of those will be cheap `304 Not Modified`
    /// responses thanks to the ETag.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        // We hold the only Arc at this point (builder chain on just-constructed
        // self), so get_mut is safe. If a caller clones before configuring,
        // this degrades gracefully to a no-op by rebuilding Inner.
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.ttl = ttl;
            self
        } else {
            Self::build(
                self.inner.url.clone(),
                self.inner.root_verifying_key.clone(),
                ttl,
                self.inner.client.clone(),
            )
        }
    }

    /// Inject a pre-configured `reqwest::Client`, useful for custom
    /// timeouts, TLS roots, authentication headers, or proxies.
    pub fn with_http_client(mut self, client: Client) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.client = client;
            self
        } else {
            Self::build(
                self.inner.url.clone(),
                self.inner.root_verifying_key.clone(),
                self.inner.ttl,
                client,
            )
        }
    }

    fn build(
        url: String,
        root_verifying_key: Option<Vec<u8>>,
        ttl: Duration,
        client: Client,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                url,
                root_verifying_key,
                ttl,
                client,
                cache: RwLock::new(CacheState {
                    bundles: None,
                    etag: None,
                    last_fetched: None,
                }),
            }),
        }
    }

    /// Force an immediate refresh regardless of TTL. If the refresh errors,
    /// the previous cache is preserved and the error returned.
    pub async fn reload(&self) -> Result<(), KeyDirectoryError> {
        self.refresh().await
    }

    /// Run the HTTP fetch and update the cache.
    ///
    /// - 200 OK → replace bundles + etag, update `last_fetched`.
    /// - 304 Not Modified → keep bundles + etag, update `last_fetched`.
    /// - Any other response or network error → `BackendUnavailable`,
    ///   cache left unchanged.
    async fn refresh(&self) -> Result<(), KeyDirectoryError> {
        // Snapshot the current etag so we don't hold the lock across await.
        let existing_etag = {
            let guard = self.inner.cache.read().await;
            guard.etag.clone()
        };

        let mut headers = HeaderMap::new();
        if let Some(tag) = &existing_etag {
            if let Ok(value) = HeaderValue::from_str(tag) {
                headers.insert(IF_NONE_MATCH, value);
            }
        }

        let response = self
            .inner
            .client
            .get(&self.inner.url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| KeyDirectoryError::BackendUnavailable(format!("GET {}: {e}", self.inner.url)))?;

        match response.status() {
            StatusCode::NOT_MODIFIED => {
                let mut guard = self.inner.cache.write().await;
                guard.last_fetched = Some(Instant::now());
                Ok(())
            }
            StatusCode::OK => {
                let new_etag = response
                    .headers()
                    .get(ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let body = response.bytes().await.map_err(|e| {
                    KeyDirectoryError::BackendUnavailable(format!("read body: {e}"))
                })?;

                let bundles = parse_bundles(&body, self.inner.root_verifying_key.as_deref())?;
                let mut map = HashMap::with_capacity(bundles.len());
                for bundle in bundles {
                    map.insert(bundle.id.clone(), bundle);
                }

                let mut guard = self.inner.cache.write().await;
                guard.bundles = Some(map);
                guard.etag = new_etag;
                guard.last_fetched = Some(Instant::now());
                Ok(())
            }
            other => Err(KeyDirectoryError::BackendUnavailable(format!(
                "GET {} returned {}",
                self.inner.url, other
            ))),
        }
    }

    /// Is the current cache fresh relative to the configured TTL?
    async fn cache_is_fresh(&self) -> bool {
        let guard = self.inner.cache.read().await;
        match (guard.bundles.as_ref(), guard.last_fetched) {
            (Some(_), Some(ts)) => ts.elapsed() < self.inner.ttl,
            _ => false,
        }
    }

    /// Look up a bundle in the cache without refreshing. Returns `None` if
    /// the cache is cold or the key isn't present.
    async fn lookup_in_cache(&self, key_id: &str) -> Option<PublicKeyBundle> {
        let guard = self.inner.cache.read().await;
        guard.bundles.as_ref().and_then(|m| m.get(key_id).cloned())
    }

    /// Number of bundles currently cached. Zero if cold.
    pub async fn cached_len(&self) -> usize {
        let guard = self.inner.cache.read().await;
        guard.bundles.as_ref().map(|m| m.len()).unwrap_or(0)
    }
}

fn default_client() -> Client {
    Client::builder()
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .build()
        .expect("reqwest Client::build with default settings never fails")
}

fn parse_bundles(
    body: &[u8],
    root_verifying_key: Option<&[u8]>,
) -> Result<Vec<PublicKeyBundle>, KeyDirectoryError> {
    match root_verifying_key {
        Some(root_vk) => {
            let manifest: SignedDirectoryManifest = serde_json::from_slice(body)
                .map_err(|e| KeyDirectoryError::Corrupt(format!("manifest: {e}")))?;
            verify_root_signature(root_vk, manifest.bundles_json.as_bytes(), &manifest.signature)?;
            serde_json::from_str::<Vec<PublicKeyBundle>>(&manifest.bundles_json)
                .map_err(|e| KeyDirectoryError::Corrupt(format!("bundles_json: {e}")))
        }
        None => serde_json::from_slice::<Vec<PublicKeyBundle>>(body)
            .map_err(|e| KeyDirectoryError::Corrupt(format!("bundles: {e}"))),
    }
}

fn verify_root_signature(
    root_vk_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), KeyDirectoryError> {
    let vk = load_ml_dsa_verifying_key(root_vk_bytes)
        .map_err(|e| KeyDirectoryError::Corrupt(format!("root VK: {e}")))?;
    let encoded: EncodedSignature<MlDsa65> =
        Array::try_from(signature_bytes).map_err(|_| KeyDirectoryError::RootSignatureInvalid)?;
    let sig = MlDsaSignature::<MlDsa65>::decode(&encoded)
        .ok_or(KeyDirectoryError::RootSignatureInvalid)?;
    vk.verify(message, &sig)
        .map_err(|_| KeyDirectoryError::RootSignatureInvalid)
}

#[async_trait]
impl PublicKeyDirectory for HttpPublicKeyDirectory {
    async fn fetch(&self, key_id: &str) -> Result<PublicKeyBundle, KeyDirectoryError> {
        // Fast path: cache is fresh. Return directly or NotFound.
        if self.cache_is_fresh().await {
            return self
                .lookup_in_cache(key_id)
                .await
                .ok_or_else(|| KeyDirectoryError::NotFound(key_id.to_string()));
        }

        // Cache is cold or stale, try to refresh.
        match self.refresh().await {
            Ok(()) => self
                .lookup_in_cache(key_id)
                .await
                .ok_or_else(|| KeyDirectoryError::NotFound(key_id.to_string())),
            Err(err) => {
                // If we have *some* cache, serve it with a warning. A transient
                // key-server blip shouldn't refuse every action.
                if let Some(bundle) = self.lookup_in_cache(key_id).await {
                    tracing::warn!(
                        error = %err,
                        url = %self.inner.url,
                        "key directory refresh failed, serving stale cache"
                    );
                    Ok(bundle)
                } else {
                    // Cold + fetch failed → fail closed.
                    Err(err)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::FilePublicKeyDirectory;
    use crate::keys::KavachKeyPair;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc as StdArc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Minimal HTTP/1.1 stub, one request per connection, honors
    // If-None-Match for the ETag path. Avoids pulling in a mock library
    // just for these tests.
    struct HttpStub {
        addr: std::net::SocketAddr,
        hit_count: StdArc<AtomicU32>,
    }

    async fn start_stub(
        body: Vec<u8>,
        etag: &'static str,
        simulate_error: bool,
    ) -> HttpStub {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hit_count = StdArc::new(AtomicU32::new(0));
        let hits = hit_count.clone();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(ok) => ok,
                    Err(_) => return,
                };
                hits.fetch_add(1, Ordering::SeqCst);
                let body = body.clone();

                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let client_etag = request
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("if-none-match:"))
                        .and_then(|l| l.split_once(':'))
                        .map(|(_, v)| v.trim().to_string());

                    let response: Vec<u8> = if simulate_error {
                        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec()
                    } else if client_etag.as_deref() == Some(etag) {
                        format!(
                            "HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\nContent-Length: 0\r\n\r\n"
                        )
                        .into_bytes()
                    } else {
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: {etag}\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(&body);
                        out
                    };
                    let _ = stream.write_all(&response).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        HttpStub { addr, hit_count }
    }

    fn sample_bundle(id: &str) -> PublicKeyBundle {
        let kp = KavachKeyPair::generate().expect("keypair");
        let mut b = kp.public_keys();
        b.id = id.to_string();
        b
    }

    fn bundles_url(stub: &HttpStub) -> String {
        format!("http://{}/", stub.addr)
    }

    // ── Unsigned happy path + ETag ─────────────────────────────

    #[tokio::test]
    async fn unsigned_fetch_caches_and_reuses() {
        let bundle = sample_bundle("k-1");
        let body = serde_json::to_vec(&vec![bundle.clone()]).unwrap();
        let stub = start_stub(body, "\"v1\"", false).await;

        let dir = HttpPublicKeyDirectory::unsigned(bundles_url(&stub));
        let got = dir.fetch("k-1").await.unwrap();
        assert_eq!(got.id, "k-1");
        assert_eq!(stub.hit_count.load(Ordering::SeqCst), 1);

        // Second fetch should hit the cache, not the server.
        let got2 = dir.fetch("k-1").await.unwrap();
        assert_eq!(got2.id, "k-1");
        assert_eq!(stub.hit_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unsigned_reload_sends_if_none_match_and_accepts_304() {
        let bundle = sample_bundle("k-1");
        let body = serde_json::to_vec(&vec![bundle.clone()]).unwrap();
        let stub = start_stub(body, "\"v1\"", false).await;

        let dir = HttpPublicKeyDirectory::unsigned(bundles_url(&stub))
            .with_cache_ttl(Duration::from_millis(1));
        dir.fetch("k-1").await.unwrap();
        assert_eq!(stub.hit_count.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Cache is now stale, the next fetch re-checks with If-None-Match
        // and the server returns 304. The count advances (one HTTP hit) but
        // bundle count stays the same.
        let got = dir.fetch("k-1").await.unwrap();
        assert_eq!(got.id, "k-1");
        assert_eq!(stub.hit_count.load(Ordering::SeqCst), 2);
        assert_eq!(dir.cached_len().await, 1);
    }

    #[tokio::test]
    async fn fetch_missing_key_returns_not_found() {
        let body = serde_json::to_vec(&vec![sample_bundle("k-1")]).unwrap();
        let stub = start_stub(body, "\"v1\"", false).await;

        let dir = HttpPublicKeyDirectory::unsigned(bundles_url(&stub));
        let err = dir.fetch("nonexistent").await.unwrap_err();
        assert!(matches!(err, KeyDirectoryError::NotFound(_)));
    }

    // ── Fail-soft on transient failure with warm cache ──────────

    #[tokio::test]
    async fn warm_cache_survives_transient_server_failure() {
        // First server: serves a normal response.
        let bundle = sample_bundle("k-1");
        let body = serde_json::to_vec(&vec![bundle.clone()]).unwrap();
        let healthy_stub = start_stub(body, "\"v1\"", false).await;

        let dir = HttpPublicKeyDirectory::unsigned(bundles_url(&healthy_stub))
            .with_cache_ttl(Duration::from_millis(1));
        dir.fetch("k-1").await.unwrap();

        // Swap the URL to a dead port but keep the warm cache.
        let dead_url = "http://127.0.0.1:1/".to_string();
        let warm_dir = HttpPublicKeyDirectory::build(
            dead_url,
            None,
            Duration::from_millis(1),
            default_client(),
        );
        // Seed its cache manually (this models a dir whose URL went dead
        // mid-flight; we can't easily swap urls post-hoc in the public API).
        {
            let mut guard = warm_dir.inner.cache.write().await;
            let mut map = HashMap::new();
            map.insert("k-1".to_string(), bundle.clone());
            guard.bundles = Some(map);
            guard.last_fetched = Some(Instant::now() - Duration::from_secs(1));
        }

        // Cache is stale, refresh will fail with BackendUnavailable, but
        // the stale cache contains the key, so we return the stale bundle.
        let got = warm_dir.fetch("k-1").await.unwrap();
        assert_eq!(got.id, "k-1");
    }

    #[tokio::test]
    async fn cold_cache_with_failing_server_errors() {
        let dir = HttpPublicKeyDirectory::unsigned("http://127.0.0.1:1/".to_string())
            .with_http_client(
                reqwest::Client::builder()
                    .timeout(Duration::from_millis(500))
                    .build()
                    .unwrap(),
            );
        let err = dir.fetch("k-1").await.unwrap_err();
        assert!(matches!(err, KeyDirectoryError::BackendUnavailable(_)));
    }

    // ── Signed mode ─────────────────────────────────────────────

    #[tokio::test]
    async fn signed_manifest_happy_path() {
        let signing = KavachKeyPair::generate().unwrap();
        let root_vk = signing.public_keys().ml_dsa_verifying_key.clone();
        let bundle = sample_bundle("k-signed");
        let manifest = FilePublicKeyDirectory::build_signed_manifest(
            std::slice::from_ref(&bundle),
            &signing.ml_dsa_signing_key,
        )
        .unwrap();
        let body = serde_json::to_vec(&manifest).unwrap();
        let stub = start_stub(body, "\"vS1\"", false).await;

        let dir = HttpPublicKeyDirectory::signed(bundles_url(&stub), root_vk);
        let got = dir.fetch("k-signed").await.unwrap();
        assert_eq!(got.id, "k-signed");
    }

    #[tokio::test]
    async fn signed_manifest_wrong_root_rejected() {
        let real_signer = KavachKeyPair::generate().unwrap();
        let imposter = KavachKeyPair::generate().unwrap();
        let bundle = sample_bundle("k-signed");
        let manifest = FilePublicKeyDirectory::build_signed_manifest(
            std::slice::from_ref(&bundle),
            &real_signer.ml_dsa_signing_key,
        )
        .unwrap();
        let body = serde_json::to_vec(&manifest).unwrap();
        let stub = start_stub(body, "\"vS1\"", false).await;

        // Pin the imposter's VK, signature verify must fail, cache not
        // populated, fetch errors.
        let dir = HttpPublicKeyDirectory::signed(
            bundles_url(&stub),
            imposter.public_keys().ml_dsa_verifying_key.clone(),
        );
        let err = dir.fetch("k-signed").await.unwrap_err();
        assert!(matches!(err, KeyDirectoryError::RootSignatureInvalid));
        assert_eq!(dir.cached_len().await, 0);
    }

    #[tokio::test]
    async fn reload_forces_fetch_even_when_fresh() {
        let bundle = sample_bundle("k-1");
        let body = serde_json::to_vec(&vec![bundle.clone()]).unwrap();
        let stub = start_stub(body, "\"v1\"", false).await;

        let dir = HttpPublicKeyDirectory::unsigned(bundles_url(&stub))
            .with_cache_ttl(Duration::from_secs(3600));
        dir.fetch("k-1").await.unwrap();
        assert_eq!(stub.hit_count.load(Ordering::SeqCst), 1);

        // TTL would normally prevent any refetch, reload() bypasses it.
        dir.reload().await.unwrap();
        assert_eq!(stub.hit_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn server_500_returns_backend_unavailable() {
        let stub = start_stub(vec![], "\"v1\"", true).await;
        let dir = HttpPublicKeyDirectory::unsigned(bundles_url(&stub));
        let err = dir.fetch("k-1").await.unwrap_err();
        assert!(matches!(err, KeyDirectoryError::BackendUnavailable(_)));
    }
}
