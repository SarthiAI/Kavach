# Key management

Kavach's crypto is opinionated: one keypair per identity, one public-key bundle per keypair, one directory per deployment. This page covers the types, the distribution formats, and the rotation pattern that holds them together.

Prerequisites: [post-quantum.md](./post-quantum.md) for the primitives.

## The types at a glance

| Type | Lives where | Contains |
|---|---|---|
| `KavachKeyPair` | Owning process only, zeroized on drop | ML-DSA-65 seed, ML-KEM-768 seed, Ed25519 seed, X25519 secret, plus the matching public halves |
| `PublicKeyBundle` | Shared freely | ML-DSA-65 VK, ML-KEM-768 EK, Ed25519 VK, X25519 PK, plus metadata |
| `PublicKeyDirectory` (trait) | Verifiers | `async fetch(key_id) -> PublicKeyBundle` |
| `SignedDirectoryManifest` | Distribution format on disk or HTTP | Raw JSON bytes of a `Vec<PublicKeyBundle>` + ML-DSA-65 signature |
| `DirectoryTokenVerifier` | Verifiers | Looks up the bundle for an envelope's `key_id` and verifies the signature |

## `KavachKeyPair`: the full keypair

Definition in [kavach-pq/src/keys.rs](../../kavach-pq/src/keys.rs):

```rust
pub struct KavachKeyPair {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub ml_dsa_signing_key: Vec<u8>,       // 32-byte seed xi
    pub ml_dsa_verifying_key: Vec<u8>,     // encoded VK
    pub ml_kem_decapsulation_key: Vec<u8>, // seed form
    pub ml_kem_encapsulation_key: Vec<u8>, // encoded EK
    pub ed25519_signing_key: Vec<u8>,      // 32-byte seed
    pub ed25519_verifying_key: Vec<u8>,    // 32-byte compressed Edwards point
    pub x25519_secret_key: Vec<u8>,        // 32 bytes
    pub x25519_public_key: Vec<u8>,        // 32 bytes
}
```

Seeds, not expanded state: ML-DSA-65 stores the 32-byte `xi` and re-derives the full signing key on demand via `KeyGen::from_seed`. ML-KEM-768 stores a 64-byte seed and re-derives both keys via `FromSeed::from_seed`. Smaller on disk, easier to back up, and the seed is all FIPS 204 / FIPS 203 require.

**Secret bytes are zeroized on drop.** The `Drop` impl runs `zeroize` over every private-key field:

```rust
impl Drop for KavachKeyPair {
    fn drop(&mut self) {
        self.ml_dsa_signing_key.zeroize();
        self.ml_kem_decapsulation_key.zeroize();
        self.ed25519_signing_key.zeroize();
        self.x25519_secret_key.zeroize();
    }
}
```

**The seed never leaves the owning process.** A `KavachKeyPair` does not implement `Clone`, does not implement `Serialize`, and is not exposed across the Python / Node FFI boundary as seed bytes. The Python and Node SDKs hold an `Arc<KavachKeyPair>` internally and expose only the public-key operations and the bundle. If your integrator design requires the seed to cross a trust boundary, stop and reconsider.

Generate one:

```rust
use kavach_pq::KavachKeyPair;

let kp = KavachKeyPair::generate()?;
println!("id = {}", kp.id); // "kavach-key-<uuid>"
```

Or with a lifetime:

```rust
use chrono::Duration;

let kp = KavachKeyPair::generate_with_expiry(Some(Duration::days(30)))?;
assert!(!kp.is_expired());
```

Randomness comes from `getrandom::fill` via `OsCryptoRng`, which is the OS RNG wrapped to satisfy rand_core 0.10's `TryCryptoRng` trait. See `fill_random` in [kavach-pq/src/keys.rs](../../kavach-pq/src/keys.rs) and the `OsCryptoRng` adapter in [kavach-pq/src/encrypt.rs](../../kavach-pq/src/encrypt.rs).

## `PublicKeyBundle`: the shareable half

```rust
pub struct PublicKeyBundle {
    pub id: String,
    pub ml_dsa_verifying_key: Vec<u8>,
    pub ml_kem_encapsulation_key: Vec<u8>,
    pub ed25519_verifying_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}
```

Produced by `KavachKeyPair::public_keys(&self) -> PublicKeyBundle`. Safe to publish, cache, ship over HTTP, commit to git, whatever. Contains only public information.

`PublicKeyBundle` is `Serialize + Deserialize`, so `serde_json::to_vec(&bundle)` is how it moves between systems.

The `id` field is the lookup key. A service that signs a `PermitToken` or an audit entry stamps its `id` into the envelope; a verifier elsewhere takes that `id`, fetches the matching bundle from a directory, and uses the four public keys to verify.

## `PublicKeyDirectory`: the lookup trait

```rust
#[async_trait]
pub trait PublicKeyDirectory: Send + Sync {
    async fn fetch(&self, key_id: &str) -> Result<PublicKeyBundle, KeyDirectoryError>;
}
```

Three implementations ship with `kavach-pq`:

| Factory | Backing | Use case |
|---|---|---|
| `InMemoryPublicKeyDirectory::from_bundles([...])` | In-process `HashMap` | Tests. Programmatic setup. Deployments that build the directory at startup by iterating a local `KeyStore`. |
| `FilePublicKeyDirectory::load_unsigned(path)` | JSON file on disk | Local trusted disk only. Dev / single-host deployments. |
| `FilePublicKeyDirectory::load_signed(path, root_vk)` | JSON file with ML-DSA-65 root signature | Cross-host production. Pin the root VK in config; any tampered manifest is rejected. |
| `HttpPublicKeyDirectory::unsigned(url)` | HTTP with ETag cache, `http` feature | Dev / trusted internal transport. |
| `HttpPublicKeyDirectory::signed(url, root_vk)` | HTTP with ETag cache + ML-DSA-65 root signature | Cross-host production. Defeats a MITM on the key server. |

### `InMemoryPublicKeyDirectory`

From [kavach-pq/tests/directory_verification.rs](../../kavach-pq/tests/directory_verification.rs):

```rust
use kavach_pq::{InMemoryPublicKeyDirectory, PublicKeyDirectory, KavachKeyPair};
use std::sync::Arc;

let kp = KavachKeyPair::generate().unwrap();
let directory: Arc<dyn PublicKeyDirectory> =
    Arc::new(InMemoryPublicKeyDirectory::from_bundles([kp.public_keys()]));
```

Supports `insert(bundle)`, `remove(key_id)`, `len()`, `is_empty()`, and `fetch(key_id).await`. Thread-safe via an internal `RwLock`.

### `FilePublicKeyDirectory` (unsigned)

Load an unsigned JSON array of bundles:

```rust
use kavach_pq::FilePublicKeyDirectory;

let dir = FilePublicKeyDirectory::load_unsigned("/etc/kavach/bundles.json")?;
```

On-disk format: raw `Vec<PublicKeyBundle>` JSON.

**Only safe when the file is on a host you trust completely** (local disk on the verifier, populated by config management you control). Anything crossing a trust boundary should be signed.

Call `reload()` to re-read the file. If the read or parse fails, the existing cache is preserved (pinned by the test `file_reload_preserves_cache_on_parse_error`), so a typo in the file does not wipe your verifier.

### `FilePublicKeyDirectory` (signed)

The production path for file-based distribution:

```rust
use kavach_pq::FilePublicKeyDirectory;

let root_vk_bytes: Vec<u8> = std::fs::read("/etc/kavach/root.vk")?;
let dir = FilePublicKeyDirectory::load_signed(
    "/etc/kavach/bundles.manifest.json",
    root_vk_bytes,
)?;
```

The on-disk format is a `SignedDirectoryManifest`:

```rust
pub struct SignedDirectoryManifest {
    pub bundles_json: String, // raw JSON bytes of Vec<PublicKeyBundle>
    pub signature: Vec<u8>,   // ML-DSA-65 over bundles_json.as_bytes()
}
```

The `bundles_json` field is a `String` on purpose, holding the raw JSON bytes that were signed. This avoids any JSON canonicalization dance: the verifier reconstructs the exact bytes the signer signed by calling `bundles_json.as_bytes()`. Mutating the bundles without re-signing breaks verification; pinned by `file_signed_tampered_bundles_are_rejected`.

The root ML-DSA-65 VK is pinned out-of-band (typically shipped in config or baked into the binary). If the manifest's signature does not verify against that root VK, the load fails with `KeyDirectoryError::RootSignatureInvalid` and the cache is not updated.

### `HttpPublicKeyDirectory` (feature `http`)

> **Experimental. Not yet thoroughly validated.**
>
> The Rust-level unit tests for `HttpPublicKeyDirectory` pass (hand-rolled Tokio HTTP stub covers the happy path, ETag reuse, 304 round-trip, cold-cache `BackendUnavailable`, and warm-cache survive-transient-outage), but the consumer-validation harness at `business-tests/` does not yet exercise this path end to end. Early adopters can wire it up; the code is shipped behind the opt-in `http` feature. Treat this section as a reference until validation lands; see [../roadmap.md](../roadmap.md).

Enable in `Cargo.toml`:

```toml
kavach-pq = { version = "0.1", features = ["http"] }
```

The HTTP directory fetches either an unsigned `Vec<PublicKeyBundle>` or a `SignedDirectoryManifest` from a URL, with ETag-aware caching:

```rust
use kavach_pq::HttpPublicKeyDirectory;

let dir = HttpPublicKeyDirectory::signed(
    "https://keys.example.com/bundles",
    root_vk_bytes,
)
    .with_cache_ttl(std::time::Duration::from_secs(300));
```

Behavior:

- First `fetch(key_id)` triggers a `GET`. The response body is parsed (and, in signed mode, the root signature is verified). The `ETag` header is stashed.
- Subsequent fetches within the TTL hit the cache, no HTTP.
- After the TTL expires, the next fetch sends `If-None-Match: <etag>`. The server responds `304 Not Modified` and the cache stays; `last_fetched` advances.
- A fresh body (200 OK) replaces the cache + etag.
- **Cold cache + fetch fails -> `BackendUnavailable`**, fail closed.
- **Warm cache + fetch fails -> stale cache is served with a `tracing::warn!`.** Better to verify against a recently-good bundle than refuse the whole system because the key server is briefly down. The warning is the operational signal.
- **Invalid root signature -> `RootSignatureInvalid`**, cache **not** replaced with the bad payload.

Construction never performs I/O, so `HttpPublicKeyDirectory::signed(...)` cannot fail on network issues; the first actual HTTP request happens on the first `fetch` call.

Force-refresh bypassing the TTL:

```rust
dir.reload().await?;
```

## `DirectoryTokenVerifier`: the consumer side

A verifier that looks up the public key by `key_id` instead of holding it directly.

From [kavach-pq/src/token.rs](../../kavach-pq/src/token.rs):

```rust
pub struct DirectoryTokenVerifier {
    directory: Arc<dyn PublicKeyDirectory>,
    hybrid: bool,
}
```

Build one for PQ-only mode:

```rust
use kavach_pq::{DirectoryTokenVerifier, PublicKeyDirectory};
use std::sync::Arc;

let verifier = DirectoryTokenVerifier::pq_only(directory);
```

Or hybrid:

```rust
let verifier = DirectoryTokenVerifier::hybrid(directory);
```

### End-to-end verify flow

From [kavach-pq/tests/directory_verification.rs](../../kavach-pq/tests/directory_verification.rs):

```rust
let kp = KavachKeyPair::generate().unwrap();
let signer = PqTokenSigner::from_keypair_pq_only(&kp);
let directory: Arc<dyn PublicKeyDirectory> =
    Arc::new(InMemoryPublicKeyDirectory::from_bundles([kp.public_keys()]));
let verifier = DirectoryTokenVerifier::pq_only(directory);

let mut token = sample_token("act");
let sig = signer.sign(&token).unwrap();
token.signature = Some(sig.clone());

verifier.verify(&token, &sig).await.unwrap();
```

What `verify` does:

1. Deserialize the signature bytes as a `SignedTokenEnvelope` (which carries `key_id`, `algorithm`, `ml_dsa_signature`, optional `ed25519_signature`).
2. Reject on algorithm mismatch (hybrid verifier rejects PQ-only envelope and vice versa; see the downgrade guard section in [post-quantum.md](./post-quantum.md)).
3. `directory.fetch(&envelope.key_id).await` to get the `PublicKeyBundle`.
4. Verify ML-DSA-65 against `bundle.ml_dsa_verifying_key` over `token.canonical_bytes()`.
5. In hybrid mode, verify Ed25519 against `bundle.ed25519_verifying_key` over the same bytes.

### Fail-closed on every error path

`DirectoryVerifyError` has five variants:

| Variant | Cause | What you should do |
|---|---|---|
| `EnvelopeParse(String)` | Envelope bytes don't parse as JSON | Refuse |
| `AlgorithmMismatch(String)` | Hybrid vs PQ-only mismatch between verifier and envelope | Refuse |
| `Directory(KeyDirectoryError)` | Lookup failed: NotFound, BackendUnavailable, RootSignatureInvalid, Corrupt, Other | Refuse |
| `SignatureInvalid(String)` | Crypto verify failed | Refuse |

Every path results in a token refusal. Pinned by `verifier_fails_closed_on_directory_backend_error` in the same test file.

## Building a `SignedDirectoryManifest`

Producer side, from [kavach-pq/src/directory.rs](../../kavach-pq/src/directory.rs):

```rust
use kavach_pq::{FilePublicKeyDirectory, KavachKeyPair, PublicKeyBundle};

let root = KavachKeyPair::generate()?; // the root authority's keypair
let bundles: Vec<PublicKeyBundle> = vec![
    service_a.public_keys(),
    service_b.public_keys(),
    service_c.public_keys(),
];

let manifest = FilePublicKeyDirectory::build_signed_manifest(
    &bundles,
    &root.ml_dsa_signing_key,
)?;

std::fs::write(
    "/etc/kavach/bundles.manifest.json",
    serde_json::to_vec_pretty(&manifest)?,
)?;
```

The root signing key never leaves the root authority's host. Only the root **verifying** key ships to verifiers, and only the manifest file ships to the file / HTTP endpoint.

### SDK helper

The Python and Node SDKs expose the same operation without requiring the raw seed bytes to cross the FFI boundary. From `KavachKeyPair.build_signed_manifest(bundles)`: the ML-DSA-65 seed stays in the owning process, only the manifest comes back out.

```python
from kavach import KavachKeyPair, PublicKeyBundle

root = KavachKeyPair.generate()
bundles = [service_a.public_keys(), service_b.public_keys()]
manifest_bytes = root.build_signed_manifest(bundles)
```

## Key rotation pattern

Rotation in Kavach is additive, not destructive. A new keypair goes in; the old one stays available for verification until all in-flight tokens signed by it have expired.

```
┌──────────────────────────────────────────────────────────────┐
│ 1. Generate a new KavachKeyPair on the signing host.         │
│ 2. Add its PublicKeyBundle to the list of bundles.           │
│ 3. Re-sign the manifest with the root key.                   │
│ 4. Push the new manifest to disk / HTTP endpoint.            │
│ 5. Verifiers reload (explicit `reload()` call, file watcher, │
│    or the HTTP directory's TTL-triggered refresh).           │
│ 6. Signer flips its PqTokenSigner to use the new KavachKeyPair.│
│ 7. After the old keys' tokens have all expired, drop the old │
│    bundle from the manifest and re-sign.                     │
└──────────────────────────────────────────────────────────────┘
```

Why additive: tokens signed under the old key are still in flight. A verdict issued at t0 with a 1-hour expiry is still being verified at t0+45min even if rotation happened at t0+30min. Keeping the old bundle in the directory until all such tokens expire avoids spurious refusals.

### With `KeyStore` for in-process rotation

`KeyStore` in [kavach-pq/src/keys.rs](../../kavach-pq/src/keys.rs) is a thread-safe in-process store for multiple keypairs with an active-key pointer:

```rust
use kavach_pq::KeyStore;
use chrono::Duration;

let store = KeyStore::new();
let old_id = store.generate_and_activate(Some(Duration::days(30)))?;

// ... some time later, rotate ...
let new_id = store.generate_and_activate(Some(Duration::days(30)))?;
// The previous active key is still in the store (can still verify old tokens).
// `old_id` still resolves via `store.public_keys(&old_id)`.

// Periodic cleanup of expired keys:
store.cleanup_expired();
```

This is a convenience; production deployments usually externalize key material to an HSM, KMS, or cloud key service and build their own `TokenSigner` on top.

### Reloading a file-backed directory

A common setup pairs `FilePublicKeyDirectory` with `kavach-core`'s `notify`-based file watcher (enabled by the `watcher` feature). Signer pushes the new manifest; watcher fires; verifier's `reload()` runs:

```rust
dir.reload()?; // reads the file, verifies root signature, swaps cache
```

If `reload()` fails (disk read error, corrupt JSON, invalid root signature), the previous cache is preserved. A bad manifest does not down your verifier.

### Reloading an HTTP-backed directory

`HttpPublicKeyDirectory` refreshes on its own on TTL expiry, but you can force-refresh:

```rust
dir.reload().await?;
```

Useful after a rotation event so verifiers don't wait the full TTL.

## Algorithm mismatch: strict both ways

Repeating the rule from [post-quantum.md](./post-quantum.md) because it applies to directory verification too:

- A **hybrid `DirectoryTokenVerifier` rejects a PQ-only envelope.** Attacker cannot strip the Ed25519 signature and force a downgrade.
- A **PQ-only `DirectoryTokenVerifier` rejects a hybrid envelope.** Catches misconfiguration; a verifier that was supposed to be hybrid shouldn't silently accept PQ-only.

Pinned by `hybrid_verifier_rejects_pq_only_token` and `pq_only_verifier_rejects_hybrid_token` in [kavach-pq/tests/directory_verification.rs](../../kavach-pq/tests/directory_verification.rs).

## Operational checklist

- **Root signing key is offline or hardware-backed.** It never touches a host that accepts network traffic.
- **Root verifying key is pinned** on every verifier (config file, env, or compiled in).
- **Manifest is signed every time it changes.** Never edit `bundles.json` in place on production hosts; always re-sign on the root host and redistribute.
- **Verifiers fail closed.** Monitor the count of `BackendUnavailable`, `NotFound`, `SignatureInvalid`, `AlgorithmMismatch`, and `RootSignatureInvalid` errors. A spike is either an operational problem or an attack in progress.
- **Rotation is additive.** Keep retired keys in the manifest until all their tokens have expired.
- **HTTP stale-serve is a warning, not a silent downgrade.** Alert on the `tracing::warn!` log line that starts with `"key directory refresh failed"`.

## See also

- [post-quantum.md](./post-quantum.md): the primitives underneath all of this.
- [audit.md](./audit.md): where `PublicKeyBundle` feeds into long-term audit verification.
- [gate-and-verdicts.md](./gate-and-verdicts.md): `PermitToken` signing from the gate side.
- [SECURITY.md](../../SECURITY.md): "Leaked keys" are out of scope; rotation and storage are the integrator's responsibility.
