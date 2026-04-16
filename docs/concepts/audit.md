# The signed audit chain

A `SignedAuditChain` is an append-only log where every entry is cryptographically signed and cryptographically linked to the one before it. Mutate any byte, reorder any entry, delete any entry, splice across modes, or forge a new entry: verification fails and names the offending index.

This is what you reach for when "we have logs" is not good enough. Logs with SQL write access behind them are not an audit trail. A signed chain survives an attacker who owns your log storage, because mutating the storage breaks the hash linkage, and replacing the hash linkage requires the signing key, which the attacker does not have.

If you are already familiar with the PQ primitives, skip ahead. Otherwise read [post-quantum.md](./post-quantum.md) first.

## What the chain detects

| Threat | How the chain catches it |
|---|---|
| Tamper: flip any byte in any entry | `entry_hash` stops matching `compute_chain_hash(index, previous_hash, signed_payload)`, and the ML-DSA-65 signature stops verifying |
| Delete an entry in the middle | The next entry's `previous_hash` no longer equals the prior entry's `entry_hash` |
| Insert a forged entry | Requires the signing key; the chain verifier's ML-DSA-65 + optional Ed25519 check fails |
| Reorder entries | Indices are checked to be sequential (`0, 1, 2, ...`), and hash linkage fails at the swap point |
| Splice a PQ-only entry into a hybrid chain (mode downgrade) | `detect_mode` returns `AuditChainBroken` naming the first inconsistent index before any crypto runs |
| Verify a hybrid chain with a PQ-only verifier (silent downgrade) | Verifier/chain mode parity is enforced before any signature is checked |

All of this is fail-closed. An unverifiable chain is a broken chain.

## On-disk format

The chain exports as JSONL: one `SignedAuditEntry` per line, UTF-8, trailing newline.

```rust
pub struct SignedAuditEntry {
    pub index: u64,
    pub previous_hash: String,
    pub signed_payload: SignedPayload,
    pub entry_hash: String,
}

pub struct SignedPayload {
    pub data: Vec<u8>,
    pub ml_dsa_signature: Vec<u8>,
    pub ed25519_signature: Option<Vec<u8>>,
    pub key_id: String,
    pub signed_at: DateTime<Utc>,
    pub nonce: String,
}
```

A single hybrid-mode entry looks roughly like this on disk (numbers truncated for readability; real signatures are 3309 bytes for ML-DSA-65 and 64 bytes for Ed25519):

```json
{
  "index": 0,
  "previous_hash": "genesis",
  "signed_payload": {
    "data": [123, 34, 105, 100, 34, 58, ...],
    "ml_dsa_signature": [51, 187, 7, 253, ...],
    "ed25519_signature": [170, 10, 74, 240, ...],
    "key_id": "kavach-key-7c8c1f6a-3e9b-4e4d-9a27-f2b6c9e4a9d2",
    "signed_at": "2026-04-16T12:34:56.789Z",
    "nonce": "b3f1e2d4-1234-5678-9abc-def012345678"
  },
  "entry_hash": "3f5a1c7e9b2d4e8a1f0b3c5d7e9a1b2c..."
}
```

The genesis entry's `previous_hash` is the literal string `"genesis"`. Every subsequent entry's `previous_hash` is the previous entry's `entry_hash`, which is SHA-256 over:

```rust
hasher.update(index.to_le_bytes());
hasher.update(previous_hash.as_bytes());
hasher.update(&payload.data);
hasher.update(&payload.ml_dsa_signature);
if let Some(ed_sig) = &payload.ed25519_signature {
    hasher.update(ed_sig);
}
hasher.update(payload.nonce.as_bytes());
hasher.update(payload.signed_at.to_rfc3339().as_bytes());
```

The signature payload binds `data || nonce_bytes || timestamp_rfc3339` (see `compose_message` in [kavach-pq/src/sign.rs](../../kavach-pq/src/sign.rs)), so the nonce and timestamp are signed, not just appended to the hash.

## How `verify_chain` works

From [kavach-pq/src/audit.rs](../../kavach-pq/src/audit.rs):

1. **`detect_mode(entries)`** runs first. It scans entries and rejects any chain whose `signed_payload.ed25519_signature.is_some()` differs from entry to entry. A chain is either uniformly PQ-only or uniformly hybrid, never both. An attacker who tries to splice a PQ-only entry into a hybrid chain (hoping the verifier will only check the ML-DSA-65 leg on that one entry) is stopped here, before any crypto runs, with an `AuditChainBroken { index, reason }` naming the first inconsistent entry.

2. **Verifier/chain mode parity.** `ChainMode::from_hybrid(verifier.is_hybrid())` must equal the detected chain mode. A hybrid verifier on a PQ-only chain is rejected. A PQ-only verifier on a hybrid chain is rejected. This is the downgrade guard: an attacker cannot get a hybrid chain accepted by pointing a PQ-only verifier at it and hoping the verifier silently ignores the Ed25519 signatures.

3. **For each entry, in order:**
   - `entry.index == i` (no gaps, no duplicates, no reorderings).
   - `entry.previous_hash == expected_hash` (hash chain linkage).
   - `verifier.verify(&entry.signed_payload)` passes ML-DSA-65 (and Ed25519 if hybrid).
   - `compute_chain_hash(...) == entry.entry_hash` (hash is correct for the stored content).
   - `expected_hash = entry.entry_hash` for the next iteration.

Any failure returns `PqError::AuditChainBroken { index, reason }` with the offending index. The reason string tells you whether it was a mode-mismatch, a hash-linkage break, a signature failure, or a bad index.

### The downgrade guard, pinned by test

`audit_chain_rejects_mode_downgrade` in [kavach-pq/tests/crypto_integration.rs](../../kavach-pq/tests/crypto_integration.rs) is the regression pin. Key excerpt:

```rust
// Hybrid chain, PQ-only verifier → must reject
let hybrid_signer = kavach_pq::Signer::from_keypair(&kp, true);
let hybrid_chain = SignedAuditChain::new(hybrid_signer);
for i in 0..2 {
    hybrid_chain.append(&AuditEntry { /* ... */ }).expect("append");
}
let hybrid_entries = hybrid_chain.entries();

let pq_verifier = kavach_pq::Verifier::from_bundle(&bundle, false);
let err = verify_chain(&hybrid_entries, &pq_verifier)
    .expect_err("PQ-only verifier MUST reject a hybrid chain (downgrade protection)");
```

Do not loosen this check. Ever.

### Mode splicing, pinned by test

Same test, later:

```rust
let mut spliced = hybrid_entries.clone();
// Strip Ed25519 sig from the second entry.
spliced[1].signed_payload.ed25519_signature = None;
let err = detect_mode(&spliced).expect_err("mixed-mode chain must be rejected");
assert!(err.to_string().contains("chain mode inconsistent"));
```

`detect_mode` runs before signatures are checked, so even an entry that would otherwise have a valid ML-DSA-65 signature is rejected if its mode does not match the rest of the chain.

## Appending to a chain

From [kavach-pq/tests/crypto_integration.rs](../../kavach-pq/tests/crypto_integration.rs):

```rust
use kavach_core::audit::AuditEntry;
use kavach_pq::{audit::SignedAuditChain, KavachKeyPair, Signer};

let kp = KavachKeyPair::generate().unwrap();
let signer = Signer::new(kp.ml_dsa_signing_key.clone(), kp.id.clone());
let chain = SignedAuditChain::new(signer);

for i in 0..3 {
    let entry = AuditEntry {
        id: Uuid::new_v4(),
        evaluation_id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        principal_id: format!("agent-{i}"),
        action_name: "issue_refund".into(),
        resource: None,
        verdict: "permit".into(),
        verdict_detail: format!("entry {i}"),
        decided_by: None,
        session_id: Uuid::new_v4(),
        ip: None,
        context_snapshot: None,
    };
    chain.append(&entry).expect("append");
}
```

Swap `Signer::new(...)` for `Signer::hybrid(...)` or `Signer::from_keypair(&kp, true)` to build a hybrid chain.

## Verifying a live chain

Also from the same test file:

```rust
let verifier = kavach_pq::Verifier::new(kp.ml_dsa_verifying_key.clone());
let entries = chain.entries();
kavach_pq::audit::verify_chain(&entries, &verifier).expect("honest chain verifies");
```

Tamper anywhere and it fails:

```rust
let mut entries = chain.entries();
entries[1].signed_payload.data[0] ^= 0xff;
assert!(
    kavach_pq::audit::verify_chain(&entries, &verifier).is_err(),
    "chain must reject tampered entry"
);
```

## Verifying an old audit dump

This is the operational path: someone exported the chain months ago, stored it as a `.jsonl` file, and now you want to confirm nothing has been changed.

```rust
use kavach_pq::{
    audit::{detect_mode, parse_jsonl, verify_chain, ChainMode},
    sign::Verifier as PqVerifier,
    PublicKeyBundle,
};

// 1. Read the JSONL file from disk.
let blob = std::fs::read("audit-2026-04.jsonl")?;

// 2. Parse it. Blank lines are tolerated; errors report by entry index.
let entries = parse_jsonl(&blob)?;

// 3. Infer the chain mode. Empty chain returns Ok(None), nothing to verify.
let Some(mode) = detect_mode(&entries)? else {
    return Ok(()); // empty chain, nothing to do
};

// 4. Load the PublicKeyBundle for the signing key.
//    In practice this comes from a PublicKeyDirectory (see key-management.md).
//    Here we assume you have the bundle in hand.
let bundle: PublicKeyBundle = /* ... load from your directory ... */;

// 5. Build the matching verifier and run verify_chain.
let verifier = PqVerifier::from_bundle(&bundle, mode.is_hybrid());
verify_chain(&entries, &verifier)?;

println!("chain verified: {} entries in {mode} mode", entries.len());
```

Four things to notice:

- **`parse_jsonl` tolerates blank lines.** Editors sometimes add trailing newlines, and that is fine.
- **Parse errors report by 0-based entry index**, not raw line number: "parse failed at entry #7: ..." tells you which logical entry is corrupt even if the file has blank lines before it.
- **`detect_mode` returns `Some(mode)` from the data itself.** You do not need out-of-band configuration to decide whether the blob is hybrid or PQ-only.
- **You still have to fetch the right `PublicKeyBundle`.** The chain's signatures are over `key_id`-scoped keys; look that key up through a [`PublicKeyDirectory`](./key-management.md), or through `InMemoryPublicKeyDirectory::from_bundles([...])` if you have the bundle already.

### One-liner for quick CI verification

For pipelines that just need "did this blob survive intact":

```rust
let blob = std::fs::read(path)?;
let entries = kavach_pq::audit::parse_jsonl(&blob)?;
let mode = kavach_pq::audit::detect_mode(&entries)?
    .ok_or_else(|| anyhow::anyhow!("empty chain"))?;
let verifier = PqVerifier::from_bundle(&bundle, mode.is_hybrid());
kavach_pq::audit::verify_chain(&entries, &verifier)?;
```

A non-zero exit on any of these is the monitoring signal you want.

## What the chain does not do

Honest limits, straight from the code:

- **The chain is append-only in memory, not on disk.** `SignedAuditChain` holds its entries in a `RwLock<Vec<SignedAuditEntry>>`. Persisting is the integrator's job: call `export_jsonl()` periodically, write to durable storage, and rotate files on boundaries that make sense for you.
- **Key rotation is out of the chain's scope.** Entries stamp `key_id` into the signed payload, so a verifier can look up the right key, but rotating the signing key mid-chain is a policy choice. See [key-management.md](./key-management.md).
- **The chain does not enforce ordering across processes.** Two processes appending to two separate chains produce two separate linear histories. Merging them is a product decision, not a crypto operation.
- **`AuditEntry`'s content is not canonicalized.** The chain signs `serde_json::to_vec(&entry)`. If you reserialize the entry with a different JSON library, you may get different bytes and the signature will not verify. Do not reserialize; keep the original bytes.

## See also

- [post-quantum.md](./post-quantum.md): the ML-DSA-65 / Ed25519 primitives behind the signature.
- [key-management.md](./key-management.md): how `PublicKeyBundle` and `PublicKeyDirectory` distribute the keys a verifier needs.
- [SECURITY.md](../../SECURITY.md): "Audit chain tamper that verifies" is in scope for security fixes.
