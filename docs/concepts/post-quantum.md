# Post-quantum crypto

Kavach assumes network transport is hostile and assumes a sufficiently-large quantum computer will one day exist. The `kavach-pq` crate composes NIST-approved post-quantum primitives alongside battle-tested classical ones so that the token you sign today still means something after the first cryptographically-relevant quantum machine comes online.

This page is about the "why" and the algorithm choices. For how to use the signer at the code level see [key-management.md](./key-management.md). For the audit chain that consumes these signatures see [audit.md](./audit.md).

## Why post-quantum at all

The short version:

- **Shor's algorithm breaks RSA, DSA, ECDSA, Ed25519, and X25519** once a large fault-tolerant quantum computer exists. Discrete log and integer factorization fall.
- **Harvest-now, decrypt-later** is already happening. An adversary who records your TLS traffic in 2026 and who builds a CRQC in 2035 decrypts it retroactively. Anything you want secret for more than a decade needs PQ protection today.
- **Signatures on audit logs and permits have long tails.** A `PermitToken` signed today may be replayed against a system in ten years. If your signing algorithm is classical-only, that token is forgeable the day the CRQC ships.

Kavach's posture, straight from [SECURITY.md](../../SECURITY.md): *"Post-quantum is real. Transport uses X25519 + ML-KEM-768 in hybrid. Signatures use Ed25519 + ML-DSA-65 in hybrid, with a PQ-only mode for environments that forbid classical crypto."*

## Algorithms

### ML-DSA-65 (FIPS 204, signatures)

The post-quantum signature scheme. Formerly called Dilithium. NIST standardized it as FIPS 204 in August 2024. Security is based on the hardness of module-lattice problems (MLWE / MSIS).

Used in Kavach for:

- Signing `PermitToken` (see [gate-and-verdicts.md](./gate-and-verdicts.md)) via `PqTokenSigner`.
- Signing `SignedAuditEntry` in the audit chain.
- Signing `SignedDirectoryManifest` so a pinned root verifier can check the integrity of distributed public-key bundles.

Implementation: the [ml-dsa](https://crates.io/crates/ml-dsa) crate from RustCrypto, pinned at `=0.1.0-rc.8`. The signing key is stored as the 32-byte seed `xi` from FIPS 204; the actual expanded state is derived on demand via `KeyGen::from_seed`.

### ML-KEM-768 (FIPS 203, key encapsulation)

The post-quantum KEM. Formerly called Kyber. NIST standardized it as FIPS 203 in August 2024. Also module-lattice-based.

KEMs are not drop-in replacements for Diffie-Hellman. A KEM gives you `encapsulate(pk) -> (ciphertext, shared_secret)` on the sender and `decapsulate(sk, ciphertext) -> shared_secret` on the receiver. Kavach pipes that shared secret into HKDF-SHA256 and derives a 32-byte ChaCha20-Poly1305 key.

Used in Kavach for:

- `SecureChannel` between two services with `KavachKeyPair`s.
- The encryption leg of `Encryptor` / `Decryptor` in `kavach-pq/src/encrypt.rs`.

Implementation: the [ml-kem](https://crates.io/crates/ml-kem) crate, pinned at `=0.3.0-rc.2`. Kavach stores the decapsulation key as its seed and re-derives the full key on demand via `FromSeed::from_seed`, which keeps stored secrets compact and avoids cross-crate RNG trait issues.

### Ed25519 (classical signatures)

EdDSA over Curve25519. Well understood, widely deployed, fast, small signatures, well-implemented in the [ed25519-dalek](https://crates.io/crates/ed25519-dalek) crate. Broken by a CRQC but not by anything that exists today.

In Kavach, Ed25519 runs **in parallel** with ML-DSA-65 when hybrid mode is on. The same message gets signed by both; verification requires both to pass. See the hybrid section below.

### X25519 (classical key agreement)

The Montgomery-form ECDH using Curve25519. Paired with ML-KEM-768 in hybrid mode: both derive shared secrets from the same handshake, and both are concatenated into the HKDF input:

```rust
let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
let mut okm = [0u8; 32];
hk.expand(HKDF_INFO, &mut okm)?;
```

where `ikm = pq_shared || classical_shared`. If either shared secret is compromised alone, the derived key still has the other as entropy. See `derive_symmetric_key` in [kavach-pq/src/encrypt.rs](../../kavach-pq/src/encrypt.rs).

One ergonomic note: X25519 uses a true `EphemeralSecret` (x25519-dalek's one-shot type that is consumed by `diffie_hellman`) so the ephemeral key cannot be reused. The static identity key is a separate `StaticSecret`.

### ChaCha20-Poly1305 (AEAD)

Symmetric authenticated encryption with a 32-byte key and a 12-byte nonce. Used after the KEM + DH handshake to encrypt the actual payload. The `recipient_key_id` is bound as AAD so that a payload encrypted for service A cannot be decrypted by service B even if B somehow had A's keys, and a wrong-recipient payload is rejected at decrypt time with a clear error.

Not quantum-affected at current key sizes. A 256-bit symmetric key against Grover's algorithm still gives 128-bit security, which is fine.

## Hybrid mode, and why it exists

**Hybrid means run both the PQ algorithm and the classical algorithm, and require both to succeed.** An attacker who wants to forge a signature has to break *both* ML-DSA-65 *and* Ed25519. An attacker who wants to decrypt a channel has to break *both* ML-KEM-768 *and* X25519.

Why this matters: the post-quantum primitives are young. ML-DSA-65 and ML-KEM-768 are NIST-standardized but have been in serious cryptanalysis for only a few years. If someone publishes a devastating attack on the module-lattice problem tomorrow, Kavach falls back to Ed25519 / X25519. Conversely, if a CRQC ships tomorrow, Kavach falls back to ML-DSA-65 / ML-KEM-768. Either shoe drops, Kavach still stands.

The parallel-sign invariant in `kavach-pq/src/sign.rs`:

```rust
pub fn sign(&self, data: &[u8]) -> Result<SignedPayload> {
    let nonce = Uuid::new_v4().to_string();
    let signed_at = Utc::now();
    let message = compose_message(data, &nonce, signed_at);

    let ml_dsa_signature = self.ml_dsa_sign(&message)?;
    let ed25519_signature = if self.hybrid {
        Some(self.ed25519_sign(&message)?)
    } else {
        None
    };
    ...
}
```

Both signatures cover the exact same bytes (data, nonce, timestamp). Verification in hybrid mode checks both.

### The signature downgrade guard

This is the subtle part.

If a hybrid verifier were to silently accept a PQ-only envelope ("well, it has an ML-DSA signature, good enough"), an attacker who breaks *only* ML-DSA-65 could strip the Ed25519 signature from a hybrid envelope, produce a PQ-only envelope, and get it through. The Ed25519 leg would provide no protection because the verifier never checked for it.

Kavach closes this. `PqTokenSigner::verify` rejects PQ-only envelopes when configured hybrid:

```rust
let envelope_is_hybrid = envelope.algorithm == ALG_HYBRID;
if self.hybrid && !envelope_is_hybrid {
    return Err(KavachError::Serialization(format!(
        "hybrid verifier rejects non-hybrid algorithm '{}'",
        envelope.algorithm
    )));
}
if !self.hybrid && envelope.algorithm != ALG_PQ_ONLY {
    return Err(KavachError::Serialization(format!(
        "PQ-only verifier expected '{ALG_PQ_ONLY}', got '{}'",
        envelope.algorithm
    )));
}
```

The rejection is strict in both directions. A PQ-only verifier also rejects hybrid envelopes, so you can't accidentally verify with the wrong mode. `DirectoryTokenVerifier` enforces the same rule for directory-looked-up keys, and the audit chain's `verify_chain` extends the rule to chain mode (see [audit.md](./audit.md)).

Pinned by the test `hybrid_verifier_rejects_pq_only_signature` in [kavach-pq/tests/crypto_integration.rs](../../kavach-pq/tests/crypto_integration.rs):

```rust
let kp = KavachKeyPair::generate().unwrap();
let pq_only = PqTokenSigner::from_keypair_pq_only(&kp);
let hybrid = PqTokenSigner::from_keypair_hybrid(&kp);

let token = fresh_permit_token("issue_refund");
let sig = pq_only.sign(&token).expect("sign");
assert!(
    hybrid.verify(&token, &sig).is_err(),
    "hybrid verifier must refuse to downgrade to PQ-only"
);
```

## Primitive summary

| Purpose | Algorithm | Rust crate | Version pin |
|---|---|---|---|
| PQ signature | ML-DSA-65 (FIPS 204) | `ml-dsa` | `=0.1.0-rc.8` |
| PQ key encapsulation | ML-KEM-768 (FIPS 203) | `ml-kem` | `=0.3.0-rc.2` |
| Classical signature | Ed25519 | `ed25519-dalek` | `2` |
| Classical key agreement | X25519 | `x25519-dalek` | `2` (with `static_secrets`) |
| AEAD (channel payload) | ChaCha20-Poly1305 | `chacha20poly1305` | `0.10` |
| Hash | SHA-256 | `sha2` | `0.10` |
| KDF | HKDF-SHA-256 | `hkdf` | `0.12` |
| OS randomness | `getrandom` | `getrandom` | `0.3` |
| Zeroize on drop | `zeroize` | `zeroize` | `1` |

The full dep list lives in [kavach-pq/Cargo.toml](../../kavach-pq/Cargo.toml).

## Release candidates: the honest disclaimer

`ml-dsa` and `ml-kem` are pinned to release candidates. **This is normal in the Rust post-quantum ecosystem right now.** RustCrypto is doing the careful thing: FIPS 203 and FIPS 204 both shipped as final standards in August 2024, and the implementations have been iterating on the final spec since. No one in the Rust PQ space has cut a stable 1.0 yet because the spec settled recently and the team wants more cryptanalysis and more review time before committing to API stability.

Kavach pins with `=` (exact-version match) to freeze the behavior:

```toml
ml-kem = "=0.3.0-rc.2"
ml-dsa = "=0.1.0-rc.8"
```

Upstream RC bumps will not silently enter your build. When stable releases ship, Kavach will upgrade in a patch release and note the change in the security section of the release notes.

The classical primitives (Ed25519, X25519, ChaCha20-Poly1305, SHA-256, HKDF) are all at stable, long-audited versions. The hybrid composition means even if an RC bug turned out to break ML-DSA or ML-KEM, the classical leg still protects you.

## What to read next

- [key-management.md](./key-management.md): `KavachKeyPair`, `PublicKeyBundle`, directories, rotation.
- [audit.md](./audit.md): how signed audit chains use these primitives to give you tamper-evident logs.
- [gate-and-verdicts.md](./gate-and-verdicts.md): where `PermitToken` signing fits in the gate pipeline.
