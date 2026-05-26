# kavach-pq

Post-quantum transport security for [Kavach](https://github.com/SarthiAI/Kavach). Ships NIST-approved post-quantum primitives plus the classical halves for hybrid mode, wired into a usable transport channel and a signed verdict/token layer.

## What this crate gives you

- **ML-KEM-768** (FIPS 203, formerly Kyber): key encapsulation.
- **ML-DSA-65** (FIPS 204, formerly Dilithium): digital signatures.
- **Hybrid mode** pairing the above with **X25519** and **Ed25519** so a break in either family alone does not compromise the channel.
- **ChaCha20-Poly1305** AEAD over the derived session key.
- `SecureChannel` for typed verdict transport and raw signed bytes, with replay protection through a shared nonce cache.
- `PqTokenSigner` and `DirectoryTokenVerifier` for signing and verifying Kavach permit tokens.
- `PublicKeyDirectory` with in-memory, file-backed, signed-manifest, and (optional) HTTP-backed variants.

## Status

**Experimental. Not yet thoroughly validated.**

Internal cargo tests pass and the crate is wired into the Python and Node SDKs that the consumer-validation harness exercises. Direct-Rust use of this crate alone does not yet have a published scenario catalogue. Use it, file issues, expect rough edges before 1.0.

## Crypto dependency notes

The crate pins release-candidate versions of `ml-dsa` and `ml-kem` with `=` because no stable release is published yet:

```toml
ml-dsa = "=0.1.0-rc.8"
ml-kem = "=0.3.0-rc.2"
```

Two majors of `rand_core` (0.10 and 0.6) coexist by design: the post-quantum crates use 0.10, the classical halves (`x25519-dalek 2`, `ed25519-dalek 2`) use 0.6. OS randomness goes through `getrandom`, not the `rand` crate.

## Features

- `http`: enables `HttpPublicKeyDirectory` with ETag caching, pulls in `reqwest` with `rustls-tls`.

## License

[Elastic License 2.0](https://github.com/SarthiAI/Kavach/blob/main/LICENSE). Source-available: you may embed and modify Kavach freely, but may not repackage it as a competing hosted service.
