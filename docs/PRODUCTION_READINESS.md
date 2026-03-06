# Production Readiness

## Required Conditions

The project should be treated as production-ready only when all of the following hold:

- Curated headers from `rust/include/` are the only published ABI contract.
- The Apple XCFramework is rebuilt from the curated headers and ships a matching module map.
- CI enforces blocking `cargo audit`, blocking `cargo-deny`, Swift package build, and C smoke validation.
- `oprf_seed` handling follows `docs/security-review/OPRF_SEED_OPERATIONAL_GUIDANCE.md`.
- Public documentation uses the scoped threat model from `docs/security-review/THREAT_MODEL.md`.

## What Production Means Here

- The code is suitable for deployments that can protect relay secret material, especially
  the relay private key and `oprf_seed`.
- The release process must publish checksums and provenance for the shipped XCFramework.
- Consumers must pin the relay public key correctly and run the protocol over authenticated transport.

## What Production Does Not Mean

- It does not mean that compromise of `oprf_seed` is benign.
- It does not mean the symbolic models are an exact proof of the shipping implementation.
- It does not eliminate the need for rate-limiting, observability, secret rotation planning,
  and incident response procedures in the integrating system.

## Recommended Validation Before Release

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace --tests --lib --locked`
4. `swift build`
5. C consumer smoke compile against `rust/include/opaque_api.h`

## Release Artifacts

- Rust crates / native libraries built from the pinned toolchain.
- Apple XCFramework packaged with curated headers and `module.modulemap`.
- Published checksum and artifact attestation.
- Advisory text describing ABI fixes, threat-model narrowing, and new verification gates.
