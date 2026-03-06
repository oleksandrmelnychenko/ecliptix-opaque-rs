# Release Playbook

## Objective

Supersede the broken `v1.0.0` Apple binary release with a verified release that ships:

- curated headers from `rust/include/`
- matching `module.modulemap`
- a checksum aligned with `Package.swift`
- attested XCFramework provenance
- advisory language that documents the ABI mismatch remediation and narrowed security claims

## Pre-Release Validation

1. Run `scripts/release/smoke-release.sh`
2. Run `scripts/release/build-apple-xcframework.sh`
3. Confirm the produced XCFramework contains:
   - `opaque_common.h`
   - `opaque_agent.h`
   - `opaque_relay.h`
   - `opaque_api.h`
   - `module.modulemap`
4. Record the checksum from `dist/apple/EcliptixOPAQUE.xcframework.zip.checksum`

## Package Manifest Update

After the checksum is known, update `Package.swift`:

```bash
scripts/release/update-package-swift.sh 1.0.1 "$(tr -d '[:space:]' < dist/apple/EcliptixOPAQUE.xcframework.zip.checksum)"
```

## GitHub Release Procedure

1. Create a new release tag, for example `v1.0.1`.
2. Push the tag so `.github/workflows/build-and-publish.yml` runs.
3. Verify the workflow uploaded:
   - `EcliptixOPAQUE.xcframework.zip`
   - `EcliptixOPAQUE.xcframework.zip.checksum`
   - build attestation
4. Publish advisory text based on `docs/releases/SECURITY_ADVISORY_TEMPLATE.md`.
5. Mark `v1.0.0` as superseded in the release notes and repository-facing documentation.

## Post-Release Consumer Check

1. Re-run `swift build` against the published binary target.
2. Re-run the C smoke test against the curated headers.
3. Verify the Swift wrapper can switch from the compatibility shim to direct imported-module usage if the published XCFramework module is available as expected.

## Expected End State

- Public ABI and shipped artifact match exactly.
- Package manifest checksum matches the newly published release.
- Operators and consumers see the corrected threat model and advisory text.
