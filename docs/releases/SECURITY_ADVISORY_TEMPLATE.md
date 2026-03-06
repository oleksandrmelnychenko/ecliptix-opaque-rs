# Security Advisory Template

## Summary

This release supersedes earlier binary packaging and documentation states.

## Included Remediations

- Canonical ABI now comes from the curated headers in `rust/include/`.
- Apple packaging path is aligned to the curated headers and module map.
- FFI regression tests and downstream consumer smoke validation were added.
- Threat-model language now scopes offline dictionary resistance to DB compromise
  without `oprf_seed` compromise.
- Formal-verification language now distinguishes surrogate symbolic models from
  exact implementation proofs.

## Impacted Consumers

- Swift / Apple consumers using the XCFramework.
- C consumers compiling against previously shipped stale headers.
- Operators who treat database compromise and `oprf_seed` compromise as equivalent events.

## Operator Actions

1. Upgrade to the superseding release.
2. Rebuild downstream bindings from the curated headers.
3. Review `docs/security-review/OPRF_SEED_OPERATIONAL_GUIDANCE.md`.
4. Audit whether any environment exposed both registration records and `oprf_seed`.

## Disclosure Notes

- ABI/header mismatch: fixed by the canonical header packaging path.
- `oprf_seed` compromise boundary: now explicitly documented as a critical operator secret.
- Formal-evidence scope: narrowed to symbolic-model coverage plus computational tests.
