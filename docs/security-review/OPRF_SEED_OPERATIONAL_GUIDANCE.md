# OPRF Seed Operational Guidance

## Purpose

`oprf_seed` is a production-critical relay secret. In this implementation it is the root
material from which per-account OPRF keys are derived deterministically. Treat it like a
master secret, not like ordinary configuration.

## Security Consequences

- DB compromise without `oprf_seed` compromise: stolen registration records are still not
  directly offline-verifiable; the attacker must still recover or query the OPRF secret.
- `oprf_seed` compromise without DB compromise: attacker gains the ability to verify stolen
  registration records if they later obtain them, and to emulate the OPRF side of the relay.
- DB compromise plus `oprf_seed` compromise: offline dictionary attacks against registration
  records become feasible.

## Storage Requirements

- Store `oprf_seed` in the same class of secret storage as the relay private key.
- Prefer HSM, KMS, or vault-backed secret delivery over flat files or environment variables.
- Keep audit logs for read/access events.
- Never embed `oprf_seed` in client artifacts, CI logs, screenshots, or test fixtures.

## Rotation Guidance

- Rotation is **not** transparent.
- Rotating `oprf_seed` invalidates the derived OPRF key space for existing registrations.
- Safe rotation therefore requires planned user re-enrollment or a migration design that
  preserves old and new seeds during a bounded transition.

## Incident Response

If `oprf_seed` is suspected compromised:

1. Treat all stored registration records as exposed to offline verification.
2. Revoke the affected relay deployment and rotate the relay private key.
3. Force or stage re-enrollment for affected accounts.
4. Publish a security advisory that clearly distinguishes DB-only compromise from
   `oprf_seed` compromise.
5. Review access logs for vault/KMS/HSM reads and correlated DB export activity.

## Monitoring

- Alert on secret read frequency anomalies.
- Alert on unusual database export volume or snapshot creation.
- Track which deployments and environments share the same `oprf_seed`.

## Release Checklist

- Release notes state the exact trust boundary around `oprf_seed`.
- Threat model and risk register match the implemented behaviour.
- Regression coverage for the `oprf_seed` compromise boundary remains present in the repo.
