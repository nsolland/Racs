# Revocation Registry Snapshot (P0.2, issue #138)

Status: NORMATIVE.

Canonical snapshot of the append-only revocation registry. A revoked
authority, token, permit, clearance, determination or capability manifest has
a deterministic, verifiable revocation record — it can never appear active by
omission or by an old serialized copy.

## Semantic model

- The revocation registry is **append-only**: a revocation is an immutable,
  ordered event keyed by `revocation_id` and bound to the registry tail.
- A **snapshot** is a deterministic, self-describing view of the registry at a
  point in time, signed by the registry issuer.
- `registry_end_sha256` binds the snapshot to the exact registry tail so a
  verifier can confirm the snapshot matches the authoritative registry.
- `previous_snapshot_sha256` chains snapshots (hash-chained), making the
  history tamper-evident (WORM-like).

## Rules (R1–R4)

1. **R1 — revocation is not a field edit.** Revoking a subject adds an
   append-only revocation record; it never mutates the subject artifact.
2. **R2 — verifiers must consult the registry.** Validation of a token/permit
   MUST consult the authoritative revocation registry (or a snapshot bound to
   the current registry tail), not only the serialized artifact.
3. **R3 — fail closed.** If the registry (or a valid snapshot) is unavailable,
   validation fails closed: the subject is treated as not-active.
4. **R4 — signature binding.** Every revocation record carries a signature, so
   a forged or reordered record is detectable. Snapshots carry `snapshot_sha256`
   over the canonical (RFC 8785) serialization of the snapshot payload.

## Schema

`revocation-registry-snapshot-v0.2.schema.json`.

`subject_type` vocabulary:

- `AUTHORITY` — revoked authority grant.
- `TOKEN` — revoked access/commit token.
- `PERMIT` — revoked executed-action permit.
- `CLEARANCE` — revoked REHT clearance.
- `DETERMINATION` — revoked admissibility determination.
- `CAPABILITY_MANIFEST` — revoked capability artifact.

## Conformance

A conforming implementation MUST:

- emit and verify snapshots in the canonical (RFC 8785) digest form;
- chain snapshots via `previous_snapshot_sha256` (except the first);
- fail closed when no registry/snapshot is available;
- never accept a revoked subject on the strength of the original artifact
  signature alone (see PersonalDataVault issue #4 class of finding).