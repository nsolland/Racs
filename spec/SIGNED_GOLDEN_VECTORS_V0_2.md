# Signed Golden Vectors (P0.2, issue #141)

Status: NORMATIVE.

Signed golden vectors for all legacy artifact types. A golden vector is a
fixed input → expected canonical digest + expected verdict/decision pair that
a conforming implementation MUST reproduce exactly. This makes canonicalization
and decision semantics machine-verifiable.

## Rules (G1–G3)

1. **G1 — canonical digest.** Every vector pins the RFC 8785 canonical digest
   (`sha256:<hex>`). Implementations MUST reproduce the digest byte-for-byte
   from the vector's canonical input.
2. **G2 — decision semantics.** Decision vectors pin the expected
   ALLOW / MODIFY / DEFER / DENY / STEP_UP / HALT outcome from the
   `CANONICAL_VERDICT_MAPPING.md` rules.
3. **G3 — signed vectors.** Vectors are signed by the registry/issuer key; a
   conforming verifier rejects unsigned or mismatched vectors (fail closed).

## Vector set

Golden vectors live in `test-vectors/0.2/` and `test-vectors/0.3/` alongside
the existing `jcs/` canonicalization vectors. Legacy artifact types covered:

- Action Envelope (`action-envelope-v0.2`)
- Authority Context (`authority-context`)
- Governance Evaluation (`governance-evaluation-v0.2`)
- Admissibility Determination (`admissibility-determination-v0.2`)
- Clearance (`governance-clearance`)
- Execution Receipt (`execution-receipt-v0.2`, `-v0.3`)
- Outcome Receipt (`outcome-receipt-v0.2`)
- Continuous Integrity Event (`continuous-integrity-event-v0.2`)
- Runtime Observation (`runtime-observation-v0.2`)
- Revocation Registry Snapshot (`revocation-registry-snapshot-v0.2`)

## Vector record shape

Each vector is a JSON object:

```json
{
  "vector_id": "v0.2/action-envelope/001",
  "artifact_type": "action-envelope-v0.2",
  "input": { "...": "canonical input payload" },
  "expected_canonical_digest": "sha256:...",
  "expected_decision": "ALLOW",
  "signature": "signed by issuer"
}
```

## Conformance

A conforming implementation MUST pass every golden vector for the artifact
types it implements, including the negative vectors (DENY / fail-closed cases).