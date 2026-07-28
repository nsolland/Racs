# RACS Draft 0.2 — Runtime Continuity Verification Profile

Status: Draft implementation profile  
Canonical decision owner: RACS  
Authority source: unchanged

## 1. Purpose

This profile defines cross-artifact verification for `GovernedExecutionSession` and `ContinuityDecision` payloads. Verification produces evidence and verified types. It does not create execution authority.

## 2. Session verification

An active session is valid only when it binds the exact supplied artifacts by RACS-JCS-1 payload digest:

- `GovernedCapabilityManifest`
- `EnvironmentGovernanceProfile`
- `GovernanceEvaluation`
- `GovernanceClearance`

The verifier MUST also prove:

1. Session, evaluation and clearance bind the same ActionEnvelope.
2. Session authority equals the clearance authority state.
3. Profile, evaluation and clearance bind the same tenant.
4. The executor is admitted by the capability manifest.
5. The cleared capability is present in manifest permissions.
6. The consequence class is admitted by both manifest and environment profile.
7. The manifest references the exact profile identity or `profile_id@profile_version`.
8. Evaluation and clearance are executable states.
9. Every artifact is current at verification time.
10. The session deadline does not exceed any bound artifact validity window.
11. Terminal sessions cannot receive new continuity authorization.

A failed check returns a normalized reason code and MUST fail closed.

## 3. Runtime-bound narrowing proof

`MODIFY_RUNTIME_BOUNDS` is valid only when every proposed bound is equal to or stricter than the current effective bound and at least one bound becomes strictly narrower.

The proof rules are:

- numeric upper bounds: proposed value MUST be lower or equal
- numeric minimum or floor bounds: proposed value MUST be higher or equal
- allowed sets: proposed members MUST be a subset of current members
- deadlines and expiry bounds: proposed time MUST be earlier or equal
- nested objects: rules apply recursively
- booleans and ordinary strings: changes are rejected unless direction semantics are explicitly defined
- unknown dimensions: rejected as `BOUNDS_UNPROVABLE`
- no-op modifications: rejected as `BOUNDS_NOT_NARROWER`

The verifier never assumes that an unknown field is restrictive. Ambiguity fails closed.

## 4. Continuity-decision verification

A continuity decision MUST:

1. bind the active session identity
2. increment `continuity_sequence` by exactly one
3. bind the same ActionEnvelope, capability manifest, environment profile and authority state
4. remain valid at verification time
5. expire no later than the session deadline
6. pass the narrowing proof when the decision is `MODIFY_RUNTIME_BOUNDS`

`HALT`, revocation and terminal session state remain dominant.

## 5. Normalized result

All bindings return:

```json
{
  "decision": "ACCEPT | REJECT",
  "reason_code": "NORMALIZED_REASON_CODE",
  "detail": "optional diagnostic",
  "effective_bounds": "present only after a proven narrowing"
}
```

Python, Rust and TypeScript MUST return identical `decision` and `reason_code` values for the shared verification vectors.

## 6. Ownership boundary

RACS owns the verification semantics, reason-code vocabulary and monotonicity proof.

REHT owns admissibility and clearance for changed consequential intent.

Core and bounded adapters enforce verified decisions. A verifier result is not a permit, commit token or execution receipt.
