# RACS Specification

Status: Draft 0.2

## 1. Purpose

RACS standardizes the signed artifacts and control messages exchanged between observation, governance, execution and evidence systems when an AI-mediated action may affect the external world.

RACS owns wire schemas, canonical serialization, signature envelopes, trust metadata, cross-artifact bindings and conformance semantics. RACS does not decide whether an action is admissible and does not execute mutations.

## 2. Design principles

- Model agnostic
- Runtime neutral
- Deterministic message semantics
- Explicit authority
- Evidence-bound decisions
- Continuous validity
- Verifiable receipts
- No hidden execution authority
- Unknown trust fails closed
- Schema validity is not authority

## 3. Canonical artifact chain

```text
ActionEnvelope
→ GovernanceEvaluation
→ AdmissibilityDetermination
→ GovernanceClearance
→ CoreExecutionPermit
→ CommitToken
→ ExecutionReceipt
→ OutcomeReceipt
→ ValueReceipt
→ SettlementReceipt
```

Every authoritative artifact is wrapped in the RACS Canonical Signed Artifact Envelope.

## 4. Core objects

### 4.1 ActionEnvelope

Represents one proposed action. It is not authority, admissibility or execution permission.

Required semantic bindings include action, actor, tenant, target, requested effect, connector capability, authority, delegation, policy, evidence, purpose, environment, state, risk, consequence, reversibility, validity and replay identity.

### 4.2 GovernanceEvaluation

A signed evaluator artifact containing risk, uncertainty, policy, evidence and context assessments. An `ALLOW` or `MODIFY` evaluation is not execution authorization.

### 4.3 AdmissibilityDetermination

REHT's determination of whether the exact action is presently legitimate to progress toward execution.

### 4.4 GovernanceClearance

A signed, scoped, time-bounded and non-transferable artifact issued only by an authorized REHT issuer. It binds the full ActionEnvelope digest and the exact authority, delegation, policy, evidence, purpose, state, target, payload, connector and capability digests.

Normative payload schema: `spec/governance-clearance.schema.json`.

### 4.5 CoreExecutionPermit

A single-execution artifact presented to the deterministic enforcement core. It binds the clearance, action, connector request, replay reservation and validity interval.

Normative payload schema: `spec/core-execution-permit.schema.json`.

### 4.6 ContinuousIntegrityEvent

A signed event recording a material change in authority, delegation, policy, purpose, evidence, target, payload, environment, state or risk while execution is pending or active.

### 4.7 ExecutionReceipt

Records the technical attempt and external execution result. It must bind the permit, exact payload, connector, external transaction reference and technical outcome.

### 4.8 OutcomeReceipt

Records an observed effect after execution. It is distinct from admissibility and technical execution success.

### 4.9 ValueReceipt

Records measured and attributed value under an explicit measurement policy. It is distinct from outcome observation.

### 4.10 SettlementReceipt

Records an idempotent value transfer or reputation mutation bound to a verified ValueReceipt.

## 5. Signed artifact envelope

All authoritative artifacts MUST conform to `spec/canonical-artifact-envelope.schema.json`.

The envelope binds:

- artifact type and schema version
- profile
- artifact and tenant identity
- trust domain
- issuer identity and role
- issuance and expiry
- canonical payload digest
- signing algorithm and key ID
- signature

Canonical serialization is defined by `spec/CANONICALIZATION.md`.

Trust resolution and fail-closed rules are defined by `spec/TRUST_MODEL.md`.

## 6. Decision vocabulary

Governance evaluation decisions:

- `ALLOW`
- `MODIFY`
- `DEFER`
- `DENY`
- `STEP_UP`
- `HALT`

Only a valid GovernanceClearance may progress toward execution. Evaluation decisions never directly authorize execution.

## 7. Protocol flow

```text
PROPOSE
  → EVALUATE
  → DETERMINE ADMISSIBILITY
  → ISSUE OR REFUSE CLEARANCE
  → RESERVE EXECUTION IDENTITY
  → ISSUE CORE PERMIT
  → VERIFY AT CORE
  → COMMIT THROUGH BOUNDED CONNECTOR
  → RECEIPT EXECUTION
  → OBSERVE OUTCOME
  → MEASURE VALUE
  → SETTLE
```

At any point before terminal completion, a material integrity change may suspend, revoke or halt execution.

## 8. Invariants

1. `EvaluationDecision(ALLOW | MODIFY) != ExecutionAuthorization`.
2. No execution without a valid, current and authentic GovernanceClearance.
3. No clearance without verified authority, delegation, policy, evidence and purpose bindings.
4. A clearance binds one exact ActionEnvelope digest.
5. A CoreExecutionPermit binds one exact clearance, target, payload, connector and capability.
6. Unknown issuer, key, schema, trust domain or revocation status fails closed.
7. Expired or revoked authority invalidates pending and active non-terminal execution.
8. Material state change requires revalidation.
9. Replay and idempotency identities are single-use and durably reserved.
10. Every terminal or indeterminate execution state produces an authoritative receipt.
11. Admissibility is not execution success.
12. Execution success is not outcome or value proof.
13. Refusal, halt, indeterminate and reversal are first-class outcomes.

## 9. Conformance

Conformance profiles will be published for:

- artifact producers
- governance evaluators
- REHT clearance issuers
- deterministic enforcement cores
- bounded execution adapters
- receipt and revocation stores
- continuous-integrity monitors
- outcome and settlement issuers

## 10. Implemented Draft 0.2 baseline

- canonical signed artifact envelope schema
- GovernanceClearance payload schema
- CoreExecutionPermit payload schema
- RACS-JCS-1 canonicalization rules
- trust model baseline and fail-closed issuer rules

## 11. Remaining normative work

- complete ActionEnvelope schema
- GovernanceEvaluation and AdmissibilityDetermination schemas
- authority and delegation grammar
- revocation event schema and registry schema
- CommitToken schema
- execution, outcome, value and settlement receipt schemas
- error model
- transport bindings
- cross-language conformance implementation
- signed golden test vectors
