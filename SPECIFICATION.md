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
AuthorityGrant
→ DelegationChain
→ ActionEnvelope
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

`RevocationEvent` may invalidate any non-terminal authority, delegation, clearance, permit, token or credential artifact.

Every authoritative artifact is wrapped in the RACS Canonical Signed Artifact Envelope.

## 4. Core objects

### 4.1 AuthorityGrant

A signed grant establishing bounded authority from a legitimate grantor to a grantee. It includes standing, action, resource, capability, purpose, validity, delegation and revocation constraints.

Normative payload schema: `spec/authority-grant-v0.2.schema.json`.

### 4.2 DelegationChain

A signed, ordered and narrowing chain derived from an AuthorityGrant. A delegation link may never expand parent scope or outlive its parent.

Normative payload schema: `spec/delegation-chain-v0.2.schema.json`.

### 4.3 ActionEnvelope

Represents one proposed action. It is not authority, admissibility or execution permission.

Required semantic bindings include action, actor, tenant, target, requested effect, connector capability, authority, delegation, policy, evidence, purpose, environment, risk, consequence, reversibility, validity and replay identity.

Normative payload schema: `spec/action-envelope-v0.2.schema.json`.

### 4.4 GovernanceEvaluation

A signed evaluator artifact containing risk, uncertainty, policy, evidence, purpose, authority and state assessments. An `ALLOW` or `MODIFY` evaluation is not execution authorization.

Normative payload schema: `spec/governance-evaluation-v0.2.schema.json`.

### 4.5 AdmissibilityDetermination

REHT's signed determination of whether the exact action is presently legitimate to progress toward execution.

Normative payload schema: `spec/admissibility-determination-v0.2.schema.json`.

### 4.6 GovernanceClearance

A signed, scoped, time-bounded and non-transferable artifact issued only by an authorized REHT issuer. It binds the full ActionEnvelope digest and the exact authority, delegation, policy, evidence, purpose, state, target, payload, connector and capability digests.

Normative payload schema: `spec/governance-clearance.schema.json`.

### 4.7 CoreExecutionPermit

A single-execution artifact presented to the deterministic enforcement core. It binds the clearance, action, connector request, replay reservation and validity interval.

Normative payload schema: `spec/core-execution-permit.schema.json`.

### 4.8 CommitToken

A short-lived, single-use artifact issued after Core verification. A bounded connector must require and consume it before creating external consequence.

Normative payload schema: `spec/commit-token-v0.2.schema.json`.

### 4.9 RevocationEvent

A signed, ordered event invalidating an authority, delegation, clearance, permit, token or credential artifact.

Normative payload schema: `spec/revocation-event-v0.2.schema.json`.

### 4.10 ContinuousIntegrityEvent

A signed event recording a material change in authority, delegation, policy, purpose, evidence, target, payload, environment, state or risk while execution is pending or active.

### 4.11 ExecutionReceipt

Records the technical attempt and external execution result. It binds the permit, token, exact payload, connector, provider reference and technical outcome.

Normative payload schema: `spec/execution-receipt-v0.2.schema.json`.

### 4.12 OutcomeReceipt

Records an observed effect after execution. It is distinct from admissibility and technical execution success.

Normative payload schema: `spec/outcome-receipt-v0.2.schema.json`.

### 4.13 ValueReceipt

Records measured and attributed value under an explicit measurement policy. It is distinct from outcome observation.

Normative payload schema: `spec/value-receipt-v0.2.schema.json`.

### 4.14 SettlementReceipt

Records an idempotent value transfer or reputation mutation bound to a verified ValueReceipt.

Normative payload schema: `spec/settlement-receipt-v0.2.schema.json`.

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
ESTABLISH AUTHORITY
  → DELEGATE WITH NARROWING
  → PROPOSE
  → EVALUATE
  → DETERMINE ADMISSIBILITY
  → ISSUE OR REFUSE CLEARANCE
  → RESERVE EXECUTION IDENTITY
  → ISSUE CORE PERMIT
  → VERIFY AT CORE
  → ISSUE SINGLE-USE COMMIT TOKEN
  → COMMIT THROUGH BOUNDED CONNECTOR
  → RECEIPT EXECUTION
  → OBSERVE OUTCOME
  → MEASURE VALUE
  → SETTLE
```

At any point before terminal completion, a material integrity change or revocation may suspend, revoke or halt execution.

## 8. Invariants

1. `EvaluationDecision(ALLOW | MODIFY) != ExecutionAuthorization`.
2. No execution without a valid, current and authentic GovernanceClearance.
3. No clearance without verified authority, delegation, policy, evidence and purpose bindings.
4. A clearance binds one exact ActionEnvelope digest.
5. A CoreExecutionPermit binds one exact clearance, target, payload, connector and capability.
6. A CommitToken is short-lived, single-use and bound to one execution identity.
7. Unknown issuer, key, schema, trust domain or revocation status fails closed.
8. Expired or revoked authority invalidates pending and active non-terminal execution.
9. Delegation may narrow but never expand authority scope.
10. Material state change requires revalidation.
11. Replay and idempotency identities are single-use and durably reserved.
12. Every terminal or indeterminate execution state produces an authoritative receipt.
13. Admissibility is not execution success.
14. Execution success is not outcome or value proof.
15. Settlement requires a verified ValueReceipt and exactly-once idempotency.
16. Refusal, halt, indeterminate, dispute and reversal are first-class states.

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

## 10. Implemented Draft 0.2 schema baseline

- canonical signed artifact envelope schema
- ActionEnvelope payload schema
- GovernanceEvaluation payload schema
- AdmissibilityDetermination payload schema
- GovernanceClearance payload schema
- CoreExecutionPermit payload schema
- CommitToken payload schema
- AuthorityGrant payload schema
- DelegationChain payload schema
- RevocationEvent payload schema
- ExecutionReceipt payload schema
- OutcomeReceipt payload schema
- ValueReceipt payload schema
- SettlementReceipt payload schema
- RACS-JCS-1 canonicalization rules
- trust model baseline and fail-closed issuer rules
- canonical GovernanceClearance digest test vector

## 11. Remaining normative work

- ContinuousIntegrityEvent schema
- revocation registry snapshot schema
- error model
- transport bindings
- schema bundle and compatibility matrix
- Python canonicalization and verification library
- Rust canonicalization and verification library
- cross-language conformance tests
- signed golden test vectors for every artifact type
- integration profiles for REHT, valo-platform and valo-v5-core
