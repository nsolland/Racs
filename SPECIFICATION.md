# RACS Specification

Status: Draft 0.2

## 1. Purpose

RACS standardizes the signed artifacts and control messages exchanged between
observation, governance, execution and evidence systems when an AI-mediated action
may affect the external world.

RACS owns wire schemas, canonical serialization, signature envelopes, trust metadata,
cross-artifact bindings, deterministic decision vocabulary and conformance semantics.

RACS does not establish human or organisational authority, determine REHT
admissibility, evaluate risk on behalf of VAIG or execute mutations.

## 2. Design principles

- Model agnostic
- Runtime and execution-substrate neutral
- Deterministic message semantics
- Explicit human and organisational authority
- Evidence-bound decisions
- Continuous validity before and during execution
- Verifiable, separate receipts
- No hidden execution authority
- Unknown trust fails closed
- Schema validity is not authority
- Capability registration is not authority
- Watcher evidence is not authority
- Recovery cannot self-authorize

## 3. Canonical artifact chain

Atomic action:

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

Active, embodied or multi-transition action:

```text
GovernedCapabilityManifest + EnvironmentGovernanceProfile
→ ActionEnvelope binding their payload digests
→ GovernanceEvaluation
→ AdmissibilityDetermination
→ GovernanceClearance
→ CoreExecutionPermit
→ CommitToken
→ GovernedExecutionSession
→ [RuntimeObservation bundle
   → ContinuityDecision
   → optional InterventionReceipt]*
→ ExecutionReceipt
→ optional RecoveryPlan
→ separately governed recovery action
→ RecoveryReceipt
→ OutcomeReceipt
```

`RevocationEvent`, `ContinuousIntegrityEvent` or applicable `HALT` may invalidate or
suspend any non-terminal authority, delegation, clearance, permit, token, session or
continuity artifact.

Every authoritative artifact is wrapped in the RACS Canonical Signed Artifact Envelope.

## 4. Core objects

### 4.1 AuthorityGrant

A signed grant establishing bounded authority from a legitimate grantor to a grantee.
It includes standing, action, resource, capability, purpose, validity, delegation and
revocation constraints.

Normative payload schema: `spec/authority-grant-v0.2.schema.json`.

### 4.2 DelegationChain

A signed, ordered and narrowing chain derived from an AuthorityGrant. A delegation
link may never expand parent scope or outlive its parent.

Normative payload schema: `spec/delegation-chain-v0.2.schema.json`.

### 4.3 ActionEnvelope

Represents one proposed action. It is not authority, admissibility or execution
permission.

Required semantic bindings include action, actor, tenant, target, requested effect,
connector capability, authority, delegation, policy, evidence, purpose, environment,
risk, consequence, reversibility, validity, replay identity and, where applicable,
the exact capability-manifest and environment-profile payload digests.

Normative payload schema: `spec/action-envelope-v0.2.schema.json`.

### 4.4 GovernanceEvaluation

A signed evaluator artifact containing risk, uncertainty, policy, evidence, purpose,
authority and state assessments. An `ALLOW` or `MODIFY` evaluation is not execution
authorization.

Normative payload schema: `spec/governance-evaluation-v0.2.schema.json`.

### 4.5 AdmissibilityDetermination

REHT's signed determination of whether the exact action is presently legitimate to
progress toward execution.

Normative payload schema: `spec/admissibility-determination-v0.2.schema.json`.

### 4.6 GovernanceClearance

A signed, scoped, time-bounded and non-transferable artifact issued only by an
authorized REHT issuer. It binds the full ActionEnvelope digest and the exact
authority, delegation, policy, evidence, purpose, state, target, payload, connector
and capability digests.

Normative payload schema: `spec/governance-clearance.schema.json`.

### 4.7 CoreExecutionPermit

A single-execution artifact presented to the deterministic enforcement core. It binds
the clearance, action, connector request, replay reservation and validity interval.

Normative payload schema: `spec/core-execution-permit.schema.json`.

### 4.8 CommitToken

A short-lived, single-use artifact issued after Core verification. A bounded connector
must require and consume it before creating external consequence.

Normative payload schema: `spec/commit-token-v0.2.schema.json`.

### 4.9 RevocationEvent

A signed, ordered event invalidating an authority, delegation, clearance, permit,
token, session, continuity decision or credential artifact.

Normative payload schema: `spec/revocation-event-v0.2.schema.json`.

### 4.10 ContinuousIntegrityEvent

A signed event recording a material change in authority, delegation, policy, purpose,
evidence, target, payload, environment, state, capability artifact, executor,
telemetry integrity or risk while execution is pending or active.

Normative payload schema: `spec/continuous-integrity-event-v0.2.schema.json`.

### 4.11 GovernedCapabilityManifest

A provider-neutral, immutable declaration of an executable capability's artifact,
interfaces, schemas, permissions, consequence classes, risk, reversibility,
environment compatibility, telemetry, postconditions, retry budget, executor binding
and supply-chain evidence.

Admission or registration never produces execution authority.

Normative payload schema: `spec/governed-capability-manifest-v0.2.schema.json`.

### 4.12 EnvironmentGovernanceProfile

A versioned environment policy and context artifact binding tenant, legal entity,
zone, human-presence mode, allowed consequence classes, runtime limits, forbidden
resources, required telemetry, independent interlocks, human roles and fail-closed
behavior.

It is evidence and policy context, not authority.

Normative payload schema: `spec/environment-governance-profile-v0.2.schema.json`.

### 4.13 GovernedExecutionSession

Represents one active execution that remains open after initial permit verification.
It binds the exact action, authority, capability manifest, environment profile,
evaluation, clearance, RACS launch decision, execution permit, principal, actor,
executor, deadline, heartbeat and monotonic continuity sequence.

Normative payload schema: `spec/governed-execution-session-v0.2.schema.json`.

### 4.14 RuntimeObservation

A source-bound runtime observation containing sequence, time, signal class, value or
digest, quality, uncertainty, freshness, integrity evidence and environment-profile
binding.

A RuntimeObservation is evidence. Agent self-report is a separate source class and
simulator oracle labels are never production evidence.

Normative payload schema: `spec/runtime-observation-v0.2.schema.json`.

### 4.15 ContinuityDecision

A deterministic RACS decision governing the next consequential interval or transition
of an active session.

Vocabulary:

- `CONTINUE`
- `MODIFY_RUNTIME_BOUNDS`
- `PAUSE`
- `STOP`
- `REAUTHORIZE`
- `ROLLBACK`
- `HANDOVER`
- `HALT`

`CONTINUE` preserves existing bounds. `MODIFY_RUNTIME_BOUNDS` may only narrow.
`ROLLBACK` identifies required governed recovery and does not authorize recovery by
itself. `HALT` dominates all outstanding continuity decisions.

Normative payload schema: `spec/continuity-decision-v0.2.schema.json`.

### 4.16 InterventionReceipt

Records whether a runtime intervention was applied, partially applied, failed or not
applicable, binding the session, continuity decision, executor and before/after state.

Normative payload schema: `spec/intervention-receipt-v0.2.schema.json`.

### 4.17 RecoveryPlan

A bounded, evidence-only proposal binding the source incident or intervention,
recovery capability, recovery ActionEnvelope, rollback authority, safe target,
budget, termination conditions and human roles.

`carries_execution_authority` is fixed to `false`.

Normative payload schema: `spec/recovery-plan-v0.2.schema.json`.

### 4.18 RecoveryReceipt

Records the technical recovery attempt and verified postcondition evidence. A failed
recovery leaves the governed session halted.

Normative payload schema: `spec/recovery-receipt-v0.2.schema.json`.

### 4.19 ExecutionReceipt

Records the technical attempt and external execution result. It binds the permit,
token, exact payload, connector, provider reference and technical outcome.

Normative payload schema: `spec/execution-receipt-v0.2.schema.json`.

### 4.20 OutcomeReceipt

Records an observed effect after execution or recovery. It is distinct from
admissibility and technical execution success.

Normative payload schema: `spec/outcome-receipt-v0.2.schema.json`.

### 4.21 ValueReceipt

Records measured and attributed value under an explicit measurement policy. It is
distinct from outcome observation.

Normative payload schema: `spec/value-receipt-v0.2.schema.json`.

### 4.22 SettlementReceipt

Records an idempotent value transfer or reputation mutation bound to a verified
ValueReceipt.

Normative payload schema: `spec/settlement-receipt-v0.2.schema.json`.

## 5. Signed artifact envelope

All authoritative artifacts MUST conform to
`spec/canonical-artifact-envelope.schema.json`.

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

A payload MUST NOT contain its own current digest. The envelope `payload_digest` is
computed over RACS-JCS-1 canonical bytes. Previous-artifact digests may appear for
chain binding.

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

Runtime continuity decisions:

- `CONTINUE`
- `MODIFY_RUNTIME_BOUNDS`
- `PAUSE`
- `STOP`
- `REAUTHORIZE`
- `ROLLBACK`
- `HANDOVER`
- `HALT`

Only valid REHT clearance and downstream Core artifacts may progress toward launch.
Evaluation decisions, capability admission, watcher alarms, environment profiles,
human-presence flags and recovery plans never directly authorize execution.

## 7. Protocol flow

```text
ESTABLISH AUTHORITY
→ DELEGATE WITH NARROWING
→ REGISTER AND VERIFY CAPABILITY WHERE REQUIRED
→ BIND ENVIRONMENT PROFILE WHERE REQUIRED
→ PROPOSE EXACT ACTION
→ EVALUATE
→ DETERMINE ADMISSIBILITY
→ ISSUE OR REFUSE CLEARANCE
→ RESERVE EXECUTION IDENTITY
→ ISSUE CORE PERMIT
→ VERIFY AT CORE
→ ISSUE SINGLE-USE COMMIT TOKEN
→ COMMIT THROUGH BOUNDED CONNECTOR
→ OPEN GOVERNED SESSION WHEN EXECUTION REMAINS ACTIVE
→ OBSERVE RUNTIME STATE
→ ISSUE AND ENFORCE CONTINUITY DECISIONS
→ RECEIPT INTERVENTIONS AND EXECUTION
→ GOVERN RECOVERY THROUGH THE NORMAL ACTION CHAIN
→ OBSERVE OUTCOME
→ MEASURE VALUE
→ SETTLE
```

At any point before terminal completion, material integrity change, revocation or HALT
may suspend, revoke or halt execution.

## 8. Invariants

1. `EvaluationDecision(ALLOW | MODIFY) != ExecutionAuthorization`.
2. No execution without a valid, current and authentic GovernanceClearance.
3. No clearance without verified authority, delegation, policy, evidence and purpose.
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
17. Capability registration or manifest presence is not authority.
18. Watcher observations and alarms are evidence, not authorization.
19. No active session without exact action, authority, capability, profile, clearance and permit binding.
20. Continuity sequence is monotonic and replay protected.
21. No consequential transition without a current ContinuityDecision.
22. `MODIFY_RUNTIME_BOUNDS` may only narrow existing authorization.
23. Changed intent, target, payload, principal, executor or consequence requires reauthorization.
24. Revocation and HALT dominate `CONTINUE`, handover and recovery.
25. Recovery cannot self-authorize or inherit unlimited authority from a failed action.
26. Failed recovery leaves the system halted.
27. Execution, intervention, recovery and outcome remain separate artifacts.
28. Missing mandatory telemetry follows the bound fail-closed profile.
29. Simulator oracle labels never enter the production decision path.
30. Low-level independent safety interlocks cannot be disabled by RACS.

## 9. Conformance profiles

Conformance profiles apply to:

- artifact producers
- governance evaluators
- REHT clearance issuers
- deterministic enforcement cores
- bounded execution adapters
- receipt and revocation stores
- continuous-integrity monitors
- capability registries
- environment-profile issuers
- runtime watchers and observation producers
- active-session managers
- intervention and recovery executors
- outcome and settlement issuers

## 10. Draft 0.2 schema baseline

Implemented or specified:

- canonical signed artifact envelope
- ActionEnvelope
- GovernanceEvaluation
- AdmissibilityDetermination
- GovernanceClearance
- CoreExecutionPermit
- CommitToken
- AuthorityGrant
- DelegationChain
- RevocationEvent
- ContinuousIntegrityEvent
- GovernedCapabilityManifest
- EnvironmentGovernanceProfile
- GovernedExecutionSession
- RuntimeObservation
- ContinuityDecision
- InterventionReceipt
- RecoveryPlan
- RecoveryReceipt
- ExecutionReceipt
- OutcomeReceipt
- ValueReceipt
- SettlementReceipt
- RACS-JCS-1 canonicalization
- trust model and fail-closed issuer rules
- cross-language runtime-continuity golden vectors

Normative runtime-continuity detail:
`spec/RUNTIME_CONTINUITY_V0_2.md`.

## 11. AgentBound delta profile

The AgentBound-inspired v0.3 delta is an additive execution-governance profile. It
extends the v0.2 chain with four artifacts:

- `TaskAuthorityMaterialization` — current, short-lived and strictly narrower task authority;
- `TargetActionContract` — authenticated semantics for the exact consequential target operation;
- `AuthorityEvaluationFragment` — typed input to monotone hierarchy composition;
- `GovernanceReplayBundle` — portable evidence for deterministic offline reconstruction.

Normative payload schemas:

- `spec/task-authority-materialization-v0.3.schema.json`
- `spec/target-action-contract-v0.3.schema.json`
- `spec/authority-evaluation-fragment-v0.3.schema.json`
- `spec/governance-replay-bundle-v0.3.schema.json`

The profile does not create an AgentBound runtime, a second constitution, a new
clearance authority, a reduced decision vocabulary or a new receipt family.

A standing authority grant MUST NOT reach a consequence-bearing commit directly when
this profile is required. It MUST first become a current, narrower task authority.
Target contracts describe operation semantics and can only narrow execution; they
never grant principal authority. Mandatory evaluation fragments compose
monotonically: constraints intersect, obligations union, and a lower-level favourable
result cannot erase a higher-level restriction. Replay produces only `MATCH`,
`MISMATCH`, `INCOMPLETE` or `UNVERIFIABLE` and has no execution authority.

A v0.2 implementation remains conformant to its declared v0.2 profile. It MUST NOT
claim the AgentBound-delta profile without the complete mandatory v0.3 artifacts and
bindings for the relevant action class. A v0.3-aware consumer MUST fail closed when a
referenced v0.3 artifact is absent, stale, revoked, substituted or unverifiable.

Full compatibility and migration rules:
`spec/AGENTBOUND_DELTA_V0_2_V0_3_COMPATIBILITY.md`.

Prior-art classification and correct interpretation of the committed deterministic
reference benchmark:
`docs/architecture/AGENTBOUND_PRIOR_ART_AND_BENCHMARK_INTERPRETATION.md`.

## 12. Remaining normative work

- revocation registry snapshot schema
- transport bindings
- complete schema bundle and compatibility matrix beyond the AgentBound delta
- signed golden vectors for all legacy artifact types
- active-session cross-artifact verification rules
- narrowing proof for `MODIFY_RUNTIME_BOUNDS`
- reauthorization and handover integration profile
- Core state-transition conformance profile
- public integration profiles for REHT, valo-platform and valo-v5-core
