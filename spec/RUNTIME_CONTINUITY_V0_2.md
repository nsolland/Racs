# RACS Draft 0.2 — Runtime Continuity Extension

Status: Draft implementation profile  
Source motivation: arXiv:2604.07833  
Canonical decision owner: RACS  
Canonical authority and clearance chain: unchanged

## 1. Purpose

This extension defines wire contracts for consequence-bearing executions that remain active after the initial commit boundary or contain multiple consequential transitions.

It extends the existing RACS chain. It does not create a parallel runtime-governance authority.

```text
AuthorityGrant
→ DelegationChain
→ ActionEnvelope
→ GovernanceEvaluation
→ AdmissibilityDetermination
→ GovernanceClearance
→ CoreExecutionPermit
→ CommitToken
→ GovernedExecutionSession
→ RuntimeObservation*
→ ContinuityDecision*
→ InterventionReceipt*
→ ExecutionReceipt
→ RecoveryPlan / governed recovery action
→ RecoveryReceipt
→ OutcomeReceipt
```

`GovernedCapabilityManifest` and `EnvironmentGovernanceProfile` are separately signed payloads whose digests are bound into the ActionEnvelope and session. `*` indicates repeatable, sequence-bound artifacts during an active execution.

## 2. Architectural boundary

The agent, capability package, watcher, environment profile and recovery planner are not authority sources.

The watcher produces evidence. RACS carries the deterministic continuity decision. The enforcement core or bounded adapter applies the decision.

Low-level functional-safety interlocks remain independent. RACS governs mission, capability, consequential transitions, handover and recovery envelopes; it does not replace servo, collision, electrical or mechanical safety controls.

## 3. Payload digests

These schemas define payloads carried by the existing canonical signed artifact envelope.

A payload MUST NOT contain its own current digest. Its authoritative digest is the envelope `payload_digest`, computed over RACS-JCS-1 canonical bytes. Previous-artifact digests MAY appear for chain binding.

This avoids recursive self-digest fields and preserves the existing signed-artifact model.

## 4. GovernedCapabilityManifest

Normative schema: `spec/governed-capability-manifest-v0.2.schema.json`.

A manifest binds an immutable executable artifact, interfaces, input and output schemas, permissions, consequence classes, risk, reversibility, telemetry, postconditions, environment compatibility, retry budget, executor identity and supply-chain evidence.

Registration or admission of a manifest never authorizes execution.

Rules:

1. The exact manifest payload digest MUST be bound into the ActionEnvelope, clearance, permit and active session.
2. Artifact, interface, schema or controller/model changes invalidate prior admission and downstream authorization.
3. Capability permissions are intersected with authority; they never widen it.
4. `REVERSIBLE` requires an explicit rollback capability reference.
5. Missing mandatory postcondition, telemetry or executor binding fails closed for consequence-bearing capabilities.

## 5. EnvironmentGovernanceProfile

Normative schema: `spec/environment-governance-profile-v0.2.schema.json`.

The profile expresses environment, tenant, legal-entity, zone, human-presence, consequence, runtime-limit, telemetry, interlock and fail-closed constraints.

The profile is policy and context evidence, not authority.

A material profile change while execution is active MUST produce `PAUSE`, `REAUTHORIZE` or `HALT` according to the bound policy and consequence class.

## 6. GovernedExecutionSession

Normative schema: `spec/governed-execution-session-v0.2.schema.json`.

A session binds one launched execution to the exact:

- ActionEnvelope
- authority state
- capability manifest
- environment profile
- GovernanceEvaluation
- REHT clearance
- RACS launch decision
- execution permit
- principal, actor and executor

Valid session states are:

```text
PREPARED
ACTIVE
PAUSED
REAUTHORIZATION_REQUIRED
RECOVERY_PENDING
ROLLING_BACK
HANDED_OVER
COMPLETED
FAILED
STOPPED
HALTED
```

The continuity sequence is monotonic. Replayed, skipped or reordered sequence transitions fail closed.

## 7. RuntimeObservation

Normative schema: `spec/runtime-observation-v0.2.schema.json`.

Runtime observations are evidence and MUST carry source identity, sequence, timestamp, signal class, quality, freshness, integrity evidence and environment-profile binding.

Exactly one of `signal_value` or `signal_digest` MUST be present.

`timestamp_ns` is a decimal string. Nanosecond epoch values exceed the interoperable JSON integer range and would otherwise break byte-identical Python, Rust and TypeScript digests.

Production governance MUST NOT consume simulator oracle labels as runtime evidence. Agent self-report is a separate, lower-trust source class.

Missing required telemetry, stale heartbeat, watcher failure or conflicting evidence MUST be represented explicitly and handled under the environment profile's fail-closed policy.

## 8. ContinuityDecision

Normative schema: `spec/continuity-decision-v0.2.schema.json`.

The continuity vocabulary is:

```text
CONTINUE
MODIFY_RUNTIME_BOUNDS
PAUSE
STOP
REAUTHORIZE
ROLLBACK
HANDOVER
HALT
```

Semantics:

- `CONTINUE`: the existing clearance remains valid inside its current bounds.
- `MODIFY_RUNTIME_BOUNDS`: narrows already-authorized runtime bounds. It MUST NOT widen authority, purpose, target, payload, resource, duration, speed, rate, zone or exposure.
- `PAUSE`: prevents the next consequential transition while preserving the session for review.
- `STOP`: terminates the active execution without authorizing recovery.
- `REAUTHORIZE`: returns the proposed continuation or changed action through evaluation, REHT clearance and RACS decision.
- `ROLLBACK`: identifies that governed rollback is required. It does not itself authorize the rollback action.
- `HANDOVER`: requires a separately bound executor identity and authority. It cannot widen mandate.
- `HALT`: immediately dominates all outstanding permits and continuity decisions.

A `CONTINUE` artifact MUST NOT add constraints or authority. `MODIFY_RUNTIME_BOUNDS` requires explicit constraints.

## 9. InterventionReceipt

Normative schema: `spec/intervention-receipt-v0.2.schema.json`.

Every applied, partially applied, failed or inapplicable intervention produces a receipt binding the session, continuity decision, intervention type, executor and before/after state digests.

An intervention receipt proves what was attempted or applied. It does not prove recovery or final outcome.

## 10. RecoveryPlan and RecoveryReceipt

Normative schemas:

- `spec/recovery-plan-v0.2.schema.json`
- `spec/recovery-receipt-v0.2.schema.json`

A RecoveryPlan is evidence and a proposal. `carries_execution_authority` is fixed to `false`.

A rollback, retract, compensation, repair or alternate-executor action that creates consequence requires:

```text
new or bound ActionEnvelope
→ GovernanceEvaluation
→ REHT admissibility and clearance
→ RACS decision
→ CoreExecutionPermit
→ CommitToken
→ bounded execution
```

A narrowly scoped independent emergency stop may be pre-authorized, but subsequent movement or repair does not inherit unlimited authority from that stop.

Failed recovery MUST leave the system halted. Recovery success requires postcondition evidence and a RecoveryReceipt.

## 11. Dominance and revalidation rules

The following events invalidate or suspend active continuity:

- revocation of principal, authority, delegation, clearance, permit or executor
- global or applicable scoped HALT
- capability artifact or manifest change
- environment-profile change
- principal, actor or executor change
- target, payload, purpose or consequence change
- telemetry loss or integrity failure where mandatory
- sequence replay, skip or reordering
- material actual-versus-approved side-effect delta
- elapsed session deadline
- recovery budget exhaustion

`HALT` and revocation dominate `CONTINUE`, `MODIFY_RUNTIME_BOUNDS`, `HANDOVER` and recovery.

## 12. Atomic-action compatibility

Atomic actions whose bounded external consequence completes within one commit retain the existing RACS flow and do not require a long-running session.

A session is required when at least one condition applies:

- execution remains active after commit
- multiple consequential transitions occur
- environment or physical state can change materially during execution
- repeated runtime evidence is required
- intervention, handover or governed recovery may be necessary

## 13. Conformance invariants

1. No active session without a valid launch permit and exact artifact bindings.
2. No consequential transition without a current continuity decision.
3. Watcher evidence cannot directly authorize execution or recovery.
4. `MODIFY_RUNTIME_BOUNDS` may only narrow.
5. Changed consequential intent requires re-evaluation.
6. Revocation and HALT block active sessions, not only new launches.
7. Recovery cannot self-authorize.
8. Human handover requires identity, mandate and authority binding.
9. Missing mandatory telemetry follows the bound fail-closed policy.
10. Every intervention and terminal state produces an authoritative receipt.
11. Execution, intervention, recovery and observed outcome remain separate artifacts.
12. Simulator oracle labels never enter the production decision path.

## 14. Contract ownership

RACS owns the wire schemas, canonical serialization, artifact bindings, decision vocabulary and conformance semantics.

REHT owns admissibility and clearance for the exact proposed action or reauthorization.

VAIG supplies evidence and risk evaluation.

The deterministic core enforces permit, revocation, HALT and continuity decisions.

Execution substrates and bounded adapters supply telemetry, apply decisions and return receipts. They cannot widen any bound artifact.
