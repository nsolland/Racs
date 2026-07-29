# RACS Decision Binding v0.2

## Purpose

This profile closes the gap between a verified REHT `GovernanceClearance` and a Core-issued `CoreExecutionPermit`.

```text
ActionEnvelope
  -> BoundaryCrossingAssessment
  -> GovernanceEvaluation[]
  -> AdmissibilityDetermination
  -> REHT GovernanceClearance
  -> RACSDecision
  -> CoreExecutionPermit
  -> CommitToken
  -> bounded connector
  -> ExecutionReceipt
```

`GovernanceClearance` remains the sole positive authorization artifact produced by REHT. `RACSDecision` is a signed runtime binding decision. It does not originate authority, repair missing authority, or directly permit execution. Core remains the only component that issues an execution permit, and bounded connectors remain the only components that consume a single-use commit token before creating an external consequence.

## Mandatory resolution

Before RACS may sign a decision, it MUST resolve and verify:

1. the signed REHT `GovernanceClearance`;
2. the exact `AdmissibilityDetermination` referenced and digested by that clearance;
3. every exact `GovernanceEvaluation` referenced and digested by the determination;
4. the exact `BoundaryCrossingAssessment` bound by the evaluation and determination; and
5. the exact canonical `ActionEnvelope` bound by the complete chain.

Unresolved, stale, expired, conflicting, substituted or digest-mismatched artifacts are commit-preclusive.

## Monotonicity

RACS may preserve or narrow a REHT outcome. It MUST NOT expand it.

| REHT clearance | Permitted RACS outcomes |
|---|---|
| `ALLOW` | `ALLOW`, `MODIFY`, `DEFER`, `DENY`, `STEP_UP`, `HALT` |
| `MODIFY` | `MODIFY`, `DEFER`, `DENY`, `STEP_UP`, `HALT` |

A `MODIFY` clearance cannot become `ALLOW`. When REHT already supplied `MODIFY` constraints, RACS MUST preserve the exact constraint set unless a separately specified machine-verifiable narrowing proof exists. This profile defines no such proof, so replacement is rejected fail-closed.

## Permit and token binding

A `CoreExecutionPermit` MUST carry:

- `racs_decision_id`;
- `racs_decision_digest`;
- the positive RACS outcome (`ALLOW` or constrained `MODIFY`); and
- the exact action, target, payload, connector, capability and upstream clearance bindings.

A `CommitToken` MUST copy the same RACS decision ID, digest and outcome from the verified permit. No fallback path may mint a permit or token directly from possession of a clearance.

The token digest is bound into `ExecutionReceipt`; therefore the decision binding remains transitively provable after execution without duplicating authority semantics into the receipt.

## Ownership boundaries

- **VAIG** evaluates.
- **REHT** clears and remains the positive authorization boundary.
- **RACS** verifies, decides and binds; it never creates broader authority.
- **Core** enforces a verified positive RACS decision by issuing a bounded permit and token.
- **Bounded connectors** atomically consume the token before provider invocation.
- **Receipts** prove what was authorized, bound, consumed and attempted.
