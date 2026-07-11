# RACS Specification

Status: Draft 0.1

## 1. Purpose

RACS standardizes the control messages exchanged between observation, governance, execution and evidence systems when an AI-mediated action may affect the external world.

## 2. Design principles

- Model agnostic
- Runtime neutral
- Deterministic message semantics
- Explicit authority
- Evidence-bound decisions
- Continuous validity
- Verifiable receipts
- No hidden execution authority

## 3. Core objects

### 3.1 Action Envelope

Represents one proposed action.

Required fields:

- `racs_version`
- `action_id`
- `action_type`
- `actor`
- `target`
- `requested_effect`
- `authority_context`
- `policy_context`
- `evidence_package`
- `environment_state`
- `risk_context`
- `created_at`
- `expires_at`

### 3.2 Authority Context

Describes who or what may authorize the action and under which delegation.

### 3.3 Evidence Package

Contains evidence references, provenance, freshness, confidence and integrity metadata.

### 3.4 Policy Context

Identifies the policy set and exact version used for evaluation.

### 3.5 Admissibility State

Possible states:

- `SUBMITTED`
- `UNDER_REVIEW`
- `ADMISSIBLE`
- `CONDITIONALLY_ADMISSIBLE`
- `NOT_ADMISSIBLE`
- `STALE`
- `REVOKED`
- `HALTED`
- `COMPLETED`

### 3.6 Governance Decision

Initial decision vocabulary:

- `ALLOW`
- `MODIFY`
- `DEFER`
- `DENY`
- `STEP_UP`
- `HALT`

### 3.7 Continuous Integrity Event

Records any material change in authority, policy, evidence, target, environment or risk while execution is pending or active.

### 3.8 Execution Receipt

Records what was proposed, evaluated, decided, executed and observed.

## 4. Protocol flow

```text
PROPOSE
  -> PACKAGE
  -> EVALUATE
  -> DECIDE
  -> COMMIT
  -> EXECUTE
  -> OBSERVE
  -> RECEIPT
```

At any point before terminal completion, a material integrity change may trigger re-evaluation.

## 5. Invariants

1. No execution without a valid decision.
2. No valid decision without explicit authority context.
3. No valid decision without a versioned policy context.
4. Evidence must be traceable to source references.
5. Expired or revoked authority invalidates pending execution.
6. Material state change requires re-evaluation.
7. Every terminal outcome produces a receipt.
8. Refusal and halt are first-class outcomes.

## 6. Conformance

Conformance levels will be defined for:

- message producers
- governance evaluators
- execution adapters
- receipt stores
- continuous-integrity monitors

## 7. Reserved work

- JSON schemas
- canonical serialization
- signatures
- trust model
- delegation grammar
- receipt chain rules
- error model
- transport bindings
- conformance test vectors