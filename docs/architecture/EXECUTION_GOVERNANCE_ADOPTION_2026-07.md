# RACS Execution Governance Adoption

Date: 2026-07-15
Status: Canonical architecture direction

## Canonical name

RACS means Runtime Agent Control Standard.

ACS is retired. It must not be used in new documentation, schemas, code, examples or communication except in explicit migration notes.

RACS defines the protocol contract between an agent, the governance layer and the execution boundary. RACS does not decide whether an action is admissible and does not execute the action.

VAIG evaluates. REHT clears. RACS standardizes, binds and carries the governed execution contract. Core enforces and commits. Receipts prove.

## Adopted external lessons

The following ideas are adopted as engineering patterns, not copied implementations.

1. Single-use, bounded authority

A clearance or permit must bind to one action or explicitly bounded action set. It must include actor, target, operation, scope, policy version, validity window, use ceiling and revocation state.

2. Governed handles

Effectful tools must be exposed through governed handles. A model or agent must not receive an unmediated raw callable for consequential actions.

3. Target lock and state witness

The target and relevant state must be hashed or otherwise bound when clearance is issued and checked again immediately before commit. A material mismatch invalidates the clearance.

4. Intent narrowing

Expressed user intent may narrow authority but must never expand static authority, delegation or policy. Compound workflows must use step-specific intent and clearance objects.

5. Read-then-act decomposition

Discovery, reading and analysis must not automatically grant mutation, export, payment, deployment, deletion or delegation authority. High-consequence effects require a new bounded clearance after the target and effect are concrete.

6. Path-aware governance

A proposed action may be individually valid and still violate policy because of the prior execution path. RACS must carry path-state references sufficient for REHT and VAIG to evaluate sequence-dependent risk.

7. Explicit handoff authority

Agent-to-agent handoff does not implicitly transfer authority. Delegation, constraints, evidence references, purpose, validity and remaining scope must be carried explicitly.

8. Continuous integrity

Admissibility is not permanent. Material changes in state, evidence, policy, target, path, environment or authority must trigger revalidation before continuation or commit.

9. Structured negative artifacts

DENY, DEFER, STEP_UP and HALT must produce structured artifacts with stable reason codes, evidence references and integrity metadata. A refusal is part of the proof chain.

10. Proof-carrying execution

The execution record should bind the governing contract, clearance, causal events, durable effect, revalidation events, overrides, outcome and replay context where feasible.

11. Proof without custody

Sensitive raw content should remain local when hashes, references, commitments or selective disclosure are sufficient for verification.

12. Falsifiable invariants

Claims must be reducible to binary or reproducible checks: signature valid or invalid, target matched or mismatched, clearance active or expired, effect present or absent, receipt complete or incomplete.

## Canonical protocol objects

### AgentPassportReference

Optional upstream reference for agent identity, owner, assurance, capabilities, limits, regions, model provenance and tool declarations.

It is evidence only. It is never sufficient for execution clearance.

### IntentCertificate

A bounded representation of the trusted request.

Required semantics:

- request digest
- intent classes
- resource bounds
- effect bounds
- confidence and provenance
- review mode
- expiry or turn limit
- parent intent for decomposed workflows

Invariant: an IntentCertificate may only narrow authority.

### ActionEnvelope

The proposed consequential action.

Minimum fields:

- envelope ID and version
- actor and tenant
- requested operation
- canonical target and target digest
- parameters or parameter digest
- requested effect
- authority and delegation references
- intent certificate reference
- policy references
- evidence references
- runtime and environment state references
- path-state reference
- reversibility and consequence class
- requested validity window

### GovernanceEvaluation

The structured VAIG evaluation consumed by REHT.

Minimum fields:

- evidence quality
- uncertainty
- policy findings
- risk findings
- semantic and normative drift signals
- convergence and systemic-risk signals
- state freshness
- unresolved conditions
- evaluator provenance

RACS carries this object but does not generate the decision.

### GovernanceClearance

The signed, bounded REHT result.

Minimum fields:

- clearance ID
- ActionEnvelope digest
- decision
- actor, operation, target and scope binding
- intent binding
- policy snapshot digest
- evidence-set digest
- state witness
- path-state digest
- constraints
- human approval requirement and reference
- issued-at, not-before and expires-at
- use ceiling
- revocation reference
- revalidation triggers
- evaluator references
- signature metadata

A GovernanceClearance is not a permanent permit.

### CommitToken

A narrow token derived only after the execution boundary verifies the clearance and current state.

Minimum checks before issue:

- clearance signature and status
- exact envelope digest
- target lock
- current state witness
- policy freshness
- evidence freshness
- path-state consistency
- use count
- human approval where required
- receipt writer availability for fail-closed tiers

### ExecutionEvent

The smallest proof-bearing unit in the execution trajectory.

Minimum fields:

- event ID and parent references
- event type
- envelope and clearance references
- actor and component identity
- input and output digests
- effect class and resource reference
- state delta digest
- decision or intervention
- monotonic sequence
- timestamp witness
- previous-event hash
- signature or integrity proof

### ExecutionReceipt

The durable proof of the governed execution path.

Minimum fields:

- ActionEnvelope reference
- GovernanceEvaluation reference
- GovernanceClearance reference
- CommitToken reference
- causal event root
- execution start, completion or failure state
- effect digest
- revalidation and intervention events
- human overrides
- policy and evidence references
- outcome reference
- replay-context reference
- integrity-chain value

A receipt proves that the protocol path executed. It does not prove that the model or outcome was correct.

## Required runtime state machine

Pre-execution decisions:

- ALLOW
- MODIFY
- DEFER
- DENY
- STEP_UP
- HALT

During-execution controls:

- CONTINUE
- PAUSE
- MODIFY
- STOP
- ROLLBACK
- HANDOVER
- HALT

Every transition must be attributable, policy-bound and receipted.

## Core invariants

1. The proposing component cannot authorize its own consequential action.
2. No consequential action executes without a canonical ActionEnvelope.
3. No execution occurs without a valid REHT GovernanceClearance.
4. RACS transports and validates protocol objects but makes no admissibility decision.
5. Intent cannot expand authority.
6. Delegation does not transfer implicitly across agents or tools.
7. Raw effectful callables are not exposed when governed handles are required.
8. Target and state are revalidated immediately before commit.
9. Material change invalidates or reopens clearance.
10. A denial must have null effect for the denied branch.
11. Every committed effect must be represented in the causal event chain.
12. Receipt failure is commit-preclusive for configured critical tiers.
13. Sensitive content remains local when cryptographic references are sufficient.
14. Formal claims are limited to named invariants and explicit assumptions.

## Conformance profiles

### RACS Reference Profile

Minimum interoperable semantics:

- ActionEnvelope
- GovernanceEvaluation
- GovernanceClearance
- deterministic validation
- stable reason codes
- target binding
- expiry and revocation
- ExecutionReceipt

### RACS Enterprise Profile

Adds:

- persistent revocation
- multi-tenant isolation
- external key management
- human approval binding
- path-state governance
- state witnesses
- policy versioning
- append-only evidence chain
- distributed replay protection

### RACS High-Consequence Profile

Adds:

- single-use CommitToken
- commit-time revalidation
- fail-closed receipt write
- continuous integrity monitoring
- interruption and rollback protocol
- dual or threshold authority where required
- deterministic replay context where feasible
- externally verifiable receipt anchoring

## Migration rule

All new work uses RACS.

Legacy names may remain only where changing them would break compatibility. Such occurrences must be marked deprecated and mapped explicitly to the canonical RACS object or interface.

No new `acs` directory, service, schema, class, API route, documentation heading or product claim may be introduced.
