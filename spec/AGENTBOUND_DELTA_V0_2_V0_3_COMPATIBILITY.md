# AgentBound Delta — RACS v0.2 / v0.3 Compatibility

Status: NORMATIVE COMPATIBILITY PROFILE  
Date: 2026-08-02  
Issue: #125

## 1. Purpose

This profile defines how the AgentBound-inspired RACS v0.3 delta composes with the existing RACS v0.2 execution-governance chain.

The delta is additive. It does not replace the v0.2 authority, action, evaluation, REHT clearance, Core permit, CommitToken, execution receipt or outcome receipt contracts.

Canonical responsibility chain:

```text
Human / organisational authority
→ principal and delegation binding
→ VAIG evaluation
→ REHT exact-action clearance
→ RACS deterministic decision contract
→ Core enforcement
→ bounded execution
→ ExecutionReceipt
→ OutcomeReceipt
```

RACS defines protocol, canonicalization, decision vocabulary and conformance. RACS does not establish human authority, issue REHT clearance or execute an action.

## 2. Additive v0.3 artifacts

The AgentBound delta adds four normative payload contracts:

| Artifact | Schema | Function | Authority boundary |
|---|---|---|---|
| Task authority materialization | `task-authority-materialization-v0.3.schema.json` | Narrows a current standing authority grant to one task or bounded workflow segment | Cannot widen authority or prove execution |
| Target action contract | `target-action-contract-v0.3.schema.json` | Authenticated semantic description of the exact target operation | Describes effects; never grants principal authority |
| Authority evaluation fragment | `authority-evaluation-fragment-v0.3.schema.json` | Typed, signed or attested input to monotone hierarchy composition | Cannot independently clear or execute |
| Governance replay bundle | `governance-replay-bundle-v0.3.schema.json` | Portable evidence bundle for deterministic offline reconstruction | Replay has no execution authority |

These artifacts are inputs to, or evidence about, the canonical chain. They are not a second authorization stack.

## 3. Compatibility classes

### 3.1 RACS v0.2 baseline

A v0.2 implementation may remain conformant to its declared v0.2 profile without producing the four v0.3 AgentBound-delta artifacts.

It MUST NOT claim the AgentBound-delta profile unless all mandatory v0.3 artifacts, bindings and conformance rules required for the relevant action class are present.

### 3.2 RACS v0.3 AgentBound-delta producer

A producer claiming this profile MUST:

1. materialize current, narrower task authority before consequence-bearing execution;
2. reject direct execution from standing authority;
3. bind the task materialization to current authority state, principal, agent identity, delegation, purpose, policy and target-contract set;
4. verify target-operation semantics for consequential actions;
5. compose all mandatory authority-evaluation fragments monotonically;
6. bind the complete fragment set and composition result into the dependent clearance evidence;
7. produce a replay bundle sufficient for deterministic offline verification;
8. preserve GovernanceClearance, authority transition, Core permit, CommitToken, ExecutionReceipt and OutcomeReceipt as separate artifacts;
9. preserve the six canonical governance decisions: `ALLOW`, `MODIFY`, `DEFER`, `DENY`, `STEP_UP`, `HALT`.

### 3.3 Consumer behavior

A v0.3-aware consumer receiving only a v0.2 artifact chain MUST apply its declared compatibility policy:

- accept only for action classes explicitly permitted by the v0.2 profile; or
- return `STEP_UP`, `DEFER` or `DENY` when the v0.3 delta is mandatory.

It MUST NOT synthesize missing task authority, target semantics, evaluation fragments or replay evidence.

A v0.2-only consumer encountering unknown v0.3 artifacts may ignore them only when its declared v0.2 action profile does not require them and the canonical v0.2 chain remains complete. It MUST fail closed rather than silently discard a v0.3 artifact that is referenced by a clearance, permit or receipt binding.

## 4. Cross-version binding rules

1. A v0.3 artifact referenced by another artifact is mandatory for verification.
2. Referenced payload digests use RACS-JCS-1: RFC 8785 canonical bytes and SHA-256 represented as `sha256:<lowercase-hex>`.
3. A target-contract change invalidates dependent task materialization, action identity, evaluation and clearance.
4. An authority-state, principal, agent, delegation, purpose or policy change invalidates dependent task materialization and downstream authorization evidence.
5. Missing mandatory evaluation fragments cannot resolve to `ALLOW`.
6. Constraints intersect; obligations union; lower-level success cannot erase a higher-level restriction.
7. Replay output is limited to `MATCH`, `MISMATCH`, `INCOMPLETE` or `UNVERIFIABLE` and cannot create a permit, token or execution right.
8. A valid governance signature proves the bound governance artifact was signed by the resolved issuer. It does not independently prove organisational legitimacy.
9. A valid target-contract signature proves contract provenance. It does not establish the actor's authority to invoke the operation.
10. An ExecutionReceipt proves an observed technical attempt or result under its exact bindings. It does not prove admissibility, outcome or value.

## 5. Migration guidance

### 5.1 Producer migration

Recommended sequence:

```text
v0.2 authority and delegation
→ add task-authority materialization
→ add target-action contract validation
→ add mandatory evaluation fragments and monotone composition
→ bind the complete set into REHT/RACS evidence
→ add replay bundle production
→ require proof at the execution boundary
```

Migration MUST be fail-closed per action class. A deployment may introduce the profile in shadow mode, but it MUST NOT report v0.3 enforcement until the actual consequence-bearing boundary requires the complete proof.

### 5.2 Consumer migration

Consumers should add v0.3 parsing and validation before making the profile mandatory. During transition they MUST expose which compatibility class was applied and which required artifacts were absent.

### 5.3 Receipt compatibility

The AgentBound delta does not create a new execution receipt family. Existing v0.2 or v0.3 ExecutionReceipt contracts remain authoritative for technical execution evidence. Governance replay bundles reference receipts; they do not replace them.

The optional portable ExecutionReceipt v0.3 extension is independent of the AgentBound delta. A deployment may implement either extension, both, or neither, but MUST declare each conformance profile separately.

## 6. Conformance minima

A claimed AgentBound-delta profile MUST demonstrate at least:

- standing grant presented directly at commit is rejected;
- widened or stale task materialization is rejected;
- missing, expired, revoked or substituted target contracts fail closed;
- missing mandatory fragments cannot produce `ALLOW`;
- hard-gate failure cannot be overridden by a favourable lower-level result;
- conflicting constraints cannot produce `ALLOW`;
- all obligations survive composition;
- independent `HALT` dominates;
- omitted replay fields produce `INCOMPLETE`;
- substituted contracts or changed action parameters produce `MISMATCH`;
- absent independent verification produces `UNVERIFIABLE`;
- valid fixtures reproduce the original decision and canonical digest;
- execution remains impossible without the canonical downstream clearance, enforcement and single-use execution artifacts.

## 7. Non-compatibility claims

This profile does not claim:

- that v0.2 is unsafe or invalid;
- that schema validity establishes authority;
- that all actions require identical v0.3 evidence;
- that AgentBound is a RACS subsystem or product name;
- that RACS replaces REHT admissibility or Core enforcement;
- that benchmark success establishes zero production risk;
- that offline reference-verifier latency represents production execution latency.
