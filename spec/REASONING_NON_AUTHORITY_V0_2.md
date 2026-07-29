# Reasoning Non-Authority Profile v0.2

Status: NORMATIVE

## Invariant

`chain_of_thought_is_non_authoritative`

Model-generated reasoning, explanations, scratchpads, filler tokens, self-reported confidence, tool-selection narratives and hidden-state claims MUST NOT satisfy or replace identity, mandate, delegation, policy, evidence, purpose, state, human approval, clearance or commit-token requirements.

Reasoning observability is not a precondition for execution safety. A governed action MUST remain controllable when model reasoning is opaque, incomplete, unavailable or misleading.

## Required behaviour

1. A model explanation MUST NOT grant, expand, repair or infer operative authority.
2. Authority marked `MISSING` MUST produce `DENY` or `HALT`, even when the visible reasoning appears legitimate.
3. Clearance and commit-token issuance MUST depend only on externally bound governance artifacts.
4. Absence of a reasoning trace MUST NOT weaken a valid external authorization path.
5. Presence of a reasoning trace MUST NOT strengthen an invalid or missing authorization path.
6. Systems MAY retain trace digests for provenance, reproducibility and incident analysis, but MUST label them non-authoritative.
7. Trace capture MUST NOT claim completeness unless the captured boundary is technically defined and verifiable.

## Reasoning trace binding

`GovernanceEvaluation.reasoning_trace_binding` MAY bind:

- model context
- prefill
- model configuration
- generated token ranges
- an external trace reference

`authoritative_for_clearance` is fixed to `false`.

`ExecutionReceipt.reasoning_trace_binding_digest` MAY preserve the audit binding. When present, it MUST be accompanied by `governance_evaluation_digest`. Neither field creates authority.

## Conformance

A conforming implementation MUST reject:

- `reasoning_authority: true`
- `authoritative_for_clearance: true`
- `authority_status: MISSING` combined with `ALLOW`, `MODIFY`, `DEFER` or `STEP_UP`

A conforming implementation MUST accept a valid externally authorized `ALLOW` evaluation when no reasoning trace is available.

## Research motivation

This profile is consistent with evidence that visible chain-of-thought may be semantically uninformative or may omit task-relevant computation. The normative rule does not depend on detecting hidden reasoning.

Reference: https://arxiv.org/abs/2607.22925
