# GOS-001 — Governance OS contract reuse map

## Purpose

This document anchors the constitutional Governance OS vertical slice in the existing RACS contract model. It prevents duplicate authority semantics and defines where new intent, business-case, mandate and authority-graph artifacts bind into the current evaluation-to-execution chain.

## Existing canonical chain to preserve

1. `GovernanceEvaluation` evaluates evidence and policy inputs.
2. `AdmissibilityDetermination` determines whether the evaluated action is admissible.
3. `GovernanceClearance` records the governed pre-execution clearance result.
4. RACS emits the final runtime decision and receipt at the execution boundary.

The new GOS contracts must extend this chain. They must not create an alternate authorization path.

## New constitutional artifacts

### BoardIntent

Represents the original human board-level intent, including:

- issuer and authority basis;
- original language and exact expression;
- desired outcome and prohibited outcomes;
- value hypothesis and evidence requirements;
- temporal scope;
- ambiguity markers;
- canonical digest and version.

`BoardIntent` is evidence of human intent. It is not executable authority.

### ExecutableBusinessCase

Binds a proposed action programme to measurable value, cost, alternatives, reversibility and consequence limits. It must reference exactly one active `BoardIntent` version and preserve all narrowing transformations.

### EnterpriseMandate

Represents a narrow, machine-verifiable delegation compiled from an approved business case. Compilation must be deterministic and fail closed on ambiguity. A mandate may only narrow authority; it may never widen the source authority path.

### AuthorityGraphSnapshot

Represents the live authority path immediately before consequential execution. It must include:

- principal chain;
- delegation provenance;
- scope and exclusions;
- expiry;
- revocation state;
- cumulative spend and exposure;
- snapshot time and digest.

A stale snapshot is inadmissible.

## Binding to existing RACS artifacts

### GovernanceEvaluation additions

Evaluation inputs should reference:

- `board_intent_digest`;
- `business_case_digest`;
- `enterprise_mandate_digest`;
- `authority_graph_snapshot_digest`;
- current evidence version;
- cumulative consequence state.

### AdmissibilityDetermination additions

Admissibility must fail closed when:

- the intent or business case is missing, expired or superseded;
- mandate compilation widened scope;
- the active authority path is broken or revoked;
- cumulative spend or exposure exceeds mandate limits;
- the action cannot be linked deterministically to the approved business case;
- material ambiguity remains unresolved.

### GovernanceClearance additions

Clearance must bind the exact versions and digests used in the decision. Any change to intent, mandate, authority graph, evidence or consequence state invalidates the clearance.

### RACS receipt additions

Receipts must trace:

`BoardIntent → ExecutableBusinessCase → EnterpriseMandate → AuthorityGraphSnapshot → GovernanceEvaluation → AdmissibilityDetermination → GovernanceClearance → RACS decision → execution → outcome`

Required extensions:

- intent digest/version;
- business-case digest/version;
- mandate digest/version;
- authority snapshot digest/time;
- active authority path identifier;
- cumulative spend/exposure before and after;
- ambiguity disposition;
- no-widening validation result;
- evidence version;
- outcome linkage.

## Deterministic mandate compiler requirements

The compiler must:

1. consume a specific approved business-case version;
2. preserve original-language source text and transformation provenance;
3. reject unresolved ambiguity;
4. produce explicit scope, exclusions, limits and expiry;
5. prove that output authority is a subset of source authority;
6. emit a canonical RFC 8785-compatible digest;
7. be reproducible across supported language bindings.

## Shared conformance vectors

Cross-language vectors must cover at least:

- valid narrow delegation;
- attempted scope widening;
- expired mandate;
- revoked ancestor delegation;
- changed board intent;
- changed evidence altering the RACS result;
- cumulative spend overflow;
- cumulative exposure overflow;
- ambiguous business-case language;
- stale authority graph snapshot;
- valid clearance invalidated by changed mandate digest.

## Repository boundaries

- `nsolland/Racs`: canonical contracts, deterministic validators, compiler semantics, shared vectors and receipt bindings.
- REHT runtime: immediate pre-action checks against the live authority path, active business case, mandate and consequence limits.
- Receipts: end-to-end evidence chain and outcome linkage.
- `nsolland/Index`: architecture catalogue and references only; no production code.

## Constitutional invariants

1. Human authority remains final.
2. Intent never equals executable authority.
3. Delegation can only narrow.
4. Authority is checked against live state immediately before execution.
5. Changed evidence may change the RACS result.
6. A prior clearance cannot authorize execution after any bound artifact changes.
7. Possession of credentials never implies authority.
8. Every consequential action must be traceable to its human intent, mandate, clearance, execution and outcome.