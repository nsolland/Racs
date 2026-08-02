# AgentBound Prior Art and Benchmark Interpretation

Status: architecture and evidence interpretation  
Date: 2026-08-02  
Issue: #125

## 1. Classification

AgentBound is relevant execution-governance prior art and category validation. Its useful overlap with RACS is the requirement for a non-bypassable, conservative decision immediately before consequence-bearing action.

The RACS adoption is a delta, not a subsystem fork.

Adopted mechanisms:

1. short-lived task authority derived from standing authority;
2. target-owned semantic contracts for consequential operations;
3. monotone composition of independent authority evaluations;
4. portable, independently replayable governance evidence;
5. security evaluation centred on violation escape and ablation.

Not adopted:

- a new `AgentBound` product or runtime;
- a second constitution or authority registry;
- a reduced `Permit / Review / Deny` decision vocabulary;
- target contracts as principal authority;
- proposer, issuer or governance signatures as self-sufficient legitimacy proof;
- a merged clearance, execution receipt and outcome artifact;
- claims of production safety or empirical superiority not established by deployment evidence.

## 2. Relationship to the RACS architecture

RACS already separates:

```text
Authority and delegation
→ exact action proposal
→ VAIG evaluation
→ REHT admissibility and clearance
→ RACS deterministic decision contract
→ Core enforcement
→ bounded connector execution
→ technical receipt
→ observed outcome
```

The AgentBound delta strengthens the evidence and binding between standing authority and exact execution. It does not move authority into RACS, a target system or an evaluator.

### Mechanism mapping

| AgentBound-relevant mechanism | RACS placement | Canonical limitation |
|---|---|---|
| Task-scoped authority | `TaskAuthorityMaterialization` | Strict subset of current standing authority; never an execution receipt |
| Site/target semantics | `TargetActionContract` | Semantic evidence only; cannot grant principal authority |
| Multiple evaluators | `AuthorityEvaluationFragment` plus canonical hierarchy composition | Constraints only narrow; obligations accumulate |
| Independent reconstruction | `GovernanceReplayBundle` and offline verifier | Replay has no execution authority |
| Security evaluation | `benchmarks/agentbound_delta` | Deterministic reference benchmark, not production assurance |

## 3. Benchmark evidence

Committed result artifact:

```text
benchmarks/agentbound_delta/results.json
result_digest = sha256:48ca88997f0fb321e3e7e33a48ec52a5abceab8db68de714a4b45cb1557e4ad3
```

Observed deterministic reference result:

| Metric | Result |
|---|---:|
| Scenarios | 18 |
| Prohibited scenarios | 17 |
| Hard-gate scenarios | 14 |
| Escaped violations | 0 |
| Governance decision accuracy | 1.0 |
| Violation escape rate | 0.0 |
| Hard-gate false allow rate | 0.0 |
| False step-up rate | 0.0 |
| Receipt verification rate | 1.0 |
| Replay equivalence rate | 1.0 |
| Policy-change invalidation rate | 1.0 |
| Contract-drift detection rate | 1.0 |
| Offline verifier latency p50 | 1,203,231 ns |
| Offline verifier latency p95 | 1,612,755 ns |
| Offline verifier latency p99 | 1,612,755 ns |

The acceptance gate passed for the committed scenario set.

## 4. Correct interpretation

The result demonstrates that the deterministic Python reference verifier and its committed fixtures behaved as specified for that run:

- all prohibited scenarios were blocked or classified as incomplete, mismatched or unverifiable;
- valid fixtures replayed equivalently;
- untampered receipt bindings verified;
- policy and target-contract changes invalidated prior evidence;
- each required ablation identified a concrete lost invariant.

It does not demonstrate:

- zero production risk;
- coverage of every implementation defect, concurrency failure or deployment topology;
- protection against every compromise of trust roots, issuers, keys, stores or operators;
- production connector correctness;
- production runtime latency;
- equivalence to the Core fast path;
- empirical superiority over another system.

The latency values cover the offline Python reference verifier only. Network, transport, production storage, cryptographic key resolution, connector execution and outcome observation are excluded.

## 5. Ablation interpretation

The benchmark distinguishes two failure types:

1. **Prohibited action becomes possible.** Removing principal binding, task materialization, target semantics, authority freshness, constitutional hierarchy, consequence evaluation, independent governance verification or policy freshness permits a forbidden action in the modelled scenario.
2. **Evidence guarantee is lost.** Removing replay or receipt verification prevents trustworthy uniqueness or reconstruction even when the benchmark does not model a direct connector escape.

The `remove_replay_protection` ablation is an evidence-integrity demonstration based on exact-action/bundle tampering. It is not a claim that every runtime nonce registry, distributed race or durable replay implementation was exercised by that scenario.

## 6. Competitor and prior-art posture

AgentBound should be tracked in the same category neighbourhood as systems and proposals that address:

- before-tool-call or before-commit authorization;
- delegated authority and principal binding;
- policy decision and enforcement separation;
- action-bound approvals and step-up;
- proof-bearing governance;
- cryptographic or portable receipts;
- independent replay and audit;
- target or connector semantic contracts.

Classification rule:

- **Category validation:** independent convergence on the need for pre-consequence control.
- **Prior art:** relevant mechanisms, terminology and evaluation patterns must be considered in novelty analysis.
- **Not architectural authority:** external papers or products do not redefine the RACS, REHT, Core or receipt responsibility boundaries.
- **Not evidence of equivalence:** similar language does not prove equal implementation, security or operating semantics.

## 7. Canonical conclusion

The adopted delta closes five specific gaps while preserving the existing architecture:

```text
Standing authority cannot execute directly.
It becomes current, narrower task authority.
The exact target operation has authenticated semantics.
Mandatory evaluations compose monotonically.
The decision can be reconstructed independently.
The execution boundary still requires the canonical clearance and enforcement chain.
```
