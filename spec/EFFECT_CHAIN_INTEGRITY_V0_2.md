# RACS Draft 0.2 — Effect Path and Chain Integrity

Status: NORMATIVE additive runtime-governance profile  
Canonical owner: RACS  
Authority and clearance chain: unchanged

## 1. Purpose

This profile makes two execution invariants explicit:

1. consequence-bearing execution has one governed enforcement path; and
2. every observed consequence must be traceable to a valid governance and receipt chain.

The short form is:

> Every effect has a chain.

This profile does not create authority, a new decision layer, or a parallel executor. It defines the integrity requirements around the existing VALO execution chain.

## 2. Single governed effect path

Every consequence-bearing call MUST pass through the bounded enforcement boundary that consumes the current governed execution artifacts required for that action.

A model, agent, workflow engine, tool broker, session, connector, adapter, credential holder or execution substrate MUST NOT have an alternate side-effect route that can bypass that boundary.

Possession of a tool, credential, authenticated session, approval artifact or executable capability does not itself authorize consequence.

Where the architecture exposes more than one technical route to the same external effect, every route MUST converge on an equivalent enforced authorization boundary before consequence.

An implementation that permits an effect to occur outside the governed enforcement path is non-conforming even if it emits logs or receipts afterward.

### 2.1 `NO_DIRECT_EFFECT_PATH`

`NO_DIRECT_EFFECT_PATH` is the canonical name for this invariant.

Every consequence-bearing tool or effector MUST be reachable only through the
governed enforcement boundary. A callable wrapper, connector, authenticated
session, runtime adapter or tool registry is non-conforming if it retains an
independent route to the same consequence.

A state, memory, configuration, instruction or artifact write MUST be treated
as consequence-bearing when it can alter a future consequence-bearing
decision. Such a write MUST cross an appropriate governed write boundary and
MUST NOT enter authoritative or decision-relevant state through an agent-local
or tool-local side channel.

### 2.2 `NULL_EFFECT_ON_DENY`

`DENY`, `DEFER`, `STEP_UP` and `HALT` MUST have a null effect. They MUST NOT
invoke an effector, consume an execution capability, commit a resource or
produce the proposed consequence. `MODIFY` may execute only after the modified
exact action has been materialized and bound by the existing authorization and
permit chain.

A receipt describing a blocked decision is evidence of the block; it is not an
execution effect.

### 2.3 Structural Coupling Test

An implementation MUST prove that the proposed effect cannot occur when any
required governance basis is invalid, stale, revoked, suspended or unresolved.
The proof MUST exercise the actual enforcement route and verify that the
effector was not invoked and the proposed consequence did not occur.

If the same effect remains technically possible after removal or invalidation
of its required governance basis, governance is observational rather than
structurally coupled and the implementation is non-conforming.

### 2.4 Effector-exclusive authority

Credentials, bearer material, signing capability, network entitlement and any
other executable capability that can realize the consequence MUST be exclusive
to the governed effector path. Models, agents, orchestrators, workspaces,
general tool registries and protocol adapters MAY receive opaque references but
MUST NOT retain an independently usable execution capability.

### 2.5 Deterministic boundary replay

Boundary replay MUST pin the exact contract, state, authority, evidence and
deterministic decision inputs used at the enforcement boundary. Given the same
pinned inputs, replay MUST produce the same boundary result without invoking
the effector.

Boundary replay is not token-level LLM replay. Reproducing prompts, model
sampling, hidden reasoning, tokens or natural-language generation is neither
required nor attempted. Determinism is scoped to the governed decision/effect
boundary.

## 3. Effect-chain integrity

For an atomic consequence-bearing action, the minimum attributable chain is conceptually:

```text
ActionEnvelope
→ GovernanceEvaluation / governed evidence
→ REHT AdmissibilityDetermination and GovernanceClearance
→ RACS deterministic decision
→ CoreExecutionPermit / CommitToken where applicable
→ bounded enforcement attempt
→ ExecutionReceipt
→ OutcomeReceipt or explicit unknown outcome
```

Long-running or multi-transition execution additionally binds the applicable `GovernedExecutionSession`, `RuntimeObservation`, `ContinuityDecision`, `InterventionReceipt`, recovery and terminal artifacts defined by `RUNTIME_CONTINUITY_V0_2.md`.

Each downstream artifact MUST be attributable to the exact upstream action and governed state through the canonical bindings available to that contract. A later receipt cannot retroactively create missing authority or repair an execution that bypassed the governed path.

## 4. Chainless effects

If an external or physical effect is observed but the implementation cannot establish the required governed chain for that exact effect, the condition MUST be treated as a control failure and suspected execution bypass until resolved.

It MUST NOT be normalized into successful governed completion merely because the effect appears desirable, the actor was authenticated, a human previously approved related work, or a post-hoc log entry exists.

Where continued execution depends on the affected authority, executor, connector, session or state, the implementation MUST fail closed, pause, reauthorize or halt according to the applicable policy until chain integrity is re-established.

A missing or malformed external result MUST remain an explicit unknown/failure state; silent success assumptions are forbidden.

## 5. Approval and authority boundary

Human approval, dual control, quorum evidence, operator acknowledgment or other gate evidence may satisfy an additional gate condition only where policy requires it.

Such evidence MUST NOT manufacture, broaden or replace authority. The execution chain still requires independently valid identity, mandate, scope, purpose, current authority and exact-action authorization.

## 6. Receipt requirements

Receipts MUST distinguish at least:

- proposed intent;
- authorization/clearance state;
- deterministic execution decision;
- enforcement attempt;
- actual execution result; and
- verified or explicitly unknown resulting state.

Receipt integrity MUST preserve enough binding information for an independent verifier to determine whether the observed effect followed the governed effect path.

A workflow-level `completed` state is not proof of real-world consequence.

## 7. Conformance invariants

A conforming implementation MUST demonstrate:

1. `NO_DIRECT_EFFECT_PATH`: no consequence-bearing route bypasses the governed enforcement boundary;
2. decision-relevant state and memory writes are governed effects, not side channels;
3. `NULL_EFFECT_ON_DENY`: `DENY`, `DEFER`, `STEP_UP` and `HALT` invoke no effector and create no proposed consequence;
4. the Structural Coupling Test blocks effects for invalid, stale, revoked, suspended and unresolved governance basis;
5. executable credentials and capabilities are exclusive to the governed effector path;
6. deterministic replay over pinned contract, state, authority, evidence and decision inputs returns the same boundary result without re-execution;
7. every observed effect can be attributed to the required current action/authority/decision/enforcement/receipt chain;
8. broken or missing required chain continuity is non-executable for continued governed execution;
9. an observed effect without a valid chain is treated as suspected bypass/control failure, not governed success;
10. post-hoc logging or receipt creation cannot retroactively authorize a prior effect;
11. human approval and other gates cannot manufacture authority;
12. unknown, malformed or inconsistent external results remain explicit unknown/failure states; and
13. independent verification can distinguish intended action, authorized action, attempted enforcement, actual effect and verified outcome.

## 8. Ownership

RACS owns the runtime effect-path, decision-binding and receipt-chain conformance semantics.

REHT owns fresh exact-action admissibility and execution clearance.

The deterministic core or bounded enforcement adapter applies valid permits and decisions. It cannot widen them.

Veritas or an equivalent independent evidence layer may verify and preserve the resulting chain, but verification does not create authority and cannot legitimize a bypass after the fact.
