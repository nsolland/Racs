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

1. no consequence-bearing route bypasses the governed enforcement boundary;
2. every observed effect can be attributed to the required current action/authority/decision/enforcement/receipt chain;
3. broken or missing required chain continuity is non-executable for continued governed execution;
4. an observed effect without a valid chain is treated as suspected bypass/control failure, not governed success;
5. post-hoc logging or receipt creation cannot retroactively authorize a prior effect;
6. human approval and other gates cannot manufacture authority;
7. unknown, malformed or inconsistent external results remain explicit unknown/failure states; and
8. independent verification can distinguish intended action, authorized action, attempted enforcement, actual effect and verified outcome.

## 8. Ownership

RACS owns the runtime effect-path, decision-binding and receipt-chain conformance semantics.

REHT owns fresh exact-action admissibility and execution clearance.

The deterministic core or bounded enforcement adapter applies valid permits and decisions. It cannot widen them.

Veritas or an equivalent independent evidence layer may verify and preserve the resulting chain, but verification does not create authority and cannot legitimize a bypass after the fact.
