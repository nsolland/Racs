# RACS Architectural Boundaries

## RACS owns

RACS owns the interoperable representation of:

- proposed actions
- authority context
- delegation
- evidence references
- policy references
- environment state
- admissibility state
- governance decisions
- continuous-integrity events
- execution outcomes
- receipts

## RACS does not own

RACS does not own:

- observation and signal collection
- truth determination
- model reasoning
- organizational legitimacy
- human standing
- policy authoring
- risk-model implementation
- runtime enforcement implementation
- audit-storage technology

## Component mapping

```text
BARO
  Produces observations and Reality Packages.

REHT
  Frames whether an action is right or admissible to execute.

VAIG
  Evaluates runtime governance conditions.

RACS
  Standardizes the messages, states and evidence exchanged.

REHT V5 Core
  May enforce bounded execution-state transitions.

Execution adapter
  Performs, refuses, pauses or halts an action.

Receipt store
  Preserves the evidence chain.
```

## Separation invariant

A RACS message may carry a decision, but RACS itself does not make the decision.

A conforming implementation must identify which component produced the decision and which component enforced it.