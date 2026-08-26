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

## Public role model

RACS is intentionally implementation-neutral. A deployment may contain roles such as:

```text
Evidence producer
  Produces observations or evidence packages.

Evaluator / admissibility issuer
  Produces a bounded decision or determination.

RACS protocol layer
  Standardizes messages, states, bindings and evidence exchanged.

Enforcement runtime
  Verifies the applicable protocol artifacts at the execution boundary.

Effect adapter
  Performs, refuses, pauses or halts an action.

Evidence store
  Preserves receipts and related evidence.
```

This role model is illustrative and does not define, reveal or require any private product topology, component naming, dependency graph or build order.

## Separation invariant

A RACS message may carry a decision, but RACS itself does not make the decision.

A conforming implementation must identify which authorized role produced the decision and which enforcing role applied it.
