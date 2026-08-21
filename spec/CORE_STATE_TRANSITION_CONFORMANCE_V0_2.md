# Core State-Transition Conformance Profile (P0.2, issue #145)

Status: NORMATIVE.

Defines the canonical conformance profile for the deterministic state machine
at the Core enforcement layer. The Core enforces governed effect transitions;
this profile fixes the legal transitions and the fail-closed rules.

## Core states

`READY → PROPOSING → DETERMINED → CLEARED → PERMITTED → EXECUTING → OBSERVED → CLOSED`

Plus terminal/exceptional states:

- `DENIED` (any step → denied, no effect)
- `HALTED` (intervention, no further effect)
- `REVOKED` (authority/clearance revoked mid-flight)

## Legal transitions

| From | To | Guard |
|------|----|-------|
| READY | PROPOSING | exact action envelope formed |
| PROPOSING | DETERMINED | VAIG evaluation bound |
| DETERMINED | CLEARED | REHT admissibility + clearance bound |
| CLEARED | PERMITTED | permit issued (one effect path) |
| PERMITTED | EXECUTING | effector-exclusive execution capability |
| EXECUTING | OBSERVED | runtime observation bound to effect |
| OBSERVED | CLOSED | receipt chain closed |
| any | DENIED | any gate fails — fail closed, zero effect |
| any | HALTED | intervention received |
| any | REVOKED | registry revocation observed |

## Rules (P1–P4)

1. **P1 — deterministic.** The same inputs at the same state produce the same
   next state. No environment-dependent branching in the transition function.
2. **P2 — no skip.** A transition MAY NOT skip states. A permit before a
   clearance is a control failure.
3. **P3 — fail closed.** Any missing artifact, digest mismatch or registry
   unavailability transitions to `DENIED` with zero external effect
   (see `NO_DIRECT_EFFECT_PATH`, `NULL_EFFECT_ON_DENY`).
4. **P4 — exact-effect binding.** An observed effect must be attributable to
   the exact permit's governed path; a chainless effect is a suspected bypass.

## Conformance

A conforming Core MUST implement the full legal transition table, reject every
illegal transition before any external effect, and expose its state so the
`Core state-transition conformance` test can assert each transition.