# RACS

RACS — REHT Action Control Standard.

RACS defines the neutral, model-agnostic contract used to represent and bind AI-mediated action-control decisions through execution and evidence.

RACS is deterministic protocol/schema infrastructure. It is not an evaluator, authorization engine, policy engine, enforcement point, or executor.

## Core question

How is an already-made governance decision represented and bound deterministically to the exact action, execution boundary, and resulting receipt?

## Scope

RACS defines:

- Action Envelope
- Authority Context representation
- Evidence Package representation
- Policy Context representation
- Admissibility State representation
- Delegation Chain representation
- Governance Decision contract
- deterministic decision/action bindings
- permit and commit-token schemas
- Continuous Integrity events
- Execution Receipt contracts

RACS does not:

- evaluate evidence or risk
- decide admissibility
- grant or infer authority
- authorize execution
- enforce policy
- execute actions
- define model architecture or agent reasoning
- determine moral truth or organizational legitimacy

## Architecture position

```text
Speider / BARO -> represented evidence
                    |
                    v
VAIG -> evaluation
                    |
                    v
REHT -> fresh execution authorization
                    |
                    v
RACS -> deterministic decision/action contract
                    |
                    v
external PEP / Gateway -> execution or refusal
                    |
                    v
Veritas -> receipt / evidence
```

REHT is the authorization boundary. RACS deterministically carries and binds the resulting decision; it cannot widen, reinterpret, or replace that decision.

## Repository status

Active v0.2 protocol specification with normative schemas, reference bindings, compliance validators, and test vectors.

No source code, schemas, wording, diagrams or structure have been copied from the archived `nsolland/ACS` repository or the external Agent Control Standard project.

## Documents

- `SPECIFICATION.md`
- `IP_PROVENANCE.md`
- `THIRD_PARTY_NOTICES.md`
- `docs/architecture/BOUNDARIES.md`
- `spec/` — normative v0.2 JSON schemas (source of truth)

## Ownership

Copyright © 2026 VALO Research Group AS.

License to be finalized before public release.
