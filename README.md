# RACS

RACS — REHT Action Control Standard.

RACS defines a neutral, model-agnostic protocol for representing, evaluating, authorizing, executing and evidencing AI-mediated actions.

RACS is a standard, not a runtime implementation.

## Core question

Is this action admissible to execute under the current authority, policy, evidence and system state?

## Scope

RACS defines:

- Action Envelope
- Authority Context
- Evidence Package
- Policy Context
- Admissibility State
- Delegation Chain
- Governance Decision
- Continuous Integrity events
- Execution Receipt

RACS does not define:

- model architecture
- agent reasoning methods
- moral truth
- organizational legitimacy
- domain policy content
- runtime implementation details

## Architecture position

```text
BARO -> Reality Package
          |
          v
REHT / VAIG -> Admissibility evaluation
          |
          v
RACS -> Standardized action-control messages
          |
          v
Execution boundary -> Action or refusal
          |
          v
Receipt
```

## Repository status

Initial clean-room specification seed.

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