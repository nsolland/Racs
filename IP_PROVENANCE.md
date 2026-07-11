# RACS IP Provenance

## Status

- IP status: VALO-owned active architecture
- Origin date: 2026-07-11
- Initial author: Njål Gaute Solland
- Organization: VALO Research Group AS
- Active authority: true

## Clean-room declaration

RACS was initialized as a new specification repository after the separate `nsolland/ACS` repository was designated for archival.

RACS does not claim ownership of the external Agent Control Standard project, its name, documentation, schemas, code, diagrams or implementation structure.

No material from the archived ACS repository is normative for RACS.

## Independent architectural basis

RACS is derived from VALO's independently developed architecture around:

- action admissibility
- explicit authority
- evidence-bound execution
- policy-bound execution
- execution boundaries
- continuous integrity
- deterministic governance decisions
- cryptographically traceable receipts

## Repository rules

1. Do not copy text, schemas, diagrams or source code from the archived ACS repository.
2. Record all external references in `THIRD_PARTY_NOTICES.md`.
3. Mark imported proposals as non-normative until reviewed.
4. Preserve contributor attribution.
5. Any disputed concept remains classified as unresolved until reviewed.
6. Normative changes require a commit, rationale and version update.

## Relationship to VALO components

- REHT defines the admissibility question.
- VAIG is a runtime governance implementation.
- REHT V5 Core may enforce bounded execution-state transitions.
- BARO produces observation and evidence packages.
- RACS defines neutral protocol objects and semantics between implementations.

RACS does not own the internal implementation of those components.