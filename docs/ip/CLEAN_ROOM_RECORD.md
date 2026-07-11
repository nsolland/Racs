# RACS Clean-Room Development Record

## Decision

The previous `nsolland/ACS` repository was archived because it contained or mirrored material from an existing third-party Agent Control Standard project.

RACS was created as a separate repository and separate standard.

No source files, specification text, schemas, diagrams, examples or repository structure from the archived ACS repository are authorized for reuse in RACS.

## Clean-room baseline

Date established: 2026-07-11

Repository: `nsolland/Racs`

Initial authoring basis:

- VALO runtime-governance architecture
- REHT admissibility principle
- VAIG governance evaluation
- deterministic Core state enforcement
- BARO observation packages
- receipt-based evidence and accountability

## Permitted inputs

Contributors may use:

- independently written VALO requirements
- public laws and regulations, with citation
- published standards used only as references, with attribution
- generic protocol and distributed-systems knowledge
- documented VALO code and architecture with confirmed ownership

## Prohibited inputs

Contributors must not copy or closely adapt:

- text from the archived ACS repository
- upstream Agent Control Standard schemas or documentation
- distinctive third-party diagrams
- externally authored field structures without attribution and license review
- unresolved collaboration material
- confidential material belonging to another party

## Development procedure

For every major protocol object:

1. State the VALO requirement in neutral language.
2. Record the source requirement in `docs/ip/ORIGIN_REGISTER.md`.
3. Draft the object without consulting prohibited source material.
4. Review naming, structure and wording for external similarity.
5. Record author, date and commit.
6. Add tests or examples demonstrating independent function.

## Similarity review

Before public release:

- search for conflicting project and standard names
- compare RACS schemas against known public standards
- identify unavoidable generic terminology
- document intentional interoperability references
- remove unnecessary structural similarity

## Historical preservation

The archived ACS repository remains historical evidence. It must not be deleted or rewritten. Its existence must not be represented as part of RACS development history beyond explaining why clean separation was required.