# RACS Clean-Room Development Record

## Decision

A previous historical repository was archived because it contained or mirrored material from an existing third-party project.

RACS was created as a separate repository and separate standard.

No source files, specification text, schemas, diagrams, examples or repository structure from archived or unlicensed third-party material are authorized for reuse in RACS.

## Clean-room baseline

Date established: 2026-07-11

Repository: `nsolland/Racs`

Initial authoring basis:

- independently authored execution-governance requirements
- pre-execution admissibility requirements
- governance-evaluation requirements
- deterministic enforcement requirements
- evidence and observation requirements
- receipt-based evidence and accountability

The public clean-room record intentionally describes requirement classes rather than private product components, repository topology or implementation sequencing.

## Permitted inputs

Contributors may use:

- independently written requirements owned or licensed for use in RACS
- public laws and regulations, with citation
- published standards used only as references, with attribution
- generic protocol and distributed-systems knowledge
- documented source material with confirmed ownership and release permission

## Prohibited inputs

Contributors must not copy or closely adapt:

- text from archived or restricted repositories
- unlicensed third-party schemas or documentation
- distinctive third-party diagrams
- externally authored field structures without attribution and license review
- unresolved collaboration material
- confidential material belonging to another party

## Development procedure

For every major protocol object:

1. State the independently owned requirement in neutral language.
2. Record the source class in `docs/ip/ORIGIN_REGISTER.md`.
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
- remove private implementation mappings that are not required for the public standard

## Historical preservation

Historical repositories and records may remain preserved as evidence. Their existence does not make their contents normative RACS material, and this public record does not expose their private implementation relationships.
