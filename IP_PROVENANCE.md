# RACS IP Provenance

## Status

- IP status: author-owned active architecture
- Origin date: 2026-07-11
- Initial author: Njål Gaute Solland
- Current rights holder: Njål Gaute Solland
- Project: VALO Research
- Legal-entity assignment: none recorded
- Active authority: true

`VALO` / `VALO Research` is used here as a project and research name. It is not identified by this repository as a separate legal rights holder. Any later transfer of the IP to a company or other legal entity requires a documented assignment.

## Clean-room declaration

RACS was initialized as a new specification repository after a separate historical repository was designated for archival.

RACS does not claim ownership of external projects, their names, documentation, schemas, code, diagrams or implementation structure.

No material from archived or third-party repositories is normative for RACS unless it is explicitly identified, licensed and reviewed as such.

## Independent architectural basis

RACS is derived from independently developed requirements around:

- action admissibility
- explicit authority
- evidence-bound execution
- policy-bound execution
- execution boundaries
- continuous integrity
- deterministic governance decisions
- cryptographically traceable receipts

These requirements describe the public protocol problem, not a private implementation topology.

## Public implementation boundary

RACS standardizes neutral protocol objects, wire semantics and conformance behavior between implementations.

Evidence producers, evaluators, authorization systems, enforcement runtimes and evidence stores are external implementation roles. Their private product names, internal dependency graph, build order, thresholds, orchestration and implementation structure are not normative RACS material and are intentionally not mapped here.

## Repository rules

1. Do not copy text, schemas, diagrams or source code from archived or unlicensed third-party repositories.
2. Record external references in `THIRD_PARTY_NOTICES.md`.
3. Mark imported proposals as non-normative until reviewed.
4. Preserve contributor attribution.
5. Any disputed concept remains classified as unresolved until reviewed.
6. Normative changes require a commit, rationale and version update.
