# AGENTS.md — public contribution guidance

This repository is a public standards and conformance surface for RACS.

Contributors and automated agents should work only from the public artifacts in this repository. Read `README.md`, `SPECIFICATION.md`, the normative files under `spec/`, `CONTRIBUTING.md`, and the relevant public conformance vectors before proposing changes.

## Public boundary

- Treat the published specification, schemas, validators, and conformance vectors as authoritative for this repository.
- Do not infer, document, or expose private product architecture, private repositories, internal orchestration, research hypotheses, roadmaps, work claims, or unpublished implementation details.
- Do not add branch ownership notes, handover records, hidden dependency maps, or internal component topology to the public tree.
- Keep normative changes versioned, reviewable, vendor-neutral, and covered by conformance evidence.
- Public examples must demonstrate the contract without requiring private implementation knowledge.

Repository-local public CI and contribution rules remain authoritative for build and review requirements.
