# Claude adapter — RACS

Read `AGENTS.md` first. It is the repository working contract.

Then read:

1. `repo-manifest.yaml`
2. `README.md`
3. the normative files under `spec/`
4. relevant validators and test vectors

This file is a Claude-specific adapter. It does not define protocol semantics, authority, repository state, branch state or merge permission.

RACS owns the deterministic, interoperable decision contract and receipt/evidence schemas between VALO components.

RACS does not:

- evaluate evidence or risk
- determine admissibility
- grant authority or clearance
- enforce a decision
- perform side effects
- learn or fetch context
- redefine REHT policy

Canonical chain:

```text
VAIG evaluation
→ REHT clearance or rejection
→ RACS deterministic decision contract
→ gateway or execution-boundary enforcement
→ execution
→ Veritas receipt and observed outcome
```

Changes to normative schemas require versioning, conformance vectors and review. Repository source, current schemas, tests, remote Git state and CI evidence remain authoritative.
