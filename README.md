# RACS

RACS — REHT Action Control Standard.

RACS is vendor-neutral, model-agnostic protocol/schema infrastructure for representing and binding an already-made governance decision to the exact action, enforcement boundary and resulting evidence.

RACS is not an evaluator, authorization engine, policy engine, enforcement point or executor.

## Core question

How is an already-made governance decision represented and bound deterministically to the exact action, execution boundary and resulting receipt?

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
- effect-boundary conformance semantics

RACS does not:

- evaluate evidence or risk
- decide admissibility
- grant or infer authority
- authorize execution
- enforce policy
- execute actions
- define model architecture or agent reasoning
- require a specific model, agent framework, identity provider, policy engine or execution vendor
- determine moral truth or organizational legitimacy

## Architecture position

```text
Evidence / state / policy sources
            |
            v
evaluator / authorization provider
            |
            v
RACS deterministic decision/action binding
            |
            v
external PEP / Gateway
            |
            v
external consequence
            |
            v
receipt / evidence verifier
```

REHT is one compatible authorization provider. VALO Gateway and Veritas are compatible enforcement and evidence implementations. None is required by the RACS protocol.

RACS cannot widen, reinterpret or replace the authority represented by an upstream authorization decision.

## Research context

RACS is one of the public protocol surfaces synthesized in the paper:

**Njål Gaute Solland, _Consequence Governance: Governing the Transition from Proposed Action to Real-World Effect_, Version 1.0, September 5, 2026.**

Zenodo record: https://zenodo.org/records/22377951

The paper positions RACS as the deterministic binding layer inside a broader Consequence Governance architecture. RACS binds an already-made governance decision to an exact action and effect boundary; it does not itself grant authority or authorize execution.

## Repository status

Active v0.2 protocol specification with normative schemas, reference bindings, compliance validators and test vectors.

The repository is being prepared as a public protocol/conformance surface. See `PUBLICATION_STATUS.md` for the exact boundary and release rule.

No source code, schemas, wording, diagrams or structure have been copied from the archived `nsolland/ACS` repository or the external Agent Control Standard project.

## Documents

- `SPECIFICATION.md`
- `IP_PROVENANCE.md`
- `THIRD_PARTY_NOTICES.md`
- `PUBLICATION_STATUS.md`
- `docs/architecture/BOUNDARIES.md`
- `spec/` — normative v0.2 JSON schemas (source of truth)

## License

Apache License 2.0. See `LICENSE`.
