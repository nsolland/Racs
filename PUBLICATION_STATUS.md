# Publication status

Status date: 2026-08-21

RACS is being prepared as a public, vendor-neutral protocol and conformance surface for deterministic governance-decision, action, enforcement-boundary and receipt bindings.

The repository is not an authorization engine, policy evaluator, execution runtime or source of authority. Public availability does not make RACS responsible for deciding whether an action is permitted.

## Public surface

The intended public surface includes:

- normative schemas and protocol semantics;
- deterministic canonicalization and bindings;
- conformance validators and test vectors;
- effect-boundary invariants including no-direct-effect-path and null-effect-on-deny;
- reference bindings that remain implementation independent.

## Explicit exclusions

The public surface does not include or require:

- proprietary authorization/evaluation logic;
- private organizational policy or authority data;
- production credentials or deployment configuration;
- PEACE, MCIP, Neuro Mesh or other adaptive intelligence research.

## Release rule

Repository visibility is not a release by itself. A release requires an immutable version/tag, exact commit, declared license and green conformance checks on that commit.
