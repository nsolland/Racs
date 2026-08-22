# Publication status

Status date: 2026-08-22

RACS is a public, vendor-neutral protocol and conformance surface for deterministic governance-decision, action, enforcement-boundary and receipt bindings.

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
- unrelated private research, product architecture or commercial implementation internals.

## Publication rule

This is a public repository: a branch push is already disclosure. New substantive material must therefore receive explicit human IP/publication review before the first public push. Merge-time CI is defense in depth, not the primary IP gate.

Repository visibility is not a versioned release by itself. A release requires an immutable version/tag, exact commit, declared license and green conformance checks on that commit.
