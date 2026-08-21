# Narrowing Proof for MODIFY_RUNTIME_BOUNDS (P0.2, issue #142)

Status: NORMATIVE.

A `MODIFY_RUNTIME_BOUNDS` decision narrows the runtime bounds under which
further execution may continue. This spec fixes the required **narrowing
proof**: the decision MUST demonstrate that the new bounds are a strict subset
of the previous bounds, so the decision can never widen authority or scope.

## Vocabulary

- `before` — the runtime bounds in force before the decision.
- `after` — the proposed runtime bounds.
- `MODIFY_RUNTIME_BOUNDS` — a `CONTINUITY_DECISION` (`continuity-decision-v0.2.schema.json`)
  whose effect is to replace `before` with `after`.

## Rule (N1 — narrowing)

`MODIFY_RUNTIME_BOUNDS` is admissible only if `after ⊆ before` is proven over
the effective comparison fields:

- **action vocabulary**: every action_type permitted in `after` is permitted in `before`;
- **target scope**: the set of targets reachable in `after` is a subset of `before`;
- **effect set**: every requested_effect in `after` is in `before`;
- **policy version**: `after` binds to a policy version that `before` already bound to (or an equivalent);
- **expiry**: `after.valid_until` is not later than `before.valid_until`.

## Rule (N2 — proof artifact)

The decision MUST carry a `narrowing_proof` object:

```json
{
  "narrowing_proof": {
    "fields": ["action_type", "target", "requested_effect", "policy_version", "valid_until"],
    "subset_verified": true,
    "before_digest": "sha256:...",
    "after_digest": "sha256:...",
    "equal_or_tightened": true
  }
}
```

## Rule (N3 — fail closed)

If the proof cannot be produced (subset not verified, a field missing, or
`after` widens any field), the decision MUST be `DENY` and MUST NOT apply
`after`. A widened bound is a control failure and suspected bypass.

## Rule (N4 — immutability)

`before` and `after` are pinned by digest. The proof is over the canonical
(RFC 8785) serializations, so a reordered or rewritten payload cannot
masquerade as narrowing.