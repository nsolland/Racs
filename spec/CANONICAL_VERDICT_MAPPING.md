# Canonical VALO Verdict Mapping & Monotonicity (RACS normative addendum)

Status: NORMATIVE addendum to the RACS 0.2 schema set.
Source of truth for cross-repo alignment of VAIG, reht, Racs, valo-platform,
Core, BARO, Index. This document does NOT change runtime; it constrains what
runtime artifacts must conform to.

Locked 2026-07-23. Base commit reference: valo-platform `d99d2f96`.

## 1. Canonical role & authority chain

```
VAIG / AARM            → signs GovernanceEvaluation (6-verdict vocabulary)
REHT                   → signs AdmissibilityDetermination (8 states; +REQUIRES_STEP_UP)
                       → issues GovernanceClearance ONLY on positive admissibility
Permit issuer          → signs CoreExecutionPermit bound to clearance + envelope digests
Core                   → verifies permit, clearance, and ALL digest bindings
                       → issues short-lived, single-use CommitToken
Bounded connector      → consumes CommitToken → creates external consequence
Receipt store          → produces ExecutionReceipt / OutcomeReceipt per RACS contracts
```

RACS defines wire format, signatures, bindings and proof semantics. RACS is
NOT itself the runtime component that "records & proves". Core does NOT issue
the CoreExecutionPermit; the permit exists before Core. Core verifies the permit
and then issues a single-use CommitToken
(`spec/core-execution-permit.schema.json` + `spec/commit-token-v0.2.schema.json`).

## 2. The three verdict spaces

### 2.1 AARM Verdict (VAIG — evaluation source, 6)
`spec/governance-evaluation-v0.2.schema.json` decision enum:
ALLOW, MODIFY, DEFER, DENY, STEP_UP, HALT.
This vocabulary is preserved verbatim and MUST NOT be reduced.

### 2.2 REHT AdmissibilityDetermination (8 states)
`spec/admissibility-determination-v0.2.schema.json` state enum:
ADMISSIBLE, CONDITIONALLY_ADMISSIBLE, NOT_ADMISSIBLE, INDETERMINATE,
STALE, REVOKED, HALTED, REQUIRES_STEP_UP.
REQUIRES_STEP_UP is the ONLY addition to this enum (locked 2026-07-23).
REHT does NOT execute actions and does NOT replace organizational authority.
ADMISSIBLE is a semantic state, not execution authority.

### 2.3 RACS GovernanceClearance (positive only)
`spec/governance-clearance.schema.json`:
decision ∈ {ALLOW, MODIFY};
admissibility_state ∈ {ADMISSIBLE, CONDITIONALLY_ADMISSIBLE}.
A clearance is a positive, bounded authorization artifact. It is issued ONLY on
positive admissibility. DEFER / DENY / STEP_UP / HALT MUST NOT be represented
as clearance variants.

## 3. The single mapping (lossless, monotonic)

| AARM verdict | REHT determination          | GovernanceClearance                  |
|--------------|-----------------------------|--------------------------------------|
| ALLOW        | ADMISSIBLE                  | ALLOW                                |
| MODIFY       | CONDITIONALLY_ADMISSIBLE    | MODIFY with explicit constraints     |
| DEFER        | INDETERMINATE               | (no clearance)                       |
| DENY         | NOT_ADMISSIBLE              | (no clearance)                       |
| STEP_UP      | REQUIRES_STEP_UP            | (no clearance)                       |
| HALT         | HALTED                      | (no clearance); any previously granted clearance is revoked or invalidated through a signed RevocationEvent |

The AARM verdict is preserved as BOUND PROVENANCE through the entire chain
(see `AdmissibilityDetermination.evaluation_bindings`
`[{evaluation_ref, evaluation_digest}]` → signed `GovernanceEvaluation`, and
`GovernanceClearance.admissibility_determination_ref` /
`admissibility_determination_digest` → `AdmissibilityDetermination`); it is never
used directly as execution authorization downstream. The evaluation is bound by
**content digest**, not by a bare identifier: `evaluation_bindings` carries both
the reference and the `sha256:` digest of the exact signed GovernanceEvaluation,
so the determination cannot be silently pointed at a different evaluation.

**Single binding path.** A `GovernanceClearance` MUST NOT carry its own
`evaluation_bindings`. Its only link to the evaluation layer is
`admissibility_determination_ref` + `admissibility_determination_digest`, which
resolves to the issuing `AdmissibilityDetermination`; that determination in turn
carries `evaluation_bindings` to the underlying `GovernanceEvaluation`(s). This
prevents a clearance from asserting an evaluation binding the determination does
not support.

## 4. NO_LONGER_ADMISSIBLE — deliberately OUT of scope for initial mapping

An initial AARM HALT MUST NOT map to NO_LONGER_ADMISSIBLE. NO_LONGER_ADMISSIBLE
belongs to continuous integrity: an action previously admissible that became
invalid due to drift, revocation, stale evidence, or changed state. RACS already
expresses this more precisely via STALE, REVOKED and HALTED post-clearance
events. An initial HALT maps to HALTED (terminal for that ActionEnvelope version
/ execution attempt); post-clearance revocation (REVOKED / STALE / HALTED) revokes or invalidates the
artifact through a signed RevocationEvent.

## 5. Monotonicity (normative)

- An existing artifact can NEVER be upgraded or mutated.
- A downstream evaluation may MAINTAIN or TIGHTEN the relevant permission.
- New evidence, new authority, or new state REQUIRES a NEW artifact, new ID,
  new digest.
- DEFER may later end in ALLOW, but only via a NEW evaluation.
- STEP_UP may later end in ALLOW, but only after STRONGER authority and a NEW
  determination.
- DENY and HALT are terminal for the concrete ActionEnvelope version /
  execution attempt — NOT necessarily for all future proposals.
- The AARM verdict travels as bound provenance; it is never re-applied as a
  direct authorization downstream.

## 6. MODIFY rule (constraints must be machine-enforceable, not self-attesting)

MODIFY may yield a clearance ONLY IF the constraints are **machine-enforceable**,
not merely self-attested. `machine_readable: true` + `binds_exact_action: true`
are necessary but NOT sufficient: the clearance MUST additionally carry at least
one enforceable element:
- a structured `rules` list (`minItems: 1`), each rule with `id`, `predicate`,
  `target`, and optional `value`; **or**
- a `constraint_set_ref` + `constraint_set_digest` pair referencing an external,
  digest-addressed constraint set.

A MODIFY clearance that asserts `machine_readable`/`binds_exact_action` but
carries no `rules` and no `constraint_set_ref`+`constraint_set_digest` is
**invalid** — it proves only that the issuer *claims* the constraints bind, not
that any binding exists. `capability`/`target` are NOT a substitute for
action-binding: the clearance already binds the exact capability, target and
payload via its own digests; changing them requires a NEW ActionEnvelope.

If the modification changes payload, target, capability, or intended effect,
the system MUST create a NEW ActionEnvelope version with a NEW digest and run
evaluation again. A loose "permit + constraints" is insufficient.

## 7. `evaluation_digest` — normative definition

`evaluation_digest` inside `evaluation_bindings` MUST be the digest of the
**exact signed evaluation artifact**. In RACS-JCS-1 terms (CANONICALIZATION.md)
this is defined precisely as:

> `evaluation_digest = SHA-256( canonicalize( GovernanceEvaluation.payload ) )`
> and therefore MUST equal that artifact's `payload_digest` (CANONICALIZATION.md
> rule 9). It is the **payload digest** of the exact referenced, signature-verified
> GovernanceEvaluation artifact, NOT a digest over the envelope, the signature, or
> any wrapper.

A determination MUST verify `evaluation_digest == payload_digest` of the
referenced, signature-verified GovernanceEvaluation before trusting the binding.
This closes the gap left by the earlier "digest of the exact signed artifact"
wording, which RACS-JCS-1 did not previously pin down.

## 8. Conformance obligations

Implementations MUST:
- Accept REQUIRES_STEP_UP as a valid AdmissibilityDetermination state.
- Never emit a GovernanceClearance for DEFER / DENY / STEP_UP / HALT.
- Preserve all 6 AARM verdicts in GovernanceEvaluation (no reduction).
- Bind ActionEnvelope digests end-to-end (permit → clearance → token).
- Treat the AARM verdict as provenance, not authorization.

Golden vectors and negative conformance tests live in
`test-vectors/0.2/canonical-*` and `tests/compliance/test_canonical_contract.py`.
