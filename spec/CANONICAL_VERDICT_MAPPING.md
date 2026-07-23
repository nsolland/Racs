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
| HALT         | HALTED                      | (no clearance); active artifacts recalled |

The AARM verdict is preserved as BOUND PROVENANCE through the entire chain
(see `governance-evaluation.admissibility_determination_ref` / clearance
`admissibility_determination_digest`); it is never used directly as execution
authorization downstream.

## 4. NO_LONGER_ADMISSIBLE — deliberately OUT of scope for initial mapping

An initial AARM HALT MUST NOT map to NO_LONGER_ADMISSIBLE. NO_LONGER_ADMISSIBLE
belongs to continuous integrity: an action previously admissible that became
invalid due to drift, revocation, stale evidence, or changed state. RACS already
expresses this more precisely via STALE, REVOKED and HALTED post-clearance
events. An initial HALT maps to HALTED (terminal for that ActionEnvelope version
/ execution attempt); post-clearance revocation (REVOKED / STALE / HALTED)
recedes the artifact back to a halted state.

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

## 6. MODIFY rule (constraints are not enough)

MODIFY may yield a clearance ONLY IF:
- the constraints are machine-readable;
- the final action is unambiguous;
- the clearance binds the EXACT action actually to be performed.
If the modification changes payload, target, capability, or intended effect,
the system MUST create a NEW ActionEnvelope version with a NEW digest and run
evaluation again. A loose "permit + constraints" is insufficient.

## 7. Conformance obligations

Implementations MUST:
- Accept REQUIRES_STEP_UP as a valid AdmissibilityDetermination state.
- Never emit a GovernanceClearance for DEFER / DENY / STEP_UP / HALT.
- Preserve all 6 AARM verdicts in GovernanceEvaluation (no reduction).
- Bind ActionEnvelope digests end-to-end (permit → clearance → token).
- Treat the AARM verdict as provenance, not authorization.

Golden vectors and negative conformance tests live in
`test-vectors/0.2/canonical-*` and `tests/compliance/test_canonical_contract.py`.
