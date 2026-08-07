# CSRD/ESRS Binding Profile V1

**Build order:** `nsolland/valo-platform#1492` (Slice 8)
**Owner:** RACS (immutable decision-contract data)
**Status:** canonical additive extension
**Version:** v1

## Purpose

RACS carries immutable references and digests for sustainability reporting
actions. These additive extension contracts bind refs ONLY — they never copy
datapoint values, ESRS text or materiality logic.

## Extensions

- `sustainability-reporting-action-binding-v1.schema.json`
- `sustainability-reporting-receipt-binding-v1.schema.json`

## What may be referenced

A RACS action binding may reference:

- reporting entity ref + digest
- reporting period
- standard profile ref + digest
- target artifact ref + digest
- source evidence refs
- materiality decision ref
- REHT clearance ref
- expected receipt type

## Acceptance

- schema is deny-unknown (`additionalProperties: false`)
- canonical `action-envelope-v0.2` remains the source of the action
- legacy or incomplete binding is rejected
- golden fixtures consumed identically by the Python binding and an
  independent validator

## Boundary

RACS binds transport and action references. It does not own ESRS semantics,
datapoint values or materiality logic.
