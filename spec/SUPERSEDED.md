# Superseded schemas (issue #991 ruling)

This record lists contracts retired by the P0.2 canonicalization. RACS/spec is the single
canonical source for runtime execution-governance contracts (ruling #991.1). Each entry names
the replacement and whether a compatibility adapter exists.

| Superseded schema | Repo | Replacement (canonical) | Compatibility adapter | Status |
|-------------------|------|-------------------------|-----------------------|--------|
| `action-envelope.schema.json` | reht-standard | `action-envelope-v0.2.schema.json` | reht-standard `$ref` | superseded 2026-07-25 |
| `authority-context.schema.json` | reht-standard | `authority-context.yaml` | reht-standard `$ref` | superseded 2026-07-25 |
| `policy-context.schema.json` | reht-standard | `policy-context.yaml` | reht-standard `$ref` | superseded 2026-07-25 |
| `evidence-package.schema.json` | reht-standard | `evidence-package.yaml` | reht-standard `$ref` | superseded 2026-07-25 |
| `governance-state.schema.json` | reht-standard | `governance-state.schema.json` (RACS, NEW) | reht-standard `$ref` | superseded 2026-07-25 |
| `continuous-integrity-event.schema.json` | reht-standard | `continuous-integrity-event-v0.2.schema.json` | reht-standard `$ref` | superseded 2026-07-25 |
| `execution-receipt.schema.json` | reht-standard | `execution-receipt-v0.2.schema.json` | reht-standard `$ref` | superseded 2026-07-25 |
| `admissibility-result.schema.json` | reht-standard | `admissibility-determination-v0.2.schema.json` | reht-standard `$ref` | superseded 2026-07-25 |
| `acs_packet.schema.json` | VAIG (`vacs/`) | `action-envelope-v0.2.schema.json` | VAIG compat adapter | deprecated 2026-07-25 |
| `acs_receipt.schema.json` | VAIG (`vacs/`) | `execution-receipt-v0.2.schema.json` | VAIG compat adapter | deprecated 2026-07-25 |
| `vacs_profile.schema.json` | VAIG (`vacs/`) | `authority-context.yaml` + `policy-context.yaml` | VAIG compat adapter | deprecated 2026-07-25 |
| `services/reth/` (stub svc) | valo-platform | `services/reth-stub/` (rename) | rename + alias | renamed 2026-07-25 |

## Rules

- No NEW ACS/VACS contracts may be introduced (ruling #991.2).
- reht-standard MUST reference RACS via `$ref`, never duplicate field shapes.
- Core (valo-v5-core) MUST NOT redefine upstream decision/schema/authority/policy semantics.
- Supersession is recorded here and in each repo's PR; implementations link to these IDs.
