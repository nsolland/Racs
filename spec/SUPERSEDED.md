# Superseded public schemas

This record identifies public contract names retired by the current RACS canonicalization line. It intentionally does not publish private repository locations, internal migration topology, or implementation ownership maps.

| Superseded public contract | Canonical replacement | Status |
|---|---|---|
| `action-envelope.schema.json` | `action-envelope-v0.2.schema.json` | superseded |
| `authority-context.schema.json` | `authority-context.yaml` | superseded |
| `policy-context.schema.json` | `policy-context.yaml` | superseded |
| `evidence-package.schema.json` | `evidence-package.yaml` | superseded |
| `governance-state.schema.json` | current RACS governance-state schema | superseded |
| `continuous-integrity-event.schema.json` | `continuous-integrity-event-v0.2.schema.json` | superseded |
| `execution-receipt.schema.json` | `execution-receipt-v0.2.schema.json` | superseded |
| `admissibility-result.schema.json` | `admissibility-determination-v0.2.schema.json` | superseded |
| legacy ACS/VACS packet and receipt names | current RACS action/evidence contracts | deprecated |

## Rules

- New public work uses the canonical RACS contract names.
- Compatibility mappings may preserve legacy wire inputs but must not create a second authoritative contract family.
- Private source locations, migration branches, downstream repository identities, and portfolio ownership maps are not part of this public compatibility record.
