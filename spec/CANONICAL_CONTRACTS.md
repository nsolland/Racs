# RACS Canonical Contract Index (P0.2, issue #991)

Status: NORMATIVE. Source of truth for runtime execution-governance contracts in the
VALO execution chain: `VAIG evaluates → REHT clears → RACS decides → Core enforces → Receipts prove`.

Ruling #991:
1. **RACS/spec is canonical** for runtime execution-governance contracts, decisions,
   canonicalization and digest semantics.
2. reht-standard remains canonical ONLY for REHT-specific clearance/authorization
   standards; it MUST reference these RACS contracts, not duplicate them.
3. valo-v5-core is the deterministic enforcement kernel (Core) AFTER RACS; it MUST NOT
   redefine upstream decisions, schemas, authority or policy semantics.
4. ACS/VACS is DEPRECATED as an execution decision layer; RACS replaces it. Preserve only
   genuinely distinct VAIG evaluation artifacts with compatibility adapters.

## The 11 canonical contracts

| # | Contract | RACS schema (canonical) | Superseded source | Notes |
|---|----------|-------------------------|-------------------|-------|
| 1 | Action Envelope | `action-envelope-v0.2.schema.json` | reht-standard `action-envelope.schema.json` | wire format of one action |
| 2 | Authority Context | `authority-context.yaml` | reht-standard `authority-context.schema.json` | delegation chains |
| 3 | Policy Context | `policy-context.yaml` | reht-standard `policy-context.schema.json` | policy data, never code |
| 4 | Evidence Package | `evidence-package.yaml` | reht-standard `evidence-package.schema.json` | facts/conditions/reasoning |
| 5 | Governance State | `governance-state.schema.json` (NEW, see below) | reht-standard `governance-state.schema.json` | runtime governance state |
| 6 | Delegation Chain | `delegation-chain-v0.2.schema.json` | — | traced authority |
| 7 | VAIG Evaluation | `governance-evaluation-v0.2.schema.json` | ACS/VACS `acs_packet` | 6-verdict vocabulary (ALLOW/MODIFY/DEFER/DENY/STEP_UP/HALT) |
| 8 | REHT Clearance | `admissibility-determination-v0.2.schema.json` + `governance-clearance.schema.json` | reht-standard `admissibility-result.schema.json` | 8-state admissibility |
| 9 | RACS Decision | `CANONICAL_VERDICT_MAPPING.md` | ACS/VACS `acs_receipt` | decision+receipt binding |
| 10 | Continuous Integrity Event | `continuous-integrity-event-v0.2.schema.json` | reht-standard `continuous-integrity-event.schema.json` | WORM event |
| 11 | Execution Receipt | `execution-receipt-v0.2.schema.json` | reht-standard `execution-receipt.schema.json` | Core proves execution |

## Canonicalization & digest (RACS-JCS-1)

- Canonicalization: **RFC 8785** (`jsoncanon`). Sorted keys, no insignificant whitespace,
  UTF-8, ES2018 number formatting (e.g. `2000.0 → "2000"`).
- Digest: **SHA-256** over canonical bytes, represented `sha256:<lowercase-hex>`.
- Rules: `spec/CANONICALIZATION.md` (13 rules). See also `CANONICAL_VERDICT_MAPPING.md`
  for the three verdict spaces and binding digest semantics (`evaluation_digest`).

## Golden vectors

`spec/golden-vectors.json` carries pinned payloads + `payload_digest` values for the four
primary contracts. The test `tests/test_golden_digests.py` re-canonicalizes each payload and
asserts the digest is byte-identical to the pinned value — proving the same vector produces
the same digest across any RFC 8785 + SHA-256 implementation (PHP/JS/Py/Rust).

## Compatibility mappings (recorded, not invented)

- `vacs/acs_packet.schema.json` (VAIG) → maps to `action-envelope-v0.2` (RACS). DEPRECATED.
- `vacs/acs_receipt.schema.json` (VAIG) → maps to `execution-receipt-v0.2` (RACS). DEPRECATED.
- reht-standard `*.schema.json` → MUST `$ref` the corresponding RACS schema; see reht-standard PR.
- valo-platform `services/reth/` → renamed `services/reth-stub/` (collision with `reht` brand).

## Supersession record

See `SUPERSEDED.md` for the explicit list of schemas retired by this ruling and their
replacement + compatibility adapter status.
