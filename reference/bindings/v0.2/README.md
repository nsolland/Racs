# RACS v0.2 — Canonical Contract Bindings (Stage 3A: canonicalization kernel)

These are the **canonicalization kernel** bindings for the RACS v0.2 contract
(PR #65 / step 2). They implement exactly one thing, identically in three
languages:

> Given a JSON value, produce its **RFC 8785 (JCS)** canonical UTF-8 bytes and
> the **SHA-256** of those bytes, as `sha256:<hex>`.

This is the foundation that step 3B (typed model bindings) and the consuming
services (valo-platform, VAIG, Core, BARO, REHT) build on.

## Why this exists separately from `reference/python/racs_canonical.py`

`reference/python/racs_canonical.py` uses `json.dumps(sort_keys=True,
separators=(",",":"), ensure_ascii=False)`. **That is NOT RFC 8785-conformant**:
- `1.0` renders as `"1.0"` (should be `"1"`)
- `-0.0` renders as `"-0.0"` (should be `"0"`)
- `1e-9` renders as `"1e-09"` (should be `"1e-9"`)
- cross-language determinism is not guaranteed

The bindings here use dedicated RFC 8785 libraries and are verified to produce
**byte-identical** output across Python/Rust/TypeScript.

## Libraries (per language)

| Lang | Library | Canonical entry |
|------|---------|-----------------|
| Python | `rfc8785>=0.1.4` | `racs_v02.canonical.canonical_bytes` |
| Rust | `serde_jcs=0.1` | `racs_v02::canonical_bytes` |
| TypeScript | `json-canonicalize@2.0.0` | `canonicalString` |

## RFC 8785 specifics enforced

- **Strings** (RFC 8785 §3.2.2.2): non-ASCII code points are serialized *as is*
  (NOT escaped to `\uXXXX`); only `"` and `\` are escaped; control chars
  `< U+0020` escaped to `\uXXXX` (or `\b\t\n\f\r`).
- **Numbers** (RFC 8785 §3.2.2.3): integer-valued floats render as integers;
  `-0.0` → `0`; shortest exponent form (`1e-9`, not `1e-09`).
- **Keys** (RFC 8785 §3.2.3): object property names sorted by UTF-16 code-unit
  order, recursively, arrays scanned for objects but element order preserved.

## Shared conformance vectors

- `test-vectors/jcs/official/vector-01..06.json` — official JCS edge cases
  (numbers/`-0`/Unicode/escaping/nesting). Each carries `expected_canonical`
  and `expected_digest`.
- `test-vectors/jcs/racs-v0.2/governance-evaluation.json` — RACS
  GovernanceEvaluation (ALLOW) payload, canonicalized with RFC 8785; the shared
  `payload_digest` all three languages must reproduce.

## Cross-language byte-identical gate

`gate.rb` runs each binding over every shared vector and asserts all three
emit identical canonical bytes and identical digests. This is the hard
requirement: the bindings are not accepted unless output is byte-for-byte equal
across languages.

## Layout

```
v0.2/
  manifest.json
  README.md
  gate.rb                      # cross-language byte-identical gate
  python/   (rfc8785)          # src/racs_v02/{canonical,digest,cli}.py, tests/
  rust/     (serde_jcs)        # src/lib.rs, src/bin/conformance.rs, tests/
  typescript/ (json-canonicalize)  # src/{index,cli}.ts, test/conformance.test.ts
```

## Stage 3B (separate PR)

Typed model bindings (structs/classes) for `GovernanceEvaluation`,
`AdmissibilityDetermination`, and `GovernanceClearance` in all three languages,
validated against the v0.2 schemas. Requires this 3A kernel to be green and
merged first.
