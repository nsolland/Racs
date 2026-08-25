# RACS v0.2 — Canonical Contract Bindings

These public bindings implement RFC 8785 (JCS) canonicalization and SHA-256 digest generation consistently across Python, Rust and TypeScript.

> Given a JSON value, produce its RFC 8785 canonical UTF-8 bytes and the SHA-256 of those bytes as `sha256:<hex>`.

The bindings are a public interoperability primitive. They intentionally do not document private consumers, portfolio topology, internal delivery stages, or downstream implementation ownership.

## Libraries

| Language | Library | Canonical entry |
|---|---|---|
| Python | `rfc8785>=0.1.4` | `racs_v02.canonical.canonical_bytes` |
| Rust | `serde_jcs=0.1` | `racs_v02::canonical_bytes` |
| TypeScript | `json-canonicalize@2.0.0` | `canonicalString` |

## Required behavior

- strings follow RFC 8785 serialization rules;
- numbers use the RFC 8785 canonical form;
- object keys use the required deterministic ordering;
- all supported language bindings must reproduce byte-identical canonical output and digests for the shared public vectors.

## Public conformance vectors

The `test-vectors/` directory contains shared vectors used to verify cross-language canonicalization and contract binding behavior.

## Layout

```text
v0.2/
  manifest.json
  README.md
  gate.py
  python/
  rust/
  typescript/
```

Public typed bindings and conformance checks are versioned with the corresponding RACS contract profile.
