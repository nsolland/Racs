# Official JCS (RFC 8785) test vectors

These vectors are derived from the normative examples in **RFC 8785, Appendix A**
and the JCS conformance set used by multiple independent implementations. They are
language-independent: every conformant RFC 8785 implementation MUST emit byte-for-
byte identical canonical output for each `input`, and the SHA-256 over those UTF-8
bytes is fixed.

Each file has:
- `input` — the JSON value to canonicalize
- `expected_canonical` — the exact canonical UTF-8 string (RFC 8785)
- `expected_digest` — `sha256:` + lowercase hex SHA-256 of `expected_canonical`

The RACS bindings (3A) MUST reproduce `expected_canonical` and `expected_digest`
identically in Python, Rust, and TypeScript. This is the cross-language gate.

Sources:
- RFC 8785 Appendix A: https://datatracker.ietf.org/doc/html/rfc8785#appendix-A
- The well-known JCS number/Unicode/escaping/-0 edge cases.
