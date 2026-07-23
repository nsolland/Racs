"""RFC 8785 (JCS) canonicalization for RACS v0.2.

Uses the `rfc8785` library, which implements the JSON Canonicalization Scheme
(RFC 8785) precisely:
- object keys sorted by UTF-16 code-unit order (RFC 8785 3.2.3)
- numbers: integer-valued floats render as integers (1.0 -> "1"); -0.0 -> "0";
  shortest exponent form (1e-9, not 1e-09) per RFC 8785 3.2.2.3 / ECMA-262 7.1.12.1
- strings: ASCII control chars (< U+0020) escaped to \\uXXXX or \\b\\t\\n\\f\\r;
  non-ASCII code points serialized "as is" (NOT escaped) per RFC 8785 3.2.2.2;
  only \\ and " are escaped.

This is NOT json.dumps(sort_keys=True), which renders 1.0 as "1.0", -0.0 as
"-0.0", and 1e-9 as "1e-09" — all non-conformant.
"""

from __future__ import annotations

from typing import Any

import rfc8785

# rfc8785._Value is a recursive JSON value type; we accept Any for ergonomics.
JSONValue = Any


def canonical_bytes(value: JSONValue) -> bytes:
    """Return deterministic RFC 8785 canonical UTF-8 bytes for a JSON value."""
    return rfc8785.dumps(value)


def canonical_str(value: JSONValue) -> str:
    """Return deterministic RFC 8785 canonical UTF-8 string for a JSON value."""
    return rfc8785.dumps(value).decode("utf-8")
