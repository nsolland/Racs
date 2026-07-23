"""RACS v0.2 canonical contract bindings — canonicalization kernel (3A).

This package provides the RFC 8785-conformant canonicalization used by the RACS
wire format, plus SHA-256 payload digests. It intentionally contains NO model
types (those arrive in 3B) and NO signing/trust/revocation logic.

The canonical output of `canonical_bytes` MUST be byte-for-byte identical across
the Python, Rust, and TypeScript bindings, verified by the shared JCS test
vectors under test-vectors/jcs/.
"""

from .canonical import canonical_bytes, canonical_str
from .digest import sha256_digest, verify_payload_digest

__all__ = [
    "canonical_bytes",
    "canonical_str",
    "sha256_digest",
    "verify_payload_digest",
]
