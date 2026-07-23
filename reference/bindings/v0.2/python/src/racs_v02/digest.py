"""SHA-256 payload digests over RFC 8785 canonical bytes."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .canonical import canonical_bytes


def sha256_digest(value: Any) -> str:
    """Return 'sha256:<lowercase-hex>' over the RFC 8785 canonical bytes of value."""
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def verify_payload_digest(artifact: Mapping[str, Any]) -> bool:
    """Return True iff artifact['payload_digest'] == sha256_digest(artifact['payload'])."""
    declared = artifact.get("payload_digest")
    payload = artifact.get("payload")
    if not isinstance(declared, str) or payload is None:
        return False
    return sha256_digest(payload) == declared
