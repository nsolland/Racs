"""RACS Draft 0.2 canonicalization and digest reference.

This module implements the deterministic JSON byte representation used by the
current RACS-JCS-1 test vectors and payload digests. It intentionally does not
perform trust resolution or Ed25519 verification; authoritative consumers must
perform those steps in the order specified by spec/CANONICALIZATION.md.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from typing import Any, Mapping


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by RACS-JCS-1."""


def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(f"{path}: NaN and infinity are forbidden")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalizationError(
        f"{path}: unsupported JSON value type {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for a JSON-compatible value."""
    _validate(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    return encoded.encode("utf-8")


def sha256_digest(value: Any) -> str:
    """Return a lowercase RACS SHA-256 digest over canonical JSON bytes."""
    digest = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    return f"sha256:{digest}"


def verify_payload_digest(artifact: Mapping[str, Any]) -> bool:
    """Compare an artifact payload with its declared payload_digest."""
    if "payload" not in artifact or "payload_digest" not in artifact:
        return False
    declared = artifact["payload_digest"]
    if not isinstance(declared, str):
        return False
    return sha256_digest(artifact["payload"]) == declared


def signature_input_bytes(artifact: Mapping[str, Any]) -> bytes:
    """Build the RACS-JCS-1 signature input.

    The signature value is replaced by the empty string while every other
    signed field remains unchanged.
    """
    candidate = copy.deepcopy(dict(artifact))
    signature = candidate.get("signature")
    if not isinstance(signature, dict):
        raise CanonicalizationError("$.signature must be an object")
    if "value" not in signature:
        raise CanonicalizationError("$.signature.value is required")
    signature["value"] = ""
    return canonical_json_bytes(candidate)


__all__ = [
    "CanonicalizationError",
    "canonical_json_bytes",
    "sha256_digest",
    "signature_input_bytes",
    "verify_payload_digest",
]
