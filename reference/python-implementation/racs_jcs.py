"""RACS-JCS-1 canonicalization helpers (RFC 8785 profile).

Minimal, dependency-free implementation used by golden-vector digest tests.
Mirrors spec/CANONICALIZATION.md rules 1-10.
"""
import hashlib
import json


def canonicalize(obj) -> bytes:
    """Return RACS-JCS-1 canonical UTF-8 bytes for ``obj``."""
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest(obj) -> str:
    """Return ``sha256:<hex>`` over canonical bytes of ``obj``."""
    return "sha256:" + hashlib.sha256(canonicalize(obj)).hexdigest()


def artifact_digest(artifact: dict) -> str:
    """payload_digest per CANONICALIZATION.md rule 9."""
    return digest(artifact["payload"])
