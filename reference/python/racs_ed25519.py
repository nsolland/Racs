"""Ed25519 signing helpers for RACS Draft 0.2 artifacts.

Requires the `cryptography` package. Trust-registry resolution, schema validation,
revocation and temporal checks remain caller responsibilities.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from racs_canonical import sha256_digest, signature_input_bytes, verify_payload_digest


class ArtifactVerificationError(ValueError):
    """Raised when an artifact cannot be authenticated."""


def _utc_z(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_signed_artifact(
    *,
    artifact_type: str,
    profile_id: str,
    artifact_id: str,
    tenant_id: str,
    trust_domain: str,
    issuer_id: str,
    issuer_role: str,
    key_id: str,
    issued_at: datetime,
    expires_at: datetime,
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    previous_artifact_ref: str | None = None,
) -> dict[str, Any]:
    artifact: dict[str, Any] = {
        "artifact_type": artifact_type,
        "schema_version": "0.2.0",
        "profile_id": profile_id,
        "artifact_id": artifact_id,
        "tenant_id": tenant_id,
        "trust_domain": trust_domain,
        "issuer_id": issuer_id,
        "issuer_role": issuer_role,
        "issued_at": _utc_z(issued_at),
        "expires_at": _utc_z(expires_at),
        "previous_artifact_ref": previous_artifact_ref,
        "payload": dict(payload),
        "payload_digest": sha256_digest(payload),
        "canonicalization": "RACS-JCS-1",
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value": "",
        },
    }
    signature = private_key.sign(signature_input_bytes(artifact))
    artifact["signature"]["value"] = base64.urlsafe_b64encode(signature).decode("ascii")
    return artifact


def verify_signed_artifact(
    artifact: Mapping[str, Any],
    public_key: Ed25519PublicKey,
    *,
    now: datetime | None = None,
) -> None:
    if artifact.get("schema_version") != "0.2.0":
        raise ArtifactVerificationError("unsupported schema version")
    if artifact.get("canonicalization") != "RACS-JCS-1":
        raise ArtifactVerificationError("unsupported canonicalization profile")
    signature = artifact.get("signature")
    if not isinstance(signature, Mapping):
        raise ArtifactVerificationError("missing signature object")
    if signature.get("algorithm") != "Ed25519":
        raise ArtifactVerificationError("unsupported signature algorithm")
    if not verify_payload_digest(artifact):
        raise ArtifactVerificationError("payload digest mismatch")

    value = signature.get("value")
    if not isinstance(value, str) or not value:
        raise ArtifactVerificationError("missing signature value")
    try:
        raw_signature = base64.urlsafe_b64decode(value.encode("ascii"))
        public_key.verify(raw_signature, signature_input_bytes(artifact))
    except (ValueError, InvalidSignature) as exc:
        raise ArtifactVerificationError("invalid Ed25519 signature") from exc

    check_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        issued_at = datetime.fromisoformat(str(artifact["issued_at"]).replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(str(artifact["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise ArtifactVerificationError("invalid artifact timestamps") from exc
    if check_time < issued_at:
        raise ArtifactVerificationError("artifact is not yet valid")
    if check_time >= expires_at:
        raise ArtifactVerificationError("artifact has expired")


__all__ = [
    "ArtifactVerificationError",
    "build_signed_artifact",
    "verify_signed_artifact",
]
