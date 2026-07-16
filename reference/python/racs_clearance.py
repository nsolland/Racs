"""RACS Draft 0.2 GovernanceClearance issuance and verification.

Implements P0-B (Clearance authenticity):

* ``GovernanceClearanceIssuer`` builds a canonical signed artifact envelope
  whose payload conforms to ``governance-clearance.schema.json`` and signs it
  with an Ed25519 REHT-clearance-issuer key.
* ``GovernanceClearanceVerifier`` performs fail-closed verification per
  ``spec/TRUST_MODEL.md``: schema validity, payload digest, signature, issuer
  role/scope, expiry and revocation. A locally constructed (unsigned or
  unknown-issuer) clearance MUST be rejected.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import jsonschema

from racs_canonical import sha256_digest, verify_payload_digest
from racs_crypto import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    sign_artifact,
    verify_artifact_signature,
)

_SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "spec")


def _load_schema(name: str) -> dict:
    path = os.path.join(_SCHEMA_DIR, name)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


_ENVELOPE_SCHEMA = _load_schema("canonical-artifact-envelope.schema.json")
_CLEARANCE_SCHEMA = _load_schema("governance-clearance.schema.json")

_REHT_ROLE = "REHT_CLEARANCE_ISSUER"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_from_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


class ClearanceError(Exception):
    """Base class for clearance verification failures."""


class GovernanceClearanceIssuer:
    """Issue signed GovernanceClearance artifacts (REHT clearance authority)."""

    def __init__(
        self,
        *,
        issuer_id: str,
        tenant_id: str,
        trust_domain: str,
        private_key: Ed25519PrivateKey,
        key_id: str,
        profile_id: str = "racs-platform-0.2",
        valid_for_seconds: int = 3600,
    ) -> None:
        self.issuer_id = issuer_id
        self.tenant_id = tenant_id
        self.trust_domain = trust_domain
        self.private_key = private_key
        self.key_id = key_id
        self.profile_id = profile_id
        self.valid_for_seconds = valid_for_seconds

    def issue(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Build and sign a canonical GovernanceClearance artifact.

        ``payload`` must conform to governance-clearance.schema.json. The
        issuer fills envelope-level fields and signs the artifact.
        """
        jsonschema.validate(instance=payload, schema=_CLEARANCE_SCHEMA)
        issued = _iso_from_ts(datetime.now(timezone.utc).timestamp())
        expires = _iso_from_ts(
            datetime.now(timezone.utc).timestamp() + self.valid_for_seconds
        )
        artifact = {
            "artifact_type": "GovernanceClearance",
            "schema_version": "0.2.0",
            "profile_id": self.profile_id,
            "artifact_id": payload["clearance_id"],
            "tenant_id": self.tenant_id,
            "trust_domain": self.trust_domain,
            "issuer_id": self.issuer_id,
            "issuer_role": _REHT_ROLE,
            "issued_at": issued,
            "expires_at": expires,
            "payload": payload,
            "payload_digest": sha256_digest(payload),
            "canonicalization": "RACS-JCS-1",
            "signature": {"algorithm": "Ed25519", "key_id": self.key_id, "value": ""},
        }
        sign_artifact(artifact, self.private_key)
        return artifact


class GovernanceClearanceVerifier:
    """Fail-closed verification of signed GovernanceClearance artifacts."""

    def __init__(self, trust_registry: Dict[str, Dict[str, Any]]) -> None:
        # trust_registry: issuer_id -> registry entry (per TRUST_MODEL.md)
        self.trust_registry = trust_registry

    def verify(self, artifact: Dict[str, Any]) -> None:
        """Raise ``ClearanceError`` if the artifact is not authoritative.

        Implements the fail-closed rules from spec/TRUST_MODEL.md.
        """
        # 1. envelope schema
        try:
            jsonschema.validate(instance=artifact, schema=_ENVELOPE_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ClearanceError(f"envelope schema invalid: {exc.message}")
        # 2. payload schema
        try:
            jsonschema.validate(instance=artifact.get("payload", {}), schema=_CLEARANCE_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ClearanceError(f"clearance payload schema invalid: {exc.message}")
        # 3. payload digest
        if not verify_payload_digest(artifact):
            raise ClearanceError("payload digest mismatch")
        # 4. signature present + valid
        sig = artifact.get("signature", {})
        if not sig.get("value"):
            raise ClearanceError("missing signature")
        issuer_id = artifact.get("issuer_id")
        entry = self.trust_registry.get(issuer_id)
        if entry is None:
            raise ClearanceError(f"unknown issuer: {issuer_id}")
        if entry.get("revocation_status") == "REVOKED":
            raise ClearanceError(f"issuer revoked: {issuer_id}")
        # issuer must be registered as the REHT clearance issuer role
        if entry.get("issuer_role") != _REHT_ROLE:
            raise ClearanceError(
                f"registry issuer_role is not {_REHT_ROLE}: {issuer_id}"
            )
        # and authorized to issue this artifact type
        allowed = entry.get("allowed_artifact_types") or []
        if artifact.get("artifact_type") not in allowed:
            raise ClearanceError(
                f"issuer not allowed to issue {artifact.get('artifact_type')}: {issuer_id}"
            )
        if artifact.get("issuer_role") != _REHT_ROLE:
            raise ClearanceError("issuer_role is not REHT_CLEARANCE_ISSUER")
        if entry.get("tenant_scope") != artifact.get("tenant_id"):
            raise ClearanceError("tenant scope mismatch")
        if entry.get("trust_domain") != artifact.get("trust_domain"):
            raise ClearanceError("trust domain mismatch")
        # public key
        pub_pem = entry.get("public_key")
        if not pub_pem:
            raise ClearanceError("issuer missing public key")
        from racs_crypto import load_public_key

        public_key = load_public_key(pub_pem.encode("utf-8"))
        if not verify_artifact_signature(artifact, public_key):
            raise ClearanceError("signature invalid")
        # 5. expiry
        expires = artifact.get("expires_at")
        if expires:
            exp = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= exp:
                raise ClearanceError("clearance expired")


__all__ = [
    "ClearanceError",
    "GovernanceClearanceIssuer",
    "GovernanceClearanceVerifier",
]
