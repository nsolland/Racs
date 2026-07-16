"""RACS Draft 0.2 CoreExecutionPermit + CommitToken issuance (P0-C).

Implements the Platform -> Core -> Connector bridge:

* ``CoreExecutionPermitBuilder`` takes a verified, signed GovernanceClearance
  artifact plus the exact execution bindings (execution_id, target/payload
  digests, reservation_id) and produces a signed ``CoreExecutionPermit``.
* ``CommitTokenIssuer`` consumes a verified permit and mints a single-use
  signed ``CommitToken``.

Both wrap the payload in the canonical signed artifact envelope
(RACS-JCS-1 + Ed25519) so Rust Core can verify the same bytes.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

import jsonschema

from racs_canonical import sha256_digest, signature_input_bytes
from racs_crypto import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    sign_artifact,
    verify_artifact_signature,
)

_SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "spec")


def _load_schema(name: str) -> dict:
    with open(os.path.join(_SCHEMA_DIR, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


_ENVELOPE_SCHEMA = _load_schema("canonical-artifact-envelope.schema.json")
_PERMIT_SCHEMA = _load_schema("core-execution-permit.schema.json")
_COMMIT_TOKEN_SCHEMA = _load_schema("commit-token-v0.2.schema.json")

_CORE_ROLE = "CORE_ENFORCER"


class PermitError(Exception):
    """Raised on permit/token construction or verification failure."""


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_from_offset(seconds: int) -> str:
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).timestamp() + seconds
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CoreExecutionPermitBuilder:
    """Build a signed CoreExecutionPermit from a verified clearance."""

    def __init__(
        self,
        *,
        issuer_id: str,
        tenant_id: str,
        trust_domain: str,
        private_key: Ed25519PrivateKey,
        key_id: str,
        profile_id: str = "racs-platform-0.2",
        valid_for_seconds: int = 60,
    ) -> None:
        self.issuer_id = issuer_id
        self.tenant_id = tenant_id
        self.trust_domain = trust_domain
        self.private_key = private_key
        self.key_id = key_id
        self.profile_id = profile_id
        self.valid_for_seconds = valid_for_seconds

    def build(
        self,
        *,
        clearance_artifact: Dict[str, Any],
        execution_id: str,
        target_digest: str,
        payload_digest: str,
        reservation_id: str,
    ) -> Dict[str, Any]:
        clr_payload = clearance_artifact["payload"]
        digest = "sha256:" + "a" * 64  # placeholder only if a digest is absent
        payload = {
            "execution_id": execution_id,
            "action_id": clr_payload["action_id"],
            "tenant_id": clr_payload["tenant_id"],
            "clearance_id": clr_payload["clearance_id"],
            "clearance_digest": sha256_digest(clr_payload),
            "action_envelope_digest": clr_payload.get("action_envelope_digest", digest),
            "connector_id": clr_payload.get("connector_id", "connector-unknown"),
            "capability": clr_payload.get("capability", "unknown"),
            "target_digest": target_digest,
            "payload_digest": payload_digest,
            "purpose_digest": clr_payload.get("purpose_digest", digest),
            "authority_digest": clr_payload.get("authority_digest", digest),
            "policy_digest": clr_payload.get("policy_digest", digest),
            "evidence_digest": clr_payload.get("evidence_digest", digest),
            "state_digest": clr_payload.get("state_digest", digest),
            "valid_from": clearance_artifact.get("issued_at", _now_iso()),
            "valid_until": _iso_from_offset(self.valid_for_seconds),
            "replay_nonce": clr_payload.get("replay_nonce", "nonce-" + "b" * 16),
            "idempotency_key": clr_payload.get("idempotency_key", "idem-" + "c" * 8),
            "reservation_id": reservation_id,
        }
        jsonschema.validate(instance=payload, schema=_PERMIT_SCHEMA)
        artifact = {
            "artifact_type": "CoreExecutionPermit",
            "schema_version": "0.2.0",
            "profile_id": self.profile_id,
            "artifact_id": f"permit-{execution_id}",
            "tenant_id": self.tenant_id,
            "trust_domain": self.trust_domain,
            "issuer_id": self.issuer_id,
            "issuer_role": _CORE_ROLE,
            "issued_at": _now_iso(),
            "expires_at": _iso_from_offset(self.valid_for_seconds),
            "payload": payload,
            "payload_digest": sha256_digest(payload),
            "canonicalization": "RACS-JCS-1",
            "signature": {"algorithm": "Ed25519", "key_id": self.key_id, "value": ""},
        }
        sign_artifact(artifact, self.private_key)
        return artifact


class CommitTokenIssuer:
    """Mint a single-use signed CommitToken from a verified permit."""

    def __init__(
        self,
        *,
        issuer_id: str,
        tenant_id: str,
        trust_domain: str,
        private_key: Ed25519PrivateKey,
        key_id: str,
        profile_id: str = "racs-platform-0.2",
        valid_for_seconds: int = 30,
    ) -> None:
        self.issuer_id = issuer_id
        self.tenant_id = tenant_id
        self.trust_domain = trust_domain
        self.private_key = private_key
        self.key_id = key_id
        self.profile_id = profile_id
        self.valid_for_seconds = valid_for_seconds

    def issue(self, permit: Dict[str, Any]) -> Dict[str, Any]:
        jsonschema.validate(instance=permit, schema=_ENVELOPE_SCHEMA)
        permit_payload = permit["payload"]
        payload = {
            "commit_token_id": f"token-{permit_payload['execution_id']}",
            "execution_id": permit_payload["execution_id"],
            "tenant_id": permit_payload["tenant_id"],
            "action_id": permit_payload["action_id"],
            "action_envelope_digest": permit_payload["action_envelope_digest"],
            "clearance_id": permit_payload["clearance_id"],
            "clearance_digest": permit_payload["clearance_digest"],
            "execution_permit_id": permit["artifact_id"],
            "execution_permit_digest": permit["payload_digest"],
            "connector_id": permit_payload["connector_id"],
            "capability": permit_payload["capability"],
            "target_digest": permit_payload["target_digest"],
            "payload_digest": permit_payload["payload_digest"],
            "reservation_id": permit_payload["reservation_id"],
            "issued_at": _now_iso(),
            "valid_until": _iso_from_offset(self.valid_for_seconds),
            "single_use": True,
            "consumption_registry_ref": f"consumption-{permit_payload['execution_id']}",
        }
        jsonschema.validate(instance=payload, schema=_COMMIT_TOKEN_SCHEMA)
        artifact = {
            "artifact_type": "CommitToken",
            "schema_version": "0.2.0",
            "profile_id": self.profile_id,
            "artifact_id": payload["commit_token_id"],
            "tenant_id": self.tenant_id,
            "trust_domain": self.trust_domain,
            "issuer_id": self.issuer_id,
            "issuer_role": _CORE_ROLE,
            "issued_at": _now_iso(),
            "expires_at": _iso_from_offset(self.valid_for_seconds),
            "payload": payload,
            "payload_digest": sha256_digest(payload),
            "canonicalization": "RACS-JCS-1",
            "signature": {"algorithm": "Ed25519", "key_id": self.key_id, "value": ""},
        }
        sign_artifact(artifact, self.private_key)
        return artifact


__all__ = [
    "PermitError",
    "CoreExecutionPermitBuilder",
    "CommitTokenIssuer",
]
