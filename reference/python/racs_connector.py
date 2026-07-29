"""Bounded connector enforcement for RACS Draft 0.2.

A connector verifies a signed CommitToken, checks exact request bindings,
atomically consumes the token before invoking the provider, and emits a signed
ExecutionReceipt. The in-memory registry is a reference implementation; a
production registry must provide equivalent durable compare-and-set semantics.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Callable, Dict, Mapping, Optional

import jsonschema

from racs_canonical import sha256_digest, verify_payload_digest
from racs_crypto import (
    Ed25519PrivateKey,
    load_public_key,
    sign_artifact,
    verify_artifact_signature,
)

_SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "spec")


def _load_schema(name: str) -> dict:
    with open(os.path.join(_SCHEMA_DIR, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


_ENVELOPE_SCHEMA = _load_schema("canonical-artifact-envelope.schema.json")
_COMMIT_TOKEN_SCHEMA = _load_schema("commit-token-v0.2.schema.json")
_EXECUTION_RECEIPT_SCHEMA = _load_schema("execution-receipt-v0.2.schema.json")

_CORE_ROLE = "CORE_ENFORCER"
_CONNECTOR_ROLE = "BOUNDED_CONNECTOR"
GENESIS_RECEIPT_HASH = "sha256:" + "0" * 64


class ConnectorError(Exception):
    """Base class for pre-side-effect connector enforcement failures."""


class TokenAlreadyConsumed(ConnectorError):
    """Raised when a CommitToken has already crossed the commit boundary."""


@dataclass(frozen=True)
class ConsumptionRecord:
    registry_ref: str
    commit_token_id: str
    commit_token_digest: str
    execution_id: str
    consumed_at: str


@dataclass(frozen=True)
class ProviderResult:
    provider_reference: str
    response: Any
    technical_outcome: str = "SUCCEEDED"
    reversal_status: str = "NOT_APPLICABLE"


class CommitTokenVerifier:
    """Fail-closed verification of a signed, current CommitToken."""

    def __init__(self, trust_registry: Dict[str, Dict[str, Any]]) -> None:
        self.trust_registry = trust_registry

    @staticmethod
    def _parse_utc(value: Any, field: str) -> datetime:
        if not isinstance(value, str) or not value:
            raise ConnectorError(f"{field} is required")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ConnectorError(f"{field} is not a valid date-time") from exc
        if parsed.tzinfo is None:
            raise ConnectorError(f"{field} must include a timezone")
        return parsed.astimezone(timezone.utc)

    def verify(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        try:
            jsonschema.validate(instance=artifact, schema=_ENVELOPE_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ConnectorError(f"token envelope schema invalid: {exc.message}") from exc

        if artifact.get("artifact_type") != "CommitToken":
            raise ConnectorError("artifact_type is not CommitToken")
        if artifact.get("issuer_role") != _CORE_ROLE:
            raise ConnectorError("token issuer_role is not CORE_ENFORCER")

        payload = artifact.get("payload", {})
        try:
            jsonschema.validate(instance=payload, schema=_COMMIT_TOKEN_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ConnectorError(f"token payload schema invalid: {exc.message}") from exc

        if not verify_payload_digest(artifact):
            raise ConnectorError("token payload digest mismatch")
        if artifact.get("artifact_id") != payload.get("commit_token_id"):
            raise ConnectorError("token artifact_id binding mismatch")
        if artifact.get("tenant_id") != payload.get("tenant_id"):
            raise ConnectorError("token tenant binding mismatch")
        if payload.get("single_use") is not True:
            raise ConnectorError("token is not single-use")
        if artifact.get("issued_at") != payload.get("issued_at"):
            raise ConnectorError("token issued_at binding mismatch")
        if artifact.get("expires_at") != payload.get("valid_until"):
            raise ConnectorError("token expiry binding mismatch")

        issuer_id = artifact.get("issuer_id")
        entry = self.trust_registry.get(issuer_id)
        if entry is None:
            raise ConnectorError(f"unknown token issuer: {issuer_id}")
        if entry.get("revocation_status") != "ACTIVE":
            raise ConnectorError(f"token issuer is not active: {issuer_id}")
        if entry.get("issuer_role") != _CORE_ROLE:
            raise ConnectorError("registry token issuer_role is not CORE_ENFORCER")
        if "CommitToken" not in (entry.get("allowed_artifact_types") or []):
            raise ConnectorError("issuer is not allowed to issue CommitToken")
        if entry.get("tenant_scope") != artifact.get("tenant_id"):
            raise ConnectorError("token issuer tenant scope mismatch")
        if entry.get("trust_domain") != artifact.get("trust_domain"):
            raise ConnectorError("token issuer trust domain mismatch")
        if entry.get("key_id") != artifact.get("signature", {}).get("key_id"):
            raise ConnectorError("token signature key_id mismatch")

        pub_pem = entry.get("public_key")
        if not pub_pem:
            raise ConnectorError("token issuer missing public key")
        public_key = load_public_key(pub_pem.encode("utf-8"))
        if not verify_artifact_signature(artifact, public_key):
            raise ConnectorError("token signature invalid")

        now = datetime.now(timezone.utc)
        issued_at = self._parse_utc(artifact.get("issued_at"), "token.issued_at")
        expires_at = self._parse_utc(artifact.get("expires_at"), "token.expires_at")
        if issued_at > now:
            raise ConnectorError("token is not yet valid")
        if now >= expires_at:
            raise ConnectorError("token expired")
        return payload


class InMemoryConsumptionRegistry:
    """Atomic process-local reference registry for single-use token consumption."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._records: Dict[tuple[str, str], ConsumptionRecord] = {}

    def consume(
        self,
        *,
        registry_ref: str,
        commit_token_id: str,
        commit_token_digest: str,
        execution_id: str,
        consumed_at: str,
    ) -> ConsumptionRecord:
        if not registry_ref:
            raise ConnectorError("consumption_registry_ref is required")
        key = (registry_ref, commit_token_id)
        with self._lock:
            if key in self._records:
                raise TokenAlreadyConsumed(f"commit token already consumed: {commit_token_id}")
            record = ConsumptionRecord(
                registry_ref=registry_ref,
                commit_token_id=commit_token_id,
                commit_token_digest=commit_token_digest,
                execution_id=execution_id,
                consumed_at=consumed_at,
            )
            self._records[key] = record
            return record

    def get(self, registry_ref: str, commit_token_id: str) -> Optional[ConsumptionRecord]:
        with self._lock:
            return self._records.get((registry_ref, commit_token_id))


class BoundedConnector:
    """Verify, atomically consume, execute once, and receipt the attempt."""

    def __init__(
        self,
        *,
        connector_id: str,
        capability: str,
        issuer_id: str,
        tenant_id: str,
        trust_domain: str,
        private_key: Ed25519PrivateKey,
        key_id: str,
        token_verifier: CommitTokenVerifier,
        consumption_registry: InMemoryConsumptionRegistry,
        profile_id: str = "racs-platform-0.2",
    ) -> None:
        self.connector_id = connector_id
        self.capability = capability
        self.issuer_id = issuer_id
        self.tenant_id = tenant_id
        self.trust_domain = trust_domain
        self.private_key = private_key
        self.key_id = key_id
        self.token_verifier = token_verifier
        self.consumption_registry = consumption_registry
        self.profile_id = profile_id

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def execute(
        self,
        *,
        commit_token: Dict[str, Any],
        target: Any,
        request_payload: Any,
        provider: Callable[[Any, Any], ProviderResult],
        previous_receipt_hash: str = GENESIS_RECEIPT_HASH,
    ) -> Dict[str, Any]:
        token_payload = self.token_verifier.verify(commit_token)

        if commit_token.get("tenant_id") != self.tenant_id:
            raise ConnectorError("token tenant does not match connector")
        if commit_token.get("trust_domain") != self.trust_domain:
            raise ConnectorError("token trust domain does not match connector")
        if token_payload.get("connector_id") != self.connector_id:
            raise ConnectorError("token connector_id mismatch")
        if token_payload.get("capability") != self.capability:
            raise ConnectorError("token capability mismatch")

        target_digest = sha256_digest(target)
        payload_digest = sha256_digest(request_payload)
        if target_digest != token_payload.get("target_digest"):
            raise ConnectorError("target digest does not match token")
        if payload_digest != token_payload.get("payload_digest"):
            raise ConnectorError("payload digest does not match token")

        started_at = self._now_iso()
        self.consumption_registry.consume(
            registry_ref=token_payload["consumption_registry_ref"],
            commit_token_id=token_payload["commit_token_id"],
            commit_token_digest=commit_token["payload_digest"],
            execution_id=token_payload["execution_id"],
            consumed_at=started_at,
        )

        error_class: Optional[str] = None
        try:
            result = provider(target, request_payload)
            if not isinstance(result, ProviderResult):
                raise TypeError("provider must return ProviderResult")
            if not result.provider_reference:
                raise ValueError("provider_reference is required")
            if result.technical_outcome not in {
                "SIMULATED",
                "SUCCEEDED",
                "INDETERMINATE",
                "REVERSED",
            }:
                raise ValueError("unsupported provider technical_outcome")
            provider_reference = result.provider_reference
            response_digest = sha256_digest(result.response)
            technical_outcome = result.technical_outcome
            reversal_status = result.reversal_status
        except Exception as exc:
            error_class = type(exc).__name__
            provider_reference = f"provider-error:{error_class}"
            response_digest = sha256_digest({"error_class": error_class})
            technical_outcome = "FAILED"
            reversal_status = "NOT_REVERSED"

        completed_at = self._now_iso()
        receipt_payload: Dict[str, Any] = {
            "execution_receipt_id": f"receipt-{token_payload['execution_id']}",
            "execution_id": token_payload["execution_id"],
            "tenant_id": token_payload["tenant_id"],
            "action_id": token_payload["action_id"],
            "action_envelope_digest": token_payload["action_envelope_digest"],
            "clearance_id": token_payload["clearance_id"],
            "clearance_digest": token_payload["clearance_digest"],
            "commit_token_id": token_payload["commit_token_id"],
            "commit_token_digest": commit_token["payload_digest"],
            "connector_id": token_payload["connector_id"],
            "capability": token_payload["capability"],
            "target_digest": token_payload["target_digest"],
            "payload_digest": token_payload["payload_digest"],
            "started_at": started_at,
            "completed_at": completed_at,
            "technical_outcome": technical_outcome,
            "provider_reference": provider_reference,
            "response_digest": response_digest,
            "reversal_status": reversal_status,
            "previous_receipt_hash": previous_receipt_hash,
        }
        if error_class is not None:
            receipt_payload["error_class"] = error_class

        try:
            jsonschema.validate(instance=receipt_payload, schema=_EXECUTION_RECEIPT_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ConnectorError(f"execution receipt schema invalid: {exc.message}") from exc

        receipt = {
            "artifact_type": "ExecutionReceipt",
            "schema_version": "0.2.0",
            "profile_id": self.profile_id,
            "artifact_id": receipt_payload["execution_receipt_id"],
            "tenant_id": self.tenant_id,
            "trust_domain": self.trust_domain,
            "issuer_id": self.issuer_id,
            "issuer_role": _CONNECTOR_ROLE,
            "issued_at": completed_at,
            "expires_at": completed_at,
            "payload": receipt_payload,
            "payload_digest": sha256_digest(receipt_payload),
            "canonicalization": "RACS-JCS-1",
            "signature": {"algorithm": "Ed25519", "key_id": self.key_id, "value": ""},
        }
        sign_artifact(receipt, self.private_key)
        return receipt


__all__ = [
    "GENESIS_RECEIPT_HASH",
    "ConnectorError",
    "TokenAlreadyConsumed",
    "ConsumptionRecord",
    "ProviderResult",
    "CommitTokenVerifier",
    "InMemoryConsumptionRegistry",
    "BoundedConnector",
]
