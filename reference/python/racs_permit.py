from __future__ import annotations
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
import jsonschema
from racs_canonical import sha256_digest, verify_payload_digest
from racs_crypto import Ed25519PrivateKey, load_public_key, sign_artifact, verify_artifact_signature
from racs_decision import RacsDecisionVerifier
_SCHEMA_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'spec')

def _load_schema(name: str) -> dict:
    with open(os.path.join(_SCHEMA_DIR, name), 'r', encoding='utf-8') as handle:
        return json.load(handle)
_ENVELOPE_SCHEMA = _load_schema('canonical-artifact-envelope.schema.json')
_PERMIT_SCHEMA = _load_schema('core-execution-permit.schema.json')
_COMMIT_TOKEN_SCHEMA = _load_schema('commit-token-v0.2.schema.json')
_CORE_ROLE = 'CORE_ENFORCER'

class PermitError(Exception):
    pass

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def _parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PermitError(f'{field} is required')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise PermitError(f'{field} is not a valid date-time') from exc
    if parsed.tzinfo is None:
        raise PermitError(f'{field} must include a timezone')
    return parsed.astimezone(timezone.utc)

def _required(payload: Dict[str, Any], field: str) -> Any:
    value = payload.get(field)
    if value is None or value == '':
        raise PermitError(f'artifact missing required binding: {field}')
    return value

def _bounded_expiry(*candidates: datetime) -> datetime:
    expiry = min(candidates)
    if expiry <= _now():
        raise PermitError('upstream authorization is expired')
    return expiry

class CoreExecutionPermitVerifier:

    def __init__(self, trust_registry: Dict[str, Dict[str, Any]]) -> None:
        self.trust_registry = trust_registry

    def verify(self, artifact: Dict[str, Any]) -> None:
        try:
            jsonschema.validate(instance=artifact, schema=_ENVELOPE_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise PermitError(f'permit envelope schema invalid: {exc.message}') from exc
        if artifact.get('artifact_type') != 'CoreExecutionPermit':
            raise PermitError('artifact_type is not CoreExecutionPermit')
        if artifact.get('issuer_role') != _CORE_ROLE:
            raise PermitError('issuer_role is not CORE_ENFORCER')
        payload = artifact.get('payload', {})
        try:
            jsonschema.validate(instance=payload, schema=_PERMIT_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise PermitError(f'permit payload schema invalid: {exc.message}') from exc
        if not verify_payload_digest(artifact):
            raise PermitError('permit payload digest mismatch')
        if artifact.get('tenant_id') != payload.get('tenant_id'):
            raise PermitError('permit tenant binding mismatch')
        if artifact.get('artifact_id') != f"permit-{payload.get('execution_id')}":
            raise PermitError('permit artifact_id binding mismatch')
        issuer_id = artifact.get('issuer_id')
        entry = self.trust_registry.get(issuer_id)
        if entry is None:
            raise PermitError(f'unknown permit issuer: {issuer_id}')
        if entry.get('revocation_status') != 'ACTIVE':
            raise PermitError(f'permit issuer is not active: {issuer_id}')
        if entry.get('issuer_role') != _CORE_ROLE:
            raise PermitError('registry issuer_role is not CORE_ENFORCER')
        if 'CoreExecutionPermit' not in (entry.get('allowed_artifact_types') or []):
            raise PermitError('issuer is not allowed to issue CoreExecutionPermit')
        if entry.get('tenant_scope') != artifact.get('tenant_id'):
            raise PermitError('permit issuer tenant scope mismatch')
        if entry.get('trust_domain') != artifact.get('trust_domain'):
            raise PermitError('permit issuer trust domain mismatch')
        if entry.get('key_id') != artifact.get('signature', {}).get('key_id'):
            raise PermitError('permit signature key_id mismatch')
        public_key_pem = entry.get('public_key')
        if not public_key_pem:
            raise PermitError('permit issuer missing public key')
        public_key = load_public_key(public_key_pem.encode('utf-8'))
        if not verify_artifact_signature(artifact, public_key):
            raise PermitError('permit signature invalid')
        now = _now()
        issued_at = _parse_utc(artifact.get('issued_at'), 'permit.issued_at')
        envelope_expiry = _parse_utc(artifact.get('expires_at'), 'permit.expires_at')
        valid_from = _parse_utc(payload.get('valid_from'), 'permit.valid_from')
        payload_expiry = _parse_utc(payload.get('valid_until'), 'permit.valid_until')
        if issued_at > now or valid_from > now:
            raise PermitError('permit is not yet valid')
        if now >= envelope_expiry or now >= payload_expiry:
            raise PermitError('permit expired')
        if envelope_expiry > payload_expiry:
            raise PermitError('permit envelope outlives payload authorization')

class CoreExecutionPermitBuilder:

    def __init__(self, *, issuer_id: str, tenant_id: str, trust_domain: str, private_key: Ed25519PrivateKey, key_id: str, decision_verifier: RacsDecisionVerifier, profile_id: str='racs-platform-0.2', valid_for_seconds: int=60) -> None:
        if valid_for_seconds <= 0:
            raise PermitError('valid_for_seconds must be positive')
        self.issuer_id = issuer_id
        self.tenant_id = tenant_id
        self.trust_domain = trust_domain
        self.private_key = private_key
        self.key_id = key_id
        self.decision_verifier = decision_verifier
        self.profile_id = profile_id
        self.valid_for_seconds = valid_for_seconds

    def build(self, *, clearance_artifact: Dict[str, Any], racs_decision_artifact: Dict[str, Any], execution_id: str, target_digest: str, payload_digest: str, reservation_id: str) -> Dict[str, Any]:
        try:
            decision_payload = self.decision_verifier.verify(racs_decision_artifact, clearance_artifact)
        except Exception as exc:
            raise PermitError(f'RACS decision verification failed: {exc}') from exc
        clearance = clearance_artifact['payload']
        if clearance_artifact.get('tenant_id') != self.tenant_id:
            raise PermitError('clearance tenant does not match permit issuer')
        if clearance_artifact.get('trust_domain') != self.trust_domain:
            raise PermitError('clearance trust domain does not match permit issuer')
        if racs_decision_artifact.get('tenant_id') != self.tenant_id:
            raise PermitError('RACS decision tenant does not match permit issuer')
        if racs_decision_artifact.get('trust_domain') != self.trust_domain:
            raise PermitError('RACS decision trust domain does not match permit issuer')
        if decision_payload.get('decision') not in {'ALLOW', 'MODIFY'}:
            raise PermitError('RACS decision cannot authorize execution')
        bound_target = _required(decision_payload, 'target_digest')
        bound_payload = _required(decision_payload, 'payload_digest')
        if target_digest != bound_target:
            raise PermitError('target digest does not match RACS decision')
        if payload_digest != bound_payload:
            raise PermitError('payload digest does not match RACS decision')
        now = _now()
        permit_expiry = _bounded_expiry(now + timedelta(seconds=self.valid_for_seconds), _parse_utc(clearance_artifact.get('expires_at'), 'clearance.expires_at'), _parse_utc(clearance.get('valid_until'), 'clearance.valid_until'), _parse_utc(racs_decision_artifact.get('expires_at'), 'racs_decision.expires_at'), _parse_utc(decision_payload.get('valid_until'), 'racs_decision.valid_until'))
        payload: Dict[str, Any] = {'execution_id': execution_id, 'action_id': _required(decision_payload, 'action_id'), 'tenant_id': _required(decision_payload, 'tenant_id'), 'clearance_id': _required(decision_payload, 'clearance_id'), 'clearance_digest': _required(decision_payload, 'clearance_digest'), 'racs_decision_id': _required(decision_payload, 'racs_decision_id'), 'racs_decision_digest': racs_decision_artifact['payload_digest'], 'decision': _required(decision_payload, 'decision'), 'action_envelope_digest': _required(decision_payload, 'action_envelope_digest'), 'connector_id': _required(decision_payload, 'connector_id'), 'capability': _required(decision_payload, 'capability'), 'target_digest': bound_target, 'payload_digest': bound_payload, 'purpose_digest': _required(clearance, 'purpose_digest'), 'authority_digest': _required(clearance, 'authority_digest'), 'policy_digest': _required(clearance, 'policy_digest'), 'evidence_digest': _required(clearance, 'evidence_digest'), 'state_digest': _required(clearance, 'state_digest'), 'valid_from': _format_utc(now), 'valid_until': _format_utc(permit_expiry), 'replay_nonce': _required(clearance, 'replay_nonce'), 'idempotency_key': _required(clearance, 'idempotency_key'), 'reservation_id': reservation_id}
        if decision_payload.get('constraints') is not None:
            payload['constraints'] = dict(decision_payload['constraints'])
        try:
            jsonschema.validate(instance=payload, schema=_PERMIT_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise PermitError(f'permit payload schema invalid: {exc.message}') from exc
        artifact = {'artifact_type': 'CoreExecutionPermit', 'schema_version': '0.2.0', 'profile_id': self.profile_id, 'artifact_id': f'permit-{execution_id}', 'tenant_id': self.tenant_id, 'trust_domain': self.trust_domain, 'issuer_id': self.issuer_id, 'issuer_role': _CORE_ROLE, 'issued_at': _format_utc(now), 'expires_at': _format_utc(permit_expiry), 'payload': payload, 'payload_digest': sha256_digest(payload), 'canonicalization': 'RACS-JCS-1', 'signature': {'algorithm': 'Ed25519', 'key_id': self.key_id, 'value': ''}}
        sign_artifact(artifact, self.private_key)
        return artifact

class CommitTokenIssuer:

    def __init__(self, *, issuer_id: str, tenant_id: str, trust_domain: str, private_key: Ed25519PrivateKey, key_id: str, trust_registry: Dict[str, Dict[str, Any]], profile_id: str='racs-platform-0.2', valid_for_seconds: int=30) -> None:
        if valid_for_seconds <= 0:
            raise PermitError('valid_for_seconds must be positive')
        self.issuer_id = issuer_id
        self.tenant_id = tenant_id
        self.trust_domain = trust_domain
        self.private_key = private_key
        self.key_id = key_id
        self.permit_verifier = CoreExecutionPermitVerifier(trust_registry)
        self.profile_id = profile_id
        self.valid_for_seconds = valid_for_seconds

    def issue(self, permit: Dict[str, Any]) -> Dict[str, Any]:
        self.permit_verifier.verify(permit)
        permit_payload = permit['payload']
        if permit.get('tenant_id') != self.tenant_id:
            raise PermitError('permit tenant does not match token issuer')
        if permit.get('trust_domain') != self.trust_domain:
            raise PermitError('permit trust domain does not match token issuer')
        now = _now()
        token_expiry = _bounded_expiry(now + timedelta(seconds=self.valid_for_seconds), _parse_utc(permit.get('expires_at'), 'permit.expires_at'), _parse_utc(permit_payload.get('valid_until'), 'permit.valid_until'))
        payload: Dict[str, Any] = {'commit_token_id': f"token-{permit_payload['execution_id']}", 'execution_id': permit_payload['execution_id'], 'tenant_id': permit_payload['tenant_id'], 'action_id': permit_payload['action_id'], 'action_envelope_digest': permit_payload['action_envelope_digest'], 'clearance_id': permit_payload['clearance_id'], 'clearance_digest': permit_payload['clearance_digest'], 'racs_decision_id': permit_payload['racs_decision_id'], 'racs_decision_digest': permit_payload['racs_decision_digest'], 'decision': permit_payload['decision'], 'execution_permit_id': permit['artifact_id'], 'execution_permit_digest': permit['payload_digest'], 'connector_id': permit_payload['connector_id'], 'capability': permit_payload['capability'], 'target_digest': permit_payload['target_digest'], 'payload_digest': permit_payload['payload_digest'], 'reservation_id': permit_payload['reservation_id'], 'issued_at': _format_utc(now), 'valid_until': _format_utc(token_expiry), 'single_use': True, 'consumption_registry_ref': f"consumption-{permit_payload['execution_id']}"}
        if permit_payload.get('constraints') is not None:
            payload['constraints'] = dict(permit_payload['constraints'])
        try:
            jsonschema.validate(instance=payload, schema=_COMMIT_TOKEN_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise PermitError(f'commit token payload schema invalid: {exc.message}') from exc
        artifact = {'artifact_type': 'CommitToken', 'schema_version': '0.2.0', 'profile_id': self.profile_id, 'artifact_id': payload['commit_token_id'], 'tenant_id': self.tenant_id, 'trust_domain': self.trust_domain, 'issuer_id': self.issuer_id, 'issuer_role': _CORE_ROLE, 'issued_at': _format_utc(now), 'expires_at': _format_utc(token_expiry), 'payload': payload, 'payload_digest': sha256_digest(payload), 'canonicalization': 'RACS-JCS-1', 'signature': {'algorithm': 'Ed25519', 'key_id': self.key_id, 'value': ''}}
        sign_artifact(artifact, self.private_key)
        return artifact
__all__ = ['PermitError', 'CoreExecutionPermitVerifier', 'CoreExecutionPermitBuilder', 'CommitTokenIssuer']
