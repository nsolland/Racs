"""P0-B conformance: signed GovernanceClearance issuance + fail-closed verify."""

import os

import pytest

from racs_canonical import sha256_digest
from racs_crypto import generate_keypair, load_private_key, load_public_key
from racs_clearance import (
    ClearanceError,
    GovernanceClearanceIssuer,
    GovernanceClearanceVerifier,
)

_ISSUER_ID = "reht-clearance-issuer-1"
_TENANT = "tenant-acme"
_DOMAIN = "valo-trust"


def _build_payload() -> dict:
    digest = "sha256:" + "a" * 64
    return {
        "clearance_id": "clr-1",
        "action_id": "act-1",
        "action_envelope_digest": digest,
        "tenant_id": _TENANT,
        "decision": "ALLOW",
        "admissibility_state": "ADMISSIBLE",
        "authority_digest": digest,
        "delegation_chain_digest": digest,
        "policy_digest": digest,
        "evidence_digest": digest,
        "purpose_digest": digest,
        "state_digest": digest,
        "target_digest": digest,
        "payload_digest": digest,
        "connector_id": "connector-email",
        "capability": "send_email",
        "consequence_class": "HIGH",
        "reversibility": "COMPENSATABLE",
        "valid_from": "2026-07-14T00:00:00Z",
        "valid_until": "2026-07-14T01:00:00Z",
        "replay_nonce": "nonce-" + "b" * 16,
        "idempotency_key": "idem-" + "c" * 8,
        "revocation_registry_ref": "rev-reg-1",
        "evaluator_refs": ["vaig-eval-1", "reht-1"],
    }


@pytest.fixture()
def keypair():
    priv_pem, pub_pem = generate_keypair()
    return priv_pem, pub_pem


@pytest.fixture()
def issuer(keypair):
    priv_pem, _ = keypair
    return GovernanceClearanceIssuer(
        issuer_id=_ISSUER_ID,
        tenant_id=_TENANT,
        trust_domain=_DOMAIN,
        private_key=load_private_key(priv_pem),
        key_id="key-1",
    )


@pytest.fixture()
def registry(keypair):
    _, pub_pem = keypair
    return {
        _ISSUER_ID: {
            "issuer_id": _ISSUER_ID,
            "issuer_role": "REHT_CLEARANCE_ISSUER",
            "tenant_scope": _TENANT,
            "trust_domain": _DOMAIN,
            "allowed_artifact_types": ["GovernanceClearance"],
            "key_id": "key-1",
            "algorithm": "Ed25519",
            "public_key": pub_pem.decode("utf-8"),
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "revocation_status": "ACTIVE",
            "registry_version": "1",
        }
    }


def test_step1_issued_clearance_verifies(issuer, registry):
    artifact = issuer.issue(_build_payload())
    # signed envelope must carry a non-empty signature
    assert artifact["signature"]["value"]
    GovernanceClearanceVerifier(registry).verify(artifact)  # must not raise


def test_step2_locally_constructed_clearance_rejected(issuer, registry):
    # attacker builds the same payload but signs nothing / unknown issuer
    payload = _build_payload()
    fake = {
        "artifact_type": "GovernanceClearance",
        "schema_version": "0.2.0",
        "profile_id": "racs-platform-0.2",
        "artifact_id": payload["clearance_id"],
        "tenant_id": _TENANT,
        "trust_domain": _DOMAIN,
        "issuer_id": "attacker-self-signed",
        "issuer_role": "REHT_CLEARANCE_ISSUER",
        "issued_at": "2026-07-14T00:00:00Z",
        "expires_at": "2026-07-14T01:00:00Z",
        "payload": payload,
        "payload_digest": sha256_digest(payload),
        "canonicalization": "RACS-JCS-1",
        "signature": {"algorithm": "Ed25519", "key_id": "key-x", "value": ""},
    }
    with pytest.raises(ClearanceError):
        GovernanceClearanceVerifier(registry).verify(fake)


def test_step3_unknown_issuer_rejected(issuer, registry):
    artifact = issuer.issue(_build_payload())
    artifact["issuer_id"] = "unknown-issuer"
    with pytest.raises(ClearanceError):
        GovernanceClearanceVerifier(registry).verify(artifact)


def test_step4_expired_clearance_rejected(issuer, registry):
    artifact = issuer.issue(_build_payload())
    artifact["expires_at"] = "2020-01-01T00:00:00Z"
    with pytest.raises(ClearanceError):
        GovernanceClearanceVerifier(registry).verify(artifact)


def test_step5_tampered_payload_rejected(issuer, registry):
    artifact = issuer.issue(_build_payload())
    # mutate payload after signing -> digest mismatch
    artifact["payload"]["decision"] = "MODIFY"
    with pytest.raises(ClearanceError):
        GovernanceClearanceVerifier(registry).verify(artifact)
