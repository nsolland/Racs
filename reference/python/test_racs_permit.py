"""P0-C conformance: Platform -> Core -> Connector signed-permit/token chain."""

import pytest

from racs_canonical import sha256_digest
from racs_crypto import generate_keypair, load_private_key, load_public_key
from racs_clearance import GovernanceClearanceIssuer
from racs_permit import (
    CoreExecutionPermitBuilder,
    CommitTokenIssuer,
)


def _digest():
    return "sha256:" + "a" * 64


def _clearance_payload():
    d = _digest()
    return {
        "clearance_id": "clr-1",
        "action_id": "act-1",
        "action_envelope_digest": d,
        "tenant_id": "tenant-acme",
        "decision": "ALLOW",
        "admissibility_state": "ADMISSIBLE",
        "authority_digest": d,
        "delegation_chain_digest": d,
        "policy_digest": d,
        "evidence_digest": d,
        "purpose_digest": d,
        "state_digest": d,
        "target_digest": d,
        "payload_digest": d,
        "connector_id": "connector-bank",
        "capability": "transfer_funds",
        "consequence_class": "HIGH",
        "reversibility": "IRREVERSIBLE",
        "valid_from": "2026-07-14T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "replay_nonce": "nonce-" + "b" * 16,
        "idempotency_key": "idem-" + "c" * 8,
        "revocation_registry_ref": "rev-reg-1",
        "evaluator_refs": ["vaig-1", "reht-1"],
    }


@pytest.fixture()
def keys():
    reht_priv, reht_pub = generate_keypair()
    core_priv, core_pub = generate_keypair()
    return {
        "reht": (load_private_key(reht_priv), reht_pub.decode()),
        "core": (load_private_key(core_priv), core_pub.decode()),
    }


@pytest.fixture()
def registry(keys):
    return {
        "reht-1": {
            "issuer_id": "reht-1",
            "issuer_role": "REHT_CLEARANCE_ISSUER",
            "tenant_scope": "tenant-acme",
            "trust_domain": "valo-trust",
            "allowed_artifact_types": ["GovernanceClearance"],
            "key_id": "key-reht",
            "algorithm": "Ed25519",
            "public_key": keys["reht"][1],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "revocation_status": "ACTIVE",
            "registry_version": "1",
        },
        "core-1": {
            "issuer_id": "core-1",
            "issuer_role": "CORE_ENFORCER",
            "tenant_scope": "tenant-acme",
            "trust_domain": "valo-trust",
            "allowed_artifact_types": ["CoreExecutionPermit", "CommitToken"],
            "key_id": "key-core",
            "algorithm": "Ed25519",
            "public_key": keys["core"][1],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "revocation_status": "ACTIVE",
            "registry_version": "1",
        },
    }


def _connector_accept(token, core_pub_pem):
    """Connector-side check: a real bounded connector requires a valid token."""
    from racs_crypto import load_public_key, verify_artifact_signature

    pub = load_public_key(core_pub_pem.encode())
    if not verify_artifact_signature(token, pub):
        return False
    if token.get("artifact_type") != "CommitToken":
        return False
    if token.get("payload", {}).get("single_use") is not True:
        return False
    return True


def test_step1_full_chain_issues_token(keys, registry):
    reht_priv, _ = keys["reht"]
    core_priv, core_pub = keys["core"]
    reht = GovernanceClearanceIssuer(
        issuer_id="reht-1", tenant_id="tenant-acme", trust_domain="valo-trust",
        private_key=reht_priv, key_id="key-reht",
    )
    clearance = reht.issue(_clearance_payload())

    builder = CoreExecutionPermitBuilder(
        issuer_id="core-1", tenant_id="tenant-acme", trust_domain="valo-trust",
        private_key=core_priv, key_id="key-core",
    )
    permit = builder.build(
        clearance_artifact=clearance,
        execution_id="exec-1",
        target_digest=_digest(),
        payload_digest=_digest(),
        reservation_id="resv-1",
    )
    assert permit["signature"]["value"]  # signed

    issuer = CommitTokenIssuer(
        issuer_id="core-1", tenant_id="tenant-acme", trust_domain="valo-trust",
        private_key=core_priv, key_id="key-core",
    )
    token = issuer.issue(permit)
    assert token["signature"]["value"]  # signed single-use token

    assert _connector_accept(token, core_pub) is True


def test_step2_connector_rejects_missing_token(keys, registry):
    # No token presented -> connector must refuse to execute
    assert _connector_accept(None, keys["core"][1]) is False


def test_step3_connector_rejects_tampered_token(keys, registry):
    reht_priv, _ = keys["reht"]
    core_priv, core_pub = keys["core"]
    reht = GovernanceClearanceIssuer(
        issuer_id="reht-1", tenant_id="tenant-acme", trust_domain="valo-trust",
        private_key=reht_priv, key_id="key-reht",
    )
    clearance = reht.issue(_clearance_payload())
    builder = CoreExecutionPermitBuilder(
        issuer_id="core-1", tenant_id="tenant-acme", trust_domain="valo-trust",
        private_key=core_priv, key_id="key-core",
    )
    permit = builder.build(
        clearance_artifact=clearance, execution_id="exec-2",
        target_digest=_digest(), payload_digest=_digest(), reservation_id="resv-2",
    )
    token = CommitTokenIssuer(
        issuer_id="core-1", tenant_id="tenant-acme", trust_domain="valo-trust",
        private_key=core_priv, key_id="key-core",
    ).issue(permit)
    # mutate payload after signing
    token["payload"]["action_id"] = "act-999"
    assert _connector_accept(token, core_pub) is False
