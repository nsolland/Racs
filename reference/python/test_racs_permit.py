"""P0-C conformance: verified REHT clearance -> permit -> commit token."""

from copy import deepcopy

import pytest

from racs_crypto import generate_keypair, load_private_key
from racs_clearance import GovernanceClearanceIssuer, GovernanceClearanceVerifier
from racs_permit import (
    CommitTokenIssuer,
    CoreExecutionPermitBuilder,
    CoreExecutionPermitVerifier,
    PermitError,
)


def _digest(char="a"):
    return "sha256:" + char * 64


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
        "admissibility_determination_ref": "det-1",
        "admissibility_determination_digest": _digest("d"),
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


def _issue_clearance(keys):
    return GovernanceClearanceIssuer(
        issuer_id="reht-1",
        tenant_id="tenant-acme",
        trust_domain="valo-trust",
        private_key=keys["reht"][0],
        key_id="key-reht",
    ).issue(_clearance_payload())


def _builder(keys, registry):
    return CoreExecutionPermitBuilder(
        issuer_id="core-1",
        tenant_id="tenant-acme",
        trust_domain="valo-trust",
        private_key=keys["core"][0],
        key_id="key-core",
        clearance_verifier=GovernanceClearanceVerifier(registry),
    )


def _build_permit(keys, registry, clearance=None, execution_id="exec-1"):
    clearance = clearance or _issue_clearance(keys)
    return _builder(keys, registry).build(
        clearance_artifact=clearance,
        execution_id=execution_id,
        target_digest=_digest(),
        payload_digest=_digest(),
        reservation_id=f"resv-{execution_id}",
    )


def _token_issuer(keys, registry):
    return CommitTokenIssuer(
        issuer_id="core-1",
        tenant_id="tenant-acme",
        trust_domain="valo-trust",
        private_key=keys["core"][0],
        key_id="key-core",
        trust_registry=registry,
    )


def _connector_accept(token, core_pub_pem):
    """A bounded connector accepts only a valid single-use signed token."""
    from racs_crypto import load_public_key, verify_artifact_signature

    if not isinstance(token, dict):
        return False
    pub = load_public_key(core_pub_pem.encode())
    if not verify_artifact_signature(token, pub):
        return False
    if token.get("artifact_type") != "CommitToken":
        return False
    return token.get("payload", {}).get("single_use") is True


def test_full_verified_chain_issues_token(keys, registry):
    permit = _build_permit(keys, registry)
    CoreExecutionPermitVerifier(registry).verify(permit)

    token = _token_issuer(keys, registry).issue(permit)

    assert permit["payload"]["clearance_digest"]
    assert token["payload"]["execution_permit_digest"] == permit["payload_digest"]
    assert token["payload"]["clearance_digest"] == permit["payload"]["clearance_digest"]
    assert _connector_accept(token, keys["core"][1]) is True


def test_connector_rejects_missing_token(keys):
    assert _connector_accept(None, keys["core"][1]) is False


def test_connector_rejects_tampered_token(keys, registry):
    token = _token_issuer(keys, registry).issue(_build_permit(keys, registry))
    token["payload"]["action_id"] = "act-999"
    assert _connector_accept(token, keys["core"][1]) is False


def test_builder_rejects_tampered_clearance(keys, registry):
    clearance = _issue_clearance(keys)
    clearance["payload"]["target_digest"] = _digest("f")
    with pytest.raises(PermitError, match="clearance verification failed"):
        _build_permit(keys, registry, clearance=clearance)


def test_builder_rejects_unknown_clearance_issuer(keys, registry):
    clearance = _issue_clearance(keys)
    restricted_registry = {"core-1": registry["core-1"]}
    with pytest.raises(PermitError, match="unknown issuer"):
        _build_permit(keys, restricted_registry, clearance=clearance)


def test_builder_rejects_target_or_payload_substitution(keys, registry):
    clearance = _issue_clearance(keys)
    builder = _builder(keys, registry)

    with pytest.raises(PermitError, match="target digest does not match clearance"):
        builder.build(
            clearance_artifact=clearance,
            execution_id="exec-target-substitution",
            target_digest=_digest("e"),
            payload_digest=_digest(),
            reservation_id="resv-target-substitution",
        )

    with pytest.raises(PermitError, match="payload digest does not match clearance"):
        builder.build(
            clearance_artifact=clearance,
            execution_id="exec-payload-substitution",
            target_digest=_digest(),
            payload_digest=_digest("e"),
            reservation_id="resv-payload-substitution",
        )


def test_token_issuer_rejects_tampered_permit(keys, registry):
    permit = _build_permit(keys, registry)
    permit["payload"]["target_digest"] = _digest("f")
    with pytest.raises(PermitError, match="permit payload digest mismatch"):
        _token_issuer(keys, registry).issue(permit)


def test_token_issuer_rejects_unknown_or_revoked_core(keys, registry):
    permit = _build_permit(keys, registry)

    unknown_registry = {"reht-1": registry["reht-1"]}
    with pytest.raises(PermitError, match="unknown permit issuer"):
        _token_issuer(keys, unknown_registry).issue(permit)

    revoked_registry = deepcopy(registry)
    revoked_registry["core-1"]["revocation_status"] = "REVOKED"
    with pytest.raises(PermitError, match="not active"):
        _token_issuer(keys, revoked_registry).issue(permit)
