"""Conformance tests for atomic CommitToken consumption at connector boundary."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Lock
from time import sleep

import pytest

from racs_canonical import sha256_digest
from racs_clearance import GovernanceClearanceIssuer, GovernanceClearanceVerifier
from racs_connector import (
    BoundedConnector,
    CommitTokenVerifier,
    ConnectorError,
    InMemoryConsumptionRegistry,
    ProviderResult,
    TokenAlreadyConsumed,
)
from racs_crypto import (
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_artifact,
    verify_artifact_signature,
)
from racs_permit import CommitTokenIssuer, CoreExecutionPermitBuilder


TARGET = {"account_id": "acct-001"}
REQUEST = {"amount": 125, "currency": "NOK"}


def _digest(char="a"):
    return "sha256:" + char * 64


@pytest.fixture()
def keys():
    reht_priv, reht_pub = generate_keypair()
    core_priv, core_pub = generate_keypair()
    connector_priv, connector_pub = generate_keypair()
    return {
        "reht": (load_private_key(reht_priv), reht_pub.decode()),
        "core": (load_private_key(core_priv), core_pub.decode()),
        "connector": (load_private_key(connector_priv), connector_pub.decode()),
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


def _clearance_payload():
    d = _digest()
    return {
        "clearance_id": "clr-connector-1",
        "action_id": "act-connector-1",
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
        "target_digest": sha256_digest(TARGET),
        "payload_digest": sha256_digest(REQUEST),
        "connector_id": "connector-bank",
        "capability": "transfer_funds",
        "consequence_class": "HIGH",
        "reversibility": "IRREVERSIBLE",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "replay_nonce": "nonce-" + "b" * 16,
        "idempotency_key": "idem-" + "c" * 8,
        "revocation_registry_ref": "rev-reg-1",
        "evaluator_refs": ["vaig-1", "reht-1"],
        "admissibility_determination_ref": "det-connector-1",
        "admissibility_determination_digest": _digest("d"),
    }


def _issue_token(keys, registry, execution_id="exec-connector-1"):
    clearance = GovernanceClearanceIssuer(
        issuer_id="reht-1",
        tenant_id="tenant-acme",
        trust_domain="valo-trust",
        private_key=keys["reht"][0],
        key_id="key-reht",
    ).issue(_clearance_payload())
    permit = CoreExecutionPermitBuilder(
        issuer_id="core-1",
        tenant_id="tenant-acme",
        trust_domain="valo-trust",
        private_key=keys["core"][0],
        key_id="key-core",
        clearance_verifier=GovernanceClearanceVerifier(registry),
    ).build(
        clearance_artifact=clearance,
        execution_id=execution_id,
        target_digest=sha256_digest(TARGET),
        payload_digest=sha256_digest(REQUEST),
        reservation_id=f"reservation-{execution_id}",
    )
    return CommitTokenIssuer(
        issuer_id="core-1",
        tenant_id="tenant-acme",
        trust_domain="valo-trust",
        private_key=keys["core"][0],
        key_id="key-core",
        trust_registry=registry,
    ).issue(permit)


def _connector(keys, registry, consumption_registry=None):
    return BoundedConnector(
        connector_id="connector-bank",
        capability="transfer_funds",
        issuer_id="connector-bank-issuer",
        tenant_id="tenant-acme",
        trust_domain="valo-trust",
        private_key=keys["connector"][0],
        key_id="key-connector",
        token_verifier=CommitTokenVerifier(registry),
        consumption_registry=consumption_registry or InMemoryConsumptionRegistry(),
    )


def _success_provider(target, request):
    assert target == TARGET
    assert request == REQUEST
    return ProviderResult(
        provider_reference="provider-transfer-001",
        response={"status": "accepted"},
    )


def test_valid_token_executes_once_and_produces_signed_receipt(keys, registry):
    token = _issue_token(keys, registry)
    consumption = InMemoryConsumptionRegistry()
    connector = _connector(keys, registry, consumption)

    receipt = connector.execute(
        commit_token=token,
        target=TARGET,
        request_payload=REQUEST,
        provider=_success_provider,
    )

    assert receipt["payload"]["technical_outcome"] == "SUCCEEDED"
    assert receipt["payload"]["commit_token_digest"] == token["payload_digest"]
    assert receipt["payload"]["target_digest"] == sha256_digest(TARGET)
    assert receipt["payload"]["payload_digest"] == sha256_digest(REQUEST)
    assert consumption.get(token["payload"]["commit_token_id"]) is not None
    connector_pub = load_public_key(keys["connector"][1].encode())
    assert verify_artifact_signature(receipt, connector_pub) is True
    assert receipt["expires_at"] > receipt["issued_at"]

    with pytest.raises(TokenAlreadyConsumed):
        connector.execute(
            commit_token=token,
            target=TARGET,
            request_payload=REQUEST,
            provider=_success_provider,
        )


def test_concurrent_replay_allows_exactly_one_provider_call(keys, registry):
    token = _issue_token(keys, registry, execution_id="exec-concurrent")
    connector = _connector(keys, registry)
    counter_lock = Lock()
    provider_calls = 0

    def provider(target, request):
        nonlocal provider_calls
        with counter_lock:
            provider_calls += 1
        sleep(0.05)
        return ProviderResult("provider-concurrent", {"ok": True})

    def attempt():
        try:
            return connector.execute(
                commit_token=token,
                target=TARGET,
                request_payload=REQUEST,
                provider=provider,
            )
        except TokenAlreadyConsumed as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))

    assert provider_calls == 1
    assert sum(isinstance(item, dict) for item in results) == 1
    assert sum(isinstance(item, TokenAlreadyConsumed) for item in results) == 1


def test_target_or_payload_substitution_never_consumes_token(keys, registry):
    token = _issue_token(keys, registry, execution_id="exec-substitution")
    consumption = InMemoryConsumptionRegistry()
    connector = _connector(keys, registry, consumption)
    provider_calls = 0

    def provider(target, request):
        nonlocal provider_calls
        provider_calls += 1
        return ProviderResult("provider-substitution", {"ok": True})

    with pytest.raises(ConnectorError, match="target digest"):
        connector.execute(
            commit_token=token,
            target={"account_id": "acct-999"},
            request_payload=REQUEST,
            provider=provider,
        )
    with pytest.raises(ConnectorError, match="payload digest"):
        connector.execute(
            commit_token=token,
            target=TARGET,
            request_payload={"amount": 999, "currency": "NOK"},
            provider=provider,
        )

    assert provider_calls == 0
    assert consumption.get(token["payload"]["commit_token_id"]) is None

    receipt = connector.execute(
        commit_token=token,
        target=TARGET,
        request_payload=REQUEST,
        provider=provider,
    )
    assert receipt["payload"]["technical_outcome"] == "SUCCEEDED"
    assert provider_calls == 1


def test_tampered_or_expired_token_is_rejected_before_consumption(keys, registry):
    consumption = InMemoryConsumptionRegistry()
    connector = _connector(keys, registry, consumption)

    tampered = _issue_token(keys, registry, execution_id="exec-tampered")
    tampered["payload"]["target_digest"] = _digest("f")
    with pytest.raises(ConnectorError, match="payload digest mismatch"):
        connector.execute(
            commit_token=tampered,
            target=TARGET,
            request_payload=REQUEST,
            provider=_success_provider,
        )

    expired = _issue_token(keys, registry, execution_id="exec-expired")
    expired["issued_at"] = "2026-07-28T00:00:00Z"
    expired["expires_at"] = "2026-07-28T00:01:00Z"
    expired["payload"]["issued_at"] = expired["issued_at"]
    expired["payload"]["valid_until"] = expired["expires_at"]
    expired["payload_digest"] = sha256_digest(expired["payload"])
    expired["signature"]["value"] = ""
    sign_artifact(expired, keys["core"][0])
    with pytest.raises(ConnectorError, match="token expired"):
        connector.execute(
            commit_token=expired,
            target=TARGET,
            request_payload=REQUEST,
            provider=_success_provider,
        )

    assert consumption.get(tampered["payload"]["commit_token_id"]) is None
    assert consumption.get(expired["payload"]["commit_token_id"]) is None


def test_revoked_core_issuer_is_rejected_before_provider(keys, registry):
    token = _issue_token(keys, registry, execution_id="exec-revoked")
    revoked = deepcopy(registry)
    revoked["core-1"]["revocation_status"] = "REVOKED"
    connector = _connector(keys, revoked)
    provider_calls = 0

    def provider(target, request):
        nonlocal provider_calls
        provider_calls += 1
        return ProviderResult("provider-revoked", {"ok": True})

    with pytest.raises(ConnectorError, match="not active"):
        connector.execute(
            commit_token=token,
            target=TARGET,
            request_payload=REQUEST,
            provider=provider,
        )
    assert provider_calls == 0


def test_provider_failure_is_receipted_and_token_stays_consumed(keys, registry):
    token = _issue_token(keys, registry, execution_id="exec-provider-failure")
    connector = _connector(keys, registry)

    def provider(target, request):
        raise RuntimeError("provider unavailable")

    receipt = connector.execute(
        commit_token=token,
        target=TARGET,
        request_payload=REQUEST,
        provider=provider,
    )
    assert receipt["payload"]["technical_outcome"] == "FAILED"
    assert receipt["payload"]["error_class"] == "RuntimeError"
    assert receipt["payload"]["provider_reference"] == "provider-error:RuntimeError"

    with pytest.raises(TokenAlreadyConsumed):
        connector.execute(
            commit_token=token,
            target=TARGET,
            request_payload=REQUEST,
            provider=_success_provider,
        )


def test_invalid_receipt_chain_hash_is_rejected_before_consumption(keys, registry):
    token = _issue_token(keys, registry, execution_id="exec-invalid-chain")
    consumption = InMemoryConsumptionRegistry()
    connector = _connector(keys, registry, consumption)

    with pytest.raises(ConnectorError, match="previous_receipt_hash"):
        connector.execute(
            commit_token=token,
            target=TARGET,
            request_payload=REQUEST,
            provider=_success_provider,
            previous_receipt_hash="not-a-digest",
        )

    assert consumption.get(token["payload"]["commit_token_id"]) is None
