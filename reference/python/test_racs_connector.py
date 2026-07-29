from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime
from threading import Lock
from time import sleep
import pytest
from racs_canonical import sha256_digest
from racs_clearance import GovernanceClearanceIssuer, GovernanceClearanceVerifier
from racs_connector import BoundedConnector, CommitTokenVerifier, ConnectorError, InMemoryConsumptionRegistry, ProviderResult, TokenAlreadyConsumed
from racs_crypto import generate_keypair, load_private_key
from racs_decision import RacsDecisionIssuer, RacsDecisionVerifier, VerifiedClearanceChain
from racs_permit import CommitTokenIssuer, CoreExecutionPermitBuilder
TARGET = {'account_id': 'acct-001'}
REQUEST = {'amount': 125, 'currency': 'NOK'}

def _digest(char='a'):
    return 'sha256:' + char * 64

class StubChainVerifier:

    def verify(self, **kwargs):
        clearance = kwargs['governance_clearance']
        return VerifiedClearanceChain(action_id=clearance['action_id'], tenant_id=clearance['tenant_id'], action_envelope_digest=clearance['action_envelope_digest'], admissibility_determination_ref=clearance['admissibility_determination_ref'], admissibility_determination_digest=clearance['admissibility_determination_digest'], boundary_assessment_ref='bca-connector-1', boundary_assessment_digest=_digest('e'), evaluation_bindings=({'evaluation_ref': 'eval-1', 'evaluation_digest': _digest('f')},), valid_until=datetime.fromisoformat(clearance['valid_until'].replace('Z', '+00:00')))

@pytest.fixture()
def keys():
    reht_priv, reht_pub = generate_keypair()
    racs_priv, racs_pub = generate_keypair()
    core_priv, core_pub = generate_keypair()
    connector_priv, connector_pub = generate_keypair()
    return {'reht': (load_private_key(reht_priv), reht_pub.decode()), 'racs': (load_private_key(racs_priv), racs_pub.decode()), 'core': (load_private_key(core_priv), core_pub.decode()), 'connector': (load_private_key(connector_priv), connector_pub.decode())}

@pytest.fixture()
def registry(keys):
    common = {'tenant_scope': 'tenant-acme', 'trust_domain': 'valo-trust', 'algorithm': 'Ed25519', 'valid_from': '2026-01-01T00:00:00Z', 'valid_until': '2027-01-01T00:00:00Z', 'revocation_status': 'ACTIVE'}
    return {'reht-1': {**common, 'issuer_id': 'reht-1', 'issuer_role': 'REHT_CLEARANCE_ISSUER', 'allowed_artifact_types': ['GovernanceClearance'], 'key_id': 'key-reht', 'public_key': keys['reht'][1]}, 'racs-1': {**common, 'issuer_id': 'racs-1', 'issuer_role': 'RACS_DECISION_POINT', 'allowed_artifact_types': ['RACSDecision'], 'key_id': 'key-racs', 'public_key': keys['racs'][1]}, 'core-1': {**common, 'issuer_id': 'core-1', 'issuer_role': 'CORE_ENFORCER', 'allowed_artifact_types': ['CoreExecutionPermit', 'CommitToken'], 'key_id': 'key-core', 'public_key': keys['core'][1]}}

def _clearance_payload():
    d = _digest()
    return {'clearance_id': 'clr-connector-1', 'action_id': 'act-connector-1', 'action_envelope_digest': d, 'tenant_id': 'tenant-acme', 'decision': 'ALLOW', 'admissibility_state': 'ADMISSIBLE', 'authority_digest': d, 'delegation_chain_digest': d, 'policy_digest': d, 'evidence_digest': d, 'purpose_digest': d, 'state_digest': d, 'target_digest': sha256_digest(TARGET), 'payload_digest': sha256_digest(REQUEST), 'connector_id': 'connector-bank', 'capability': 'transfer_funds', 'consequence_class': 'HIGH', 'reversibility': 'IRREVERSIBLE', 'valid_from': '2026-01-01T00:00:00Z', 'valid_until': '2027-01-01T00:00:00Z', 'replay_nonce': 'nonce-' + 'b' * 16, 'idempotency_key': 'idem-' + 'c' * 8, 'revocation_registry_ref': 'rev-reg-1', 'evaluator_refs': ['vaig-1', 'reht-1'], 'admissibility_determination_ref': 'det-connector-1', 'admissibility_determination_digest': _digest('d')}

def _issue_token(keys, registry, execution_id='exec-connector-1'):
    clearance_verifier = GovernanceClearanceVerifier(registry)
    clearance = GovernanceClearanceIssuer(issuer_id='reht-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['reht'][0], key_id='key-reht').issue(_clearance_payload())
    decision = RacsDecisionIssuer(issuer_id='racs-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['racs'][0], key_id='key-racs', clearance_verifier=clearance_verifier, chain_verifier=StubChainVerifier()).issue(racs_decision_id=f'racs-decision-{execution_id}', clearance_artifact=clearance, action_envelope={}, boundary_assessment={}, governance_evaluations=[{}], admissibility_determination={})
    permit = CoreExecutionPermitBuilder(issuer_id='core-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['core'][0], key_id='key-core', decision_verifier=RacsDecisionVerifier(registry, clearance_verifier)).build(clearance_artifact=clearance, racs_decision_artifact=decision, execution_id=execution_id, target_digest=sha256_digest(TARGET), payload_digest=sha256_digest(REQUEST), reservation_id=f'reservation-{execution_id}')
    return CommitTokenIssuer(issuer_id='core-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['core'][0], key_id='key-core', trust_registry=registry).issue(permit)

def _connector(keys, registry, consumption_registry=None):
    return BoundedConnector(connector_id='connector-bank', capability='transfer_funds', issuer_id='connector-bank-issuer', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['connector'][0], key_id='key-connector', token_verifier=CommitTokenVerifier(registry), consumption_registry=consumption_registry or InMemoryConsumptionRegistry())

def _success_provider(target, request):
    return ProviderResult('provider-transfer-001', {'status': 'accepted'})

def test_valid_decision_bound_token_executes_once(keys, registry):
    token = _issue_token(keys, registry)
    consumption = InMemoryConsumptionRegistry()
    connector = _connector(keys, registry, consumption)
    receipt = connector.execute(commit_token=token, target=TARGET, request_payload=REQUEST, provider=_success_provider)
    assert token['payload']['racs_decision_id']
    assert token['payload']['racs_decision_digest'].startswith('sha256:')
    assert receipt['payload']['technical_outcome'] == 'SUCCEEDED'
    assert consumption.get(token['payload']['commit_token_id']) is not None
    with pytest.raises(TokenAlreadyConsumed):
        connector.execute(commit_token=token, target=TARGET, request_payload=REQUEST, provider=_success_provider)

def test_concurrent_replay_allows_one_provider_call(keys, registry):
    token = _issue_token(keys, registry, 'exec-concurrent')
    connector = _connector(keys, registry)
    lock = Lock()
    calls = 0

    def provider(target, request):
        nonlocal calls
        with lock:
            calls += 1
        sleep(0.05)
        return ProviderResult('provider-concurrent', {'ok': True})

    def attempt():
        try:
            return connector.execute(commit_token=token, target=TARGET, request_payload=REQUEST, provider=provider)
        except TokenAlreadyConsumed as exc:
            return exc
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert calls == 1
    assert sum((isinstance(item, dict) for item in results)) == 1
    assert sum((isinstance(item, TokenAlreadyConsumed) for item in results)) == 1

def test_substitution_never_consumes_token(keys, registry):
    token = _issue_token(keys, registry, 'exec-substitution')
    consumption = InMemoryConsumptionRegistry()
    connector = _connector(keys, registry, consumption)
    with pytest.raises(ConnectorError, match='target digest'):
        connector.execute(commit_token=token, target={'account_id': 'acct-999'}, request_payload=REQUEST, provider=_success_provider)
    with pytest.raises(ConnectorError, match='payload digest'):
        connector.execute(commit_token=token, target=TARGET, request_payload={'amount': 999, 'currency': 'NOK'}, provider=_success_provider)
    assert consumption.get(token['payload']['commit_token_id']) is None

def test_tampered_or_revoked_token_rejected(keys, registry):
    token = _issue_token(keys, registry, 'exec-tampered')
    token['payload']['racs_decision_digest'] = _digest('f')
    with pytest.raises(ConnectorError, match='payload digest mismatch'):
        _connector(keys, registry).execute(commit_token=token, target=TARGET, request_payload=REQUEST, provider=_success_provider)
    token = _issue_token(keys, registry, 'exec-revoked')
    revoked = deepcopy(registry)
    revoked['core-1']['revocation_status'] = 'REVOKED'
    with pytest.raises(ConnectorError, match='not active'):
        _connector(keys, revoked).execute(commit_token=token, target=TARGET, request_payload=REQUEST, provider=_success_provider)

def test_provider_failure_receipted_and_token_consumed(keys, registry):
    token = _issue_token(keys, registry, 'exec-provider-failure')
    connector = _connector(keys, registry)

    def provider(target, request):
        raise RuntimeError('provider unavailable')
    receipt = connector.execute(commit_token=token, target=TARGET, request_payload=REQUEST, provider=provider)
    assert receipt['payload']['technical_outcome'] == 'FAILED'
    assert receipt['payload']['error_class'] == 'RuntimeError'
    with pytest.raises(TokenAlreadyConsumed):
        connector.execute(commit_token=token, target=TARGET, request_payload=REQUEST, provider=_success_provider)

def test_invalid_receipt_chain_hash_rejected_before_consumption(keys, registry):
    token = _issue_token(keys, registry, 'exec-invalid-chain')
    consumption = InMemoryConsumptionRegistry()
    connector = _connector(keys, registry, consumption)
    with pytest.raises(ConnectorError, match='previous_receipt_hash'):
        connector.execute(commit_token=token, target=TARGET, request_payload=REQUEST, provider=_success_provider, previous_receipt_hash='not-a-digest')
    assert consumption.get(token['payload']['commit_token_id']) is None
