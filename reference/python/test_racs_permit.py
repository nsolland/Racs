from copy import deepcopy
from datetime import datetime
import pytest
from racs_clearance import GovernanceClearanceIssuer, GovernanceClearanceVerifier
from racs_crypto import generate_keypair, load_private_key
from racs_decision import RacsDecisionError, RacsDecisionIssuer, RacsDecisionVerifier, VerifiedClearanceChain
from racs_permit import CommitTokenIssuer, CoreExecutionPermitBuilder, CoreExecutionPermitVerifier, PermitError

def _digest(char='a'):
    return 'sha256:' + char * 64

def _constraints():
    return {'machine_readable': True, 'binds_exact_action': True, 'rules': [{'id': 'r1', 'predicate': 'amount_lte', 'target': 'amount', 'value': 100}]}

def _clearance_payload(decision='ALLOW'):
    d = _digest()
    payload = {'clearance_id': 'clr-1', 'action_id': 'act-1', 'action_envelope_digest': d, 'tenant_id': 'tenant-acme', 'decision': decision, 'admissibility_state': 'ADMISSIBLE' if decision == 'ALLOW' else 'CONDITIONALLY_ADMISSIBLE', 'authority_digest': d, 'delegation_chain_digest': d, 'policy_digest': d, 'evidence_digest': d, 'purpose_digest': d, 'state_digest': d, 'target_digest': d, 'payload_digest': d, 'connector_id': 'connector-bank', 'capability': 'transfer_funds', 'consequence_class': 'HIGH', 'reversibility': 'IRREVERSIBLE', 'valid_from': '2026-07-14T00:00:00Z', 'valid_until': '2026-12-31T23:59:59Z', 'replay_nonce': 'nonce-' + 'b' * 16, 'idempotency_key': 'idem-' + 'c' * 8, 'revocation_registry_ref': 'rev-reg-1', 'evaluator_refs': ['vaig-1', 'reht-1'], 'admissibility_determination_ref': 'det-1', 'admissibility_determination_digest': _digest('d')}
    if decision == 'MODIFY':
        payload['constraints'] = _constraints()
    return payload

class StubChainVerifier:

    def verify(self, **kwargs):
        clearance = kwargs['governance_clearance']
        return VerifiedClearanceChain(action_id=clearance['action_id'], tenant_id=clearance['tenant_id'], action_envelope_digest=clearance['action_envelope_digest'], admissibility_determination_ref=clearance['admissibility_determination_ref'], admissibility_determination_digest=clearance['admissibility_determination_digest'], boundary_assessment_ref='bca-1', boundary_assessment_digest=_digest('e'), evaluation_bindings=({'evaluation_ref': 'eval-1', 'evaluation_digest': _digest('f')},), valid_until=datetime.fromisoformat(clearance['valid_until'].replace('Z', '+00:00')))

@pytest.fixture()
def keys():
    reht_priv, reht_pub = generate_keypair()
    racs_priv, racs_pub = generate_keypair()
    core_priv, core_pub = generate_keypair()
    return {'reht': (load_private_key(reht_priv), reht_pub.decode()), 'racs': (load_private_key(racs_priv), racs_pub.decode()), 'core': (load_private_key(core_priv), core_pub.decode())}

@pytest.fixture()
def registry(keys):
    return {'reht-1': {'issuer_id': 'reht-1', 'issuer_role': 'REHT_CLEARANCE_ISSUER', 'tenant_scope': 'tenant-acme', 'trust_domain': 'valo-trust', 'allowed_artifact_types': ['GovernanceClearance'], 'key_id': 'key-reht', 'algorithm': 'Ed25519', 'public_key': keys['reht'][1], 'valid_from': '2026-01-01T00:00:00Z', 'valid_until': '2027-01-01T00:00:00Z', 'revocation_status': 'ACTIVE'}, 'racs-1': {'issuer_id': 'racs-1', 'issuer_role': 'RACS_DECISION_POINT', 'tenant_scope': 'tenant-acme', 'trust_domain': 'valo-trust', 'allowed_artifact_types': ['RACSDecision'], 'key_id': 'key-racs', 'algorithm': 'Ed25519', 'public_key': keys['racs'][1], 'valid_from': '2026-01-01T00:00:00Z', 'valid_until': '2027-01-01T00:00:00Z', 'revocation_status': 'ACTIVE'}, 'core-1': {'issuer_id': 'core-1', 'issuer_role': 'CORE_ENFORCER', 'tenant_scope': 'tenant-acme', 'trust_domain': 'valo-trust', 'allowed_artifact_types': ['CoreExecutionPermit', 'CommitToken'], 'key_id': 'key-core', 'algorithm': 'Ed25519', 'public_key': keys['core'][1], 'valid_from': '2026-01-01T00:00:00Z', 'valid_until': '2027-01-01T00:00:00Z', 'revocation_status': 'ACTIVE'}}

def _issue_clearance(keys, decision='ALLOW'):
    return GovernanceClearanceIssuer(issuer_id='reht-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['reht'][0], key_id='key-reht').issue(_clearance_payload(decision))

def _issue_decision(keys, registry, clearance, decision=None, constraints=None):
    return RacsDecisionIssuer(issuer_id='racs-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['racs'][0], key_id='key-racs', clearance_verifier=GovernanceClearanceVerifier(registry), chain_verifier=StubChainVerifier()).issue(racs_decision_id='racs-dec-1', clearance_artifact=clearance, action_envelope={}, boundary_assessment={}, governance_evaluations=[{}], admissibility_determination={}, decision=decision, constraints=constraints)

def _builder(keys, registry):
    clearance_verifier = GovernanceClearanceVerifier(registry)
    return CoreExecutionPermitBuilder(issuer_id='core-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['core'][0], key_id='key-core', decision_verifier=RacsDecisionVerifier(registry, clearance_verifier))

def _build_permit(keys, registry, clearance=None, decision=None, execution_id='exec-1'):
    clearance = clearance or _issue_clearance(keys)
    decision = decision or _issue_decision(keys, registry, clearance)
    return _builder(keys, registry).build(clearance_artifact=clearance, racs_decision_artifact=decision, execution_id=execution_id, target_digest=_digest(), payload_digest=_digest(), reservation_id=f'resv-{execution_id}')

def _token_issuer(keys, registry):
    return CommitTokenIssuer(issuer_id='core-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['core'][0], key_id='key-core', trust_registry=registry)

def test_full_verified_chain_issues_decision_permit_and_token(keys, registry):
    clearance = _issue_clearance(keys)
    decision = _issue_decision(keys, registry, clearance)
    permit = _build_permit(keys, registry, clearance, decision)
    CoreExecutionPermitVerifier(registry).verify(permit)
    token = _token_issuer(keys, registry).issue(permit)
    assert permit['payload']['racs_decision_id'] == decision['artifact_id']
    assert permit['payload']['racs_decision_digest'] == decision['payload_digest']
    assert token['payload']['racs_decision_digest'] == decision['payload_digest']
    assert token['payload']['execution_permit_digest'] == permit['payload_digest']

def test_racs_cannot_expand_modify_clearance_to_allow(keys, registry):
    clearance = _issue_clearance(keys, 'MODIFY')
    with pytest.raises(RacsDecisionError, match='expand'):
        _issue_decision(keys, registry, clearance, decision='ALLOW')

def test_allow_can_be_narrowed_to_modify_with_constraints(keys, registry):
    clearance = _issue_clearance(keys)
    decision = _issue_decision(keys, registry, clearance, decision='MODIFY', constraints=_constraints())
    permit = _build_permit(keys, registry, clearance, decision)
    token = _token_issuer(keys, registry).issue(permit)
    assert permit['payload']['decision'] == 'MODIFY'
    assert permit['payload']['constraints'] == _constraints()
    assert token['payload']['constraints'] == _constraints()

def test_builder_rejects_tampered_or_unknown_racs_decision(keys, registry):
    clearance = _issue_clearance(keys)
    decision = _issue_decision(keys, registry, clearance)
    tampered = deepcopy(decision)
    tampered['payload']['target_digest'] = _digest('f')
    with pytest.raises(PermitError, match='RACS decision verification failed'):
        _build_permit(keys, registry, clearance, tampered)
    restricted = {k: v for k, v in registry.items() if k != 'racs-1'}
    with pytest.raises(PermitError, match='unknown RACS decision issuer'):
        _build_permit(keys, restricted, clearance, decision)

def test_builder_rejects_target_or_payload_substitution(keys, registry):
    clearance = _issue_clearance(keys)
    decision = _issue_decision(keys, registry, clearance)
    builder = _builder(keys, registry)
    with pytest.raises(PermitError, match='target digest'):
        builder.build(clearance_artifact=clearance, racs_decision_artifact=decision, execution_id='exec-target', target_digest=_digest('e'), payload_digest=_digest(), reservation_id='resv-target')
    with pytest.raises(PermitError, match='payload digest'):
        builder.build(clearance_artifact=clearance, racs_decision_artifact=decision, execution_id='exec-payload', target_digest=_digest(), payload_digest=_digest('e'), reservation_id='resv-payload')

def test_token_issuer_rejects_tampered_or_revoked_core(keys, registry):
    permit = _build_permit(keys, registry)
    permit['payload']['target_digest'] = _digest('f')
    with pytest.raises(PermitError, match='permit payload digest mismatch'):
        _token_issuer(keys, registry).issue(permit)
    permit = _build_permit(keys, registry, execution_id='exec-revoked')
    revoked = deepcopy(registry)
    revoked['core-1']['revocation_status'] = 'REVOKED'
    with pytest.raises(PermitError, match='not active'):
        _token_issuer(keys, revoked).issue(permit)
