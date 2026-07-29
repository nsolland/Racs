from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import pytest
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'reference' / 'python'))
sys.path.insert(0, str(REPO / 'reference' / 'bindings' / 'v0.2' / 'python' / 'src'))
from racs_clearance import GovernanceClearanceIssuer, GovernanceClearanceVerifier
from racs_crypto import generate_keypair, load_private_key
from racs_decision import RacsDecisionError, RacsDecisionIssuer, RacsDecisionVerifier
from racs_permit import CommitTokenIssuer, CoreExecutionPermitBuilder
from racs_v02 import AdmissibilityDetermination, BoundaryCrossingAssessment, GovernanceEvaluation, sha256_digest

def _d(char: str) -> str:
    return 'sha256:' + char * 64

def _ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

def _chain():
    now = datetime.now(timezone.utc)
    envelope = {'action_id': 'act-racs-decision-1', 'tenant_id': 'tenant-acme', 'action_type': 'CONNECTOR_CALL', 'actor_ref': 'agent://decision/1', 'target_ref': 'system://bank/account', 'target_digest': _d('1'), 'payload_digest': _d('2'), 'authority_grant_ref': 'authority://grant/1', 'delegation_chain_ref': 'delegation://chain/1', 'policy_ref': 'policy://main/1', 'evidence_package_ref': 'evidence://package/1', 'purpose_ref': 'purpose://payment/1', 'environment_state_ref': 'state://environment/1', 'risk_context_ref': 'risk://context/1', 'connector_id': 'connector-bank', 'capability': 'transfer_funds', 'consequence_class': 'HIGH', 'reversibility': 'IRREVERSIBLE', 'created_at': _ts(now - timedelta(minutes=2)), 'expires_at': _ts(now + timedelta(minutes=10)), 'replay_nonce': '0123456789abcdef0123', 'idempotency_key': 'idem-racs-decision-1', 'boundary_requirements': {'required_types': ['EXECUTION'], 'policy_ref': 'policy://boundary/1', 'policy_digest': _d('3'), 'fail_closed': True}}
    envelope_digest = sha256_digest(envelope)
    assessment = BoundaryCrossingAssessment.model_validate({'schema_version': 'racs.boundary-crossing-assessment.v0.2', 'assessment_id': 'bca-racs-decision-1', 'action_id': envelope['action_id'], 'action_envelope_digest': envelope_digest, 'tenant_id': envelope['tenant_id'], 'assessor_id': 'boundary-evaluator-1', 'assessor_version': '0.2.0', 'requirement_policy_ref': 'policy://boundary/1', 'requirement_policy_digest': _d('3'), 'crossings': [{'crossing_id': 'crossing-execution-1', 'boundary_type': 'EXECUTION', 'crossing_detected': True, 'prior_state_digest': _d('4'), 'proposed_state_digest': _d('5'), 'authority_requirement_ref': 'authority-requirement://execution/1', 'authority_binding': {'ref': 'authority://grant/1', 'digest': _d('6')}, 'policy_binding': {'ref': 'policy://boundary/1', 'digest': _d('3')}, 'evidence_binding': {'ref': 'evidence://execution/1', 'digest': _d('7')}, 'details_digest': _d('8'), 'state': 'AUTHORIZED', 'required_response_floor': 'NONE', 'reason_codes': [], 'observed_at': _ts(now - timedelta(seconds=90)), 'valid_until': _ts(now + timedelta(minutes=8))}], 'aggregate_state': 'AUTHORIZED', 'required_response_floor': 'NONE', 'reason_codes': [], 'assessed_at': _ts(now - timedelta(seconds=80)), 'valid_until': _ts(now + timedelta(minutes=7)), 'revocation_registry_ref': 'revocations://boundary/1'})
    evaluation = GovernanceEvaluation.model_validate({'evaluation_id': 'eval-racs-decision-1', 'action_id': envelope['action_id'], 'action_envelope_digest': envelope_digest, 'tenant_id': envelope['tenant_id'], 'evaluator_id': 'vaig-1', 'evaluator_version': '0.2.0', 'decision': 'ALLOW', 'authority_status': 'PRESENT_AND_VALID', 'policy_status': 'PRESENT_AND_VALID', 'evidence_status': 'PRESENT_AND_VALID', 'purpose_status': 'PRESENT_AND_VALID', 'state_status': 'PRESENT_AND_VALID', 'risk_status': 'PRESENT_AND_VALID', 'reason_codes': ['OK'], 'boundary_assessment_binding': {'assessment_ref': assessment.assessment_id, 'assessment_digest': assessment.model_digest()}, 'evaluated_at': _ts(now - timedelta(seconds=60)), 'valid_until': _ts(now + timedelta(minutes=6))})
    determination = AdmissibilityDetermination.model_validate({'determination_id': 'det-racs-decision-1', 'action_id': envelope['action_id'], 'action_envelope_digest': envelope_digest, 'tenant_id': envelope['tenant_id'], 'authority_digest': _d('a'), 'delegation_chain_digest': _d('b'), 'policy_digest': _d('c'), 'evidence_digest': _d('d'), 'purpose_digest': _d('e'), 'state_digest': _d('f'), 'evaluation_bindings': [{'evaluation_ref': evaluation.evaluation_id, 'evaluation_digest': evaluation.model_digest()}], 'boundary_assessment_binding': evaluation.boundary_assessment_binding.model_dump(mode='json'), 'state': 'ADMISSIBLE', 'reason_codes': ['OK'], 'determined_at': _ts(now - timedelta(seconds=40)), 'valid_until': _ts(now + timedelta(minutes=5)), 'revocation_registry_ref': 'revocations://determination/1'})
    clearance_payload = {'clearance_id': 'clr-racs-decision-1', 'action_id': envelope['action_id'], 'action_envelope_digest': envelope_digest, 'tenant_id': envelope['tenant_id'], 'decision': 'ALLOW', 'admissibility_state': 'ADMISSIBLE', 'authority_digest': determination.authority_digest, 'delegation_chain_digest': determination.delegation_chain_digest, 'policy_digest': determination.policy_digest, 'evidence_digest': determination.evidence_digest, 'purpose_digest': determination.purpose_digest, 'state_digest': determination.state_digest, 'target_digest': envelope['target_digest'], 'payload_digest': envelope['payload_digest'], 'connector_id': envelope['connector_id'], 'capability': envelope['capability'], 'consequence_class': envelope['consequence_class'], 'reversibility': envelope['reversibility'], 'valid_from': _ts(now - timedelta(seconds=20)), 'valid_until': _ts(now + timedelta(minutes=4)), 'replay_nonce': envelope['replay_nonce'], 'idempotency_key': envelope['idempotency_key'], 'revocation_registry_ref': 'revocations://clearance/1', 'evaluator_refs': [evaluation.evaluator_id], 'admissibility_determination_ref': determination.determination_id, 'admissibility_determination_digest': determination.model_digest()}
    return (envelope, assessment.model_dump(mode='json'), [evaluation.model_dump(mode='json')], determination.model_dump(mode='json'), clearance_payload)

def _keys_and_registry():
    reht_priv, reht_pub = generate_keypair()
    racs_priv, racs_pub = generate_keypair()
    core_priv, core_pub = generate_keypair()
    keys = {'reht': load_private_key(reht_priv), 'racs': load_private_key(racs_priv), 'core': load_private_key(core_priv)}
    common = {'tenant_scope': 'tenant-acme', 'trust_domain': 'valo-trust', 'algorithm': 'Ed25519', 'valid_from': '2026-01-01T00:00:00Z', 'valid_until': '2027-01-01T00:00:00Z', 'revocation_status': 'ACTIVE'}
    registry = {'reht-1': {**common, 'issuer_role': 'REHT_CLEARANCE_ISSUER', 'allowed_artifact_types': ['GovernanceClearance'], 'key_id': 'key-reht', 'public_key': reht_pub.decode()}, 'racs-1': {**common, 'issuer_role': 'RACS_DECISION_POINT', 'allowed_artifact_types': ['RACSDecision'], 'key_id': 'key-racs', 'public_key': racs_pub.decode()}, 'core-1': {**common, 'issuer_role': 'CORE_ENFORCER', 'allowed_artifact_types': ['CoreExecutionPermit', 'CommitToken'], 'key_id': 'key-core', 'public_key': core_pub.decode()}}
    return (keys, registry)

def _signed_clearance(keys, payload):
    return GovernanceClearanceIssuer(issuer_id='reht-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['reht'], key_id='key-reht').issue(payload)

def test_full_canonical_chain_survives_decision_permit_and_token():
    envelope, assessment, evaluations, determination, clearance_payload = _chain()
    keys, registry = _keys_and_registry()
    clearance = _signed_clearance(keys, clearance_payload)
    clearance_verifier = GovernanceClearanceVerifier(registry)
    decision = RacsDecisionIssuer(issuer_id='racs-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['racs'], key_id='key-racs', clearance_verifier=clearance_verifier).issue(racs_decision_id='racs-decision-1', clearance_artifact=clearance, action_envelope=envelope, boundary_assessment=assessment, governance_evaluations=evaluations, admissibility_determination=determination)
    verified = RacsDecisionVerifier(registry, clearance_verifier).verify(decision, clearance)
    permit = CoreExecutionPermitBuilder(issuer_id='core-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['core'], key_id='key-core', decision_verifier=RacsDecisionVerifier(registry, clearance_verifier)).build(clearance_artifact=clearance, racs_decision_artifact=decision, execution_id='exec-racs-decision-1', target_digest=envelope['target_digest'], payload_digest=envelope['payload_digest'], reservation_id='reservation-racs-decision-1')
    token = CommitTokenIssuer(issuer_id='core-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['core'], key_id='key-core', trust_registry=registry).issue(permit)
    assert verified['boundary_assessment_digest'] == assessment_digest(assessment)
    assert permit['payload']['racs_decision_digest'] == decision['payload_digest']
    assert token['payload']['racs_decision_digest'] == decision['payload_digest']
    assert token['payload']['execution_permit_digest'] == permit['payload_digest']

def assessment_digest(assessment):
    return BoundaryCrossingAssessment.model_validate(assessment).model_digest()

def test_tampered_determination_cannot_produce_racs_decision():
    envelope, assessment, evaluations, determination, clearance_payload = _chain()
    keys, registry = _keys_and_registry()
    clearance = _signed_clearance(keys, clearance_payload)
    tampered = deepcopy(determination)
    tampered['state_digest'] = _d('0')
    with pytest.raises(RacsDecisionError, match='CLEARANCE_DETERMINATION_DIGEST_MISMATCH'):
        RacsDecisionIssuer(issuer_id='racs-1', tenant_id='tenant-acme', trust_domain='valo-trust', private_key=keys['racs'], key_id='key-racs', clearance_verifier=GovernanceClearanceVerifier(registry)).issue(racs_decision_id='racs-decision-tampered', clearance_artifact=clearance, action_envelope=envelope, boundary_assessment=assessment, governance_evaluations=evaluations, admissibility_determination=tampered)
