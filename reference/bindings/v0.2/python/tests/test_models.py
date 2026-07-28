"""Stage 3B typed-model tests for mandatory boundary-assessment binding."""
import json
from pathlib import Path

import pytest

from racs_v02 import (
    AdmissibilityDetermination,
    AdmissibilityState,
    BoundaryAssessmentBinding,
    Decision,
    GovernanceClearance,
    GovernanceEvaluation,
    Status,
    sha256_digest,
)

REPO = Path(__file__).resolve().parents[5]
GOLDEN = REPO / "test-vectors" / "0.2" / "governance-evaluation-golden.json"
STEP2_DIGEST = "sha256:532d2a571f8536890bf9b79994703c63a44c01ba40f71b4733d045674bdb3273"
BINDING = {
    "assessment_ref": "bca:test:001",
    "assessment_digest": "sha256:" + "b" * 64,
}


@pytest.fixture
def golden_payload():
    return json.loads(GOLDEN.read_text(encoding="utf-8"))["payload"]


def test_governance_evaluation_parses_golden(golden_payload):
    evaluation = GovernanceEvaluation(**golden_payload)
    assert evaluation.decision is Decision.ALLOW
    assert evaluation.authority_status is Status.PRESENT_AND_VALID
    assert evaluation.boundary_assessment_binding is not None


def test_governance_evaluation_reproduces_step2_digest(golden_payload):
    assert GovernanceEvaluation(**golden_payload).model_digest() == STEP2_DIGEST


def test_governance_evaluation_canonical_matches_raw(golden_payload):
    assert GovernanceEvaluation(**golden_payload).model_digest() == sha256_digest(
        golden_payload
    )


def test_governance_evaluation_requires_boundary_binding(golden_payload):
    payload = dict(golden_payload)
    del payload["boundary_assessment_binding"]
    with pytest.raises(Exception):
        GovernanceEvaluation(**payload)


def test_invalid_decision_rejected(golden_payload):
    payload = dict(golden_payload)
    payload["decision"] = "NOT_A_DECISION"
    with pytest.raises(Exception):
        GovernanceEvaluation(**payload)


def test_admissibility_determination_model():
    determination = AdmissibilityDetermination(
        determination_id="d1",
        action_id="a1",
        action_envelope_digest="sha256:" + "0" * 64,
        tenant_id="t1",
        authority_digest="sha256:" + "1" * 64,
        delegation_chain_digest="sha256:" + "2" * 64,
        policy_digest="sha256:" + "3" * 64,
        evidence_digest="sha256:" + "4" * 64,
        purpose_digest="sha256:" + "5" * 64,
        state_digest="sha256:" + "6" * 64,
        evaluation_bindings=[
            {"evaluation_ref": "ev-1", "evaluation_digest": "sha256:" + "7" * 64}
        ],
        boundary_assessment_binding=BINDING,
        state=AdmissibilityState.ADMISSIBLE,
        determined_at="2026-07-23T00:00:00Z",
        valid_until="2026-08-23T00:00:00Z",
        revocation_registry_ref="rr://x",
    )
    assert determination.model_digest().startswith("sha256:")


def test_determination_requires_boundary_binding():
    with pytest.raises(Exception):
        AdmissibilityDetermination(
            determination_id="d1",
            action_id="a1",
            action_envelope_digest="sha256:" + "0" * 64,
            tenant_id="t1",
            authority_digest="sha256:" + "1" * 64,
            delegation_chain_digest="sha256:" + "2" * 64,
            policy_digest="sha256:" + "3" * 64,
            evidence_digest="sha256:" + "4" * 64,
            purpose_digest="sha256:" + "5" * 64,
            state_digest="sha256:" + "6" * 64,
            evaluation_bindings=[
                {"evaluation_ref": "ev-1", "evaluation_digest": "sha256:" + "7" * 64}
            ],
            state=AdmissibilityState.ADMISSIBLE,
            determined_at="2026-07-23T00:00:00Z",
            valid_until="2026-08-23T00:00:00Z",
            revocation_registry_ref="rr://x",
        )


def test_governance_clearance_model():
    clearance = GovernanceClearance(
        clearance_id="c1",
        action_id="a1",
        action_envelope_digest="sha256:" + "0" * 64,
        tenant_id="t1",
        decision=Decision.ALLOW,
        admissibility_state=AdmissibilityState.ADMISSIBLE,
        authority_digest="sha256:" + "1" * 64,
        delegation_chain_digest="sha256:" + "2" * 64,
        policy_digest="sha256:" + "3" * 64,
        evidence_digest="sha256:" + "4" * 64,
        purpose_digest="sha256:" + "5" * 64,
        state_digest="sha256:" + "6" * 64,
        target_digest="sha256:" + "8" * 64,
        payload_digest="sha256:" + "9" * 64,
        connector_id="conn-1",
        capability="read",
        consequence_class="LOW",
        reversibility="REVERSIBLE",
        valid_from="2026-07-23T00:00:00Z",
        valid_until="2026-08-23T00:00:00Z",
        replay_nonce="0123456789abcdef",
        idempotency_key="idem-001",
        revocation_registry_ref="rr://x",
        evaluator_refs=["e1"],
        admissibility_determination_ref="d1",
        admissibility_determination_digest="sha256:" + "a" * 64,
    )
    assert clearance.decision is Decision.ALLOW
    assert clearance.model_digest().startswith("sha256:")


def test_boundary_binding_is_frozen_and_typed():
    binding = BoundaryAssessmentBinding(**BINDING)
    assert binding.assessment_ref == "bca:test:001"
    with pytest.raises(Exception):
        binding.assessment_ref = "changed"
