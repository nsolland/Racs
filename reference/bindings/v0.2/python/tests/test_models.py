"""Stage 3B typed-model tests.

Validates that the pydantic models:
  - parse the shared RACS GovernanceEvaluation golden payload identically to 3A,
  - reproduce the step-2 golden `payload_digest` when canonicalized,
  - enforce the schema enums / required fields (pure data-type fidelity).
"""

import json
import os

import pytest

from racs_v02 import (
    AdmissibilityDetermination,
    AdmissibilityState,
    Decision,
    GovernanceClearance,
    GovernanceEvaluation,
    Status,
)

REPO = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "..")
GOLDEN = os.path.join(REPO, "test-vectors", "0.2", "governance-evaluation-golden.json")
STEP2_DIGEST = "sha256:58c8431515435642ee92d148a0636f2b20c5292c843fc8977a1fda3f5d94644c"


@pytest.fixture
def golden_payload():
    with open(GOLDEN, "r", encoding="utf-8") as fh:
        return json.load(fh)["payload"]


def test_governance_evaluation_parses_golden(golden_payload):
    ev = GovernanceEvaluation(**golden_payload)
    assert ev.decision is Decision.ALLOW
    assert ev.authority_status is Status.PRESENT_AND_VALID
    assert ev.evaluation_id == golden_payload["evaluation_id"]


def test_governance_evaluation_reproduces_step2_digest(golden_payload):
    ev = GovernanceEvaluation(**golden_payload)
    assert ev.model_digest() == STEP2_DIGEST


def test_governance_evaluation_canonical_matches_3a(golden_payload):
    # canonical bytes from the model must equal 3A canonical of the raw dict
    from racs_v02 import sha256_digest

    ev = GovernanceEvaluation(**golden_payload)
    raw = sha256_digest(golden_payload)
    assert ev.model_digest() == raw


def test_enum_fidelity_and_rejection():
    # Invalid decision enum must be rejected (pure data-type fidelity).
    with pytest.raises(Exception):
        GovernanceEvaluation(
            evaluation_id="e1",
            action_id="a1",
            action_envelope_digest="sha256:" + "0" * 64,
            tenant_id="t1",
            evaluator_id="ev1",
            evaluator_version="v1",
            decision="NOT_A_DECISION",  # invalid
            authority_status="PRESENT_AND_VALID",
            policy_status="PRESENT_AND_VALID",
            evidence_status="PRESENT_AND_VALID",
            purpose_status="PRESENT_AND_VALID",
            state_status="PRESENT_AND_VALID",
            risk_status="PRESENT_AND_VALID",
            evaluated_at="2026-07-23T00:00:00Z",
            valid_until="2026-08-23T00:00:00Z",
        )


def test_admissibility_determination_model():
    det = AdmissibilityDetermination(
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
    assert det.model_digest().startswith("sha256:")


def test_governance_clearance_model():
    cl = GovernanceClearance(
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
        replay_nonce="nonce",
        idempotency_key="idem",
        revocation_registry_ref="rr://x",
        evaluator_refs=["e1"],
        admissibility_determination_ref="d1",
        admissibility_determination_digest="sha256:" + "a" * 64,
    )
    assert cl.decision is Decision.ALLOW
    assert cl.model_digest().startswith("sha256:")
