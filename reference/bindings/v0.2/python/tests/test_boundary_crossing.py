from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from racs_v02.boundary_crossing import (
    ArtifactBinding,
    BoundaryAssessmentBinding,
    BoundaryCrossing,
    BoundaryCrossingAssessment,
    BoundaryRequirementSet,
    BoundaryResponseFloor,
    BoundaryState,
    BoundaryType,
)
from racs_v02.boundary_validation import (
    REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH,
    REASON_BOUNDARY_ASSESSMENT_EXPIRED,
    REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH,
    REASON_BOUNDARY_ENVELOPE_MISMATCH,
    REASON_BOUNDARY_LIFETIME_MISMATCH,
    REASON_BOUNDARY_POLICY_MISMATCH,
    REASON_BOUNDARY_REQUIRED_MISSING,
    REASON_BOUNDARY_RESPONSE_FLOOR_VIOLATION,
    REASON_BOUNDARY_TYPE_MISSING,
    verify_boundary_chain,
    verify_determination_boundary_binding,
    verify_evaluation_boundary_binding,
)
from racs_v02.digest import sha256_digest
from racs_v02.models import (
    AdmissibilityDetermination,
    AdmissibilityState,
    ConsequenceClass,
    Decision,
    EvaluationBinding,
    GovernanceClearance,
    GovernanceEvaluation,
    Reversibility,
    Status,
)
from racs_v02.verification import verify_clearance_binding

D = lambda char: "sha256:" + char * 64
SPEC = Path(__file__).resolve().parents[5] / "spec"
STATE_RANK = {
    "NO_CROSSING": 0,
    "AUTHORIZED": 1,
    "CONDITIONALLY_AUTHORIZED": 2,
    "INDETERMINATE": 3,
    "UNAUTHORIZED": 4,
    "STALE": 5,
    "REVOKED": 6,
}
RESPONSE_RANK = {"NONE": 0, "MODIFY": 1, "DEFER": 2, "STEP_UP": 3, "DENY": 4, "HALT": 5}


def envelope() -> dict:
    return {
        "action_id": "act-1",
        "tenant_id": "tenant-1",
        "action_type": "SEND_EMAIL",
        "actor_ref": "actor:1",
        "target_ref": "mail:1",
        "target_digest": D("1"),
        "payload_digest": D("2"),
        "authority_grant_ref": "auth:1",
        "delegation_chain_ref": "deleg:1",
        "policy_ref": "policy:main",
        "evidence_package_ref": "evidence:1",
        "purpose_ref": "purpose:1",
        "environment_state_ref": "env:1",
        "risk_context_ref": "risk:1",
        "connector_id": "gmail",
        "capability": "send_email",
        "consequence_class": "MEDIUM",
        "reversibility": "IRREVERSIBLE",
        "created_at": "2026-07-28T15:00:00Z",
        "expires_at": "2026-07-28T15:30:00Z",
        "replay_nonce": "1234567890abcdef",
        "idempotency_key": "idem-123",
        "boundary_requirements": {
            "required_types": ["EXECUTION"],
            "policy_ref": "boundary-policy:1",
            "policy_digest": D("3"),
            "fail_closed": True,
        },
    }


def crossing(
    *,
    boundary_type: BoundaryType = BoundaryType.EXECUTION,
    state: BoundaryState = BoundaryState.AUTHORIZED,
    floor: BoundaryResponseFloor = BoundaryResponseFloor.NONE,
    reasons: list[str] | None = None,
    crossing_id: str = "cross-1",
    authority: bool = True,
    policy_ref: str = "boundary-policy:1",
    policy_digest: str = D("3"),
    valid_until: str = "2026-07-28T15:20:00Z",
) -> BoundaryCrossing:
    optional = {}
    if boundary_type is BoundaryType.RESOURCE and state in {
        BoundaryState.AUTHORIZED,
        BoundaryState.CONDITIONALLY_AUTHORIZED,
    }:
        optional["resource_reservation_binding"] = ArtifactBinding(ref="reservation:1", digest=D("9"))
    if boundary_type is BoundaryType.EVALUATION:
        optional["evaluation_provenance_binding"] = ArtifactBinding(ref="eval-prov:1", digest=D("a"))
    return BoundaryCrossing(
        crossing_id=crossing_id,
        boundary_type=boundary_type,
        crossing_detected=True,
        prior_state_digest=D("4"),
        proposed_state_digest=D("5"),
        authority_requirement_ref="authority:required",
        authority_binding=ArtifactBinding(ref="auth-binding:1", digest=D("6")) if authority else None,
        policy_binding=ArtifactBinding(ref=policy_ref, digest=policy_digest),
        evidence_binding=ArtifactBinding(ref="evidence:cross-1", digest=D("7")),
        details_digest=D("8"),
        state=state,
        required_response_floor=floor,
        reason_codes=sorted(reasons or []),
        observed_at="2026-07-28T15:01:00Z",
        valid_until=valid_until,
        **optional,
    )


def assessment(env: dict | None = None, items: list[BoundaryCrossing] | None = None, **overrides) -> BoundaryCrossingAssessment:
    env = env or envelope()
    items = items or [crossing()]
    data = {
        "schema_version": "racs.boundary-crossing-assessment.v0.2",
        "assessment_id": "assess-1",
        "action_id": env["action_id"],
        "action_envelope_digest": sha256_digest(env),
        "tenant_id": env["tenant_id"],
        "assessor_id": "vaig:1",
        "assessor_version": "1.0",
        "requirement_policy_ref": env["boundary_requirements"]["policy_ref"],
        "requirement_policy_digest": env["boundary_requirements"]["policy_digest"],
        "crossings": items,
        "aggregate_state": max((item.state for item in items), key=lambda item: STATE_RANK[item.value]),
        "required_response_floor": max(
            (item.required_response_floor for item in items), key=lambda item: RESPONSE_RANK[item.value]
        ),
        "reason_codes": sorted({reason for item in items for reason in item.reason_codes}),
        "assessed_at": "2026-07-28T15:02:00Z",
        "valid_until": "2026-07-28T15:20:00Z",
        "revocation_registry_ref": "revocations:1",
    }
    data.update(overrides)
    return BoundaryCrossingAssessment(**data)


def evaluation(env: dict, assessed: BoundaryCrossingAssessment, decision: Decision = Decision.ALLOW, **overrides) -> GovernanceEvaluation:
    data = {
        "evaluation_id": "eval-1",
        "action_id": env["action_id"],
        "action_envelope_digest": sha256_digest(env),
        "tenant_id": env["tenant_id"],
        "evaluator_id": "vaig:1",
        "evaluator_version": "1",
        "decision": decision,
        "authority_status": Status.PRESENT_AND_VALID,
        "policy_status": Status.PRESENT_AND_VALID,
        "evidence_status": Status.PRESENT_AND_VALID,
        "purpose_status": Status.PRESENT_AND_VALID,
        "state_status": Status.PRESENT_AND_VALID,
        "risk_status": Status.PRESENT_AND_VALID,
        "boundary_assessment_binding": BoundaryAssessmentBinding(
            assessment_ref=assessed.assessment_id,
            assessment_digest=assessed.model_digest(),
        ),
        "evaluated_at": "2026-07-28T15:03:00Z",
        "valid_until": "2026-07-28T15:15:00Z",
    }
    data.update(overrides)
    return GovernanceEvaluation(**data)


def determination(
    env: dict,
    assessed: BoundaryCrossingAssessment,
    evaluated: GovernanceEvaluation,
    state: AdmissibilityState = AdmissibilityState.ADMISSIBLE,
    **overrides,
) -> AdmissibilityDetermination:
    data = {
        "determination_id": "det-1",
        "action_id": env["action_id"],
        "action_envelope_digest": sha256_digest(env),
        "tenant_id": env["tenant_id"],
        "authority_digest": D("a"),
        "delegation_chain_digest": D("b"),
        "policy_digest": D("c"),
        "evidence_digest": D("d"),
        "purpose_digest": D("e"),
        "state_digest": D("f"),
        "evaluation_bindings": [
            EvaluationBinding(evaluation_ref=evaluated.evaluation_id, evaluation_digest=evaluated.model_digest())
        ],
        "boundary_assessment_binding": evaluated.boundary_assessment_binding,
        "state": state,
        "determined_at": "2026-07-28T15:04:00Z",
        "valid_until": "2026-07-28T15:10:00Z",
        "revocation_registry_ref": "revocations:1",
    }
    data.update(overrides)
    return AdmissibilityDetermination(**data)


def clearance(env: dict, determined: AdmissibilityDetermination) -> GovernanceClearance:
    return GovernanceClearance(
        clearance_id="clear-1",
        action_id=env["action_id"],
        action_envelope_digest=sha256_digest(env),
        tenant_id=env["tenant_id"],
        decision=Decision.ALLOW,
        admissibility_state=AdmissibilityState.ADMISSIBLE,
        authority_digest=determined.authority_digest,
        delegation_chain_digest=determined.delegation_chain_digest,
        policy_digest=determined.policy_digest,
        evidence_digest=determined.evidence_digest,
        purpose_digest=determined.purpose_digest,
        state_digest=determined.state_digest,
        target_digest=env["target_digest"],
        payload_digest=env["payload_digest"],
        connector_id=env["connector_id"],
        capability=env["capability"],
        consequence_class=ConsequenceClass.MEDIUM,
        reversibility=Reversibility.IRREVERSIBLE,
        valid_from="2026-07-28T15:04:00Z",
        valid_until="2026-07-28T15:10:00Z",
        replay_nonce="1234567890abcdef",
        idempotency_key="idem-clear-1",
        revocation_registry_ref="revocations:1",
        evaluator_refs=["vaig:1"],
        admissibility_determination_ref=determined.determination_id,
        admissibility_determination_digest=determined.model_digest(),
    )


def schema(name: str) -> dict:
    return json.loads((SPEC / name).read_text())


def schema_errors(name: str, payload: dict) -> list:
    return list(Draft202012Validator(schema(name)).iter_errors(payload))


def test_action_envelope_requires_boundary_requirements():
    raw = envelope(); raw.pop("boundary_requirements")
    assert schema_errors("action-envelope-v0.2.schema.json", raw)


def test_action_envelope_requires_execution_boundary():
    raw = envelope(); raw["boundary_requirements"]["required_types"] = ["DISCLOSURE"]
    assert schema_errors("action-envelope-v0.2.schema.json", raw)


def test_typed_requirement_requires_execution():
    with pytest.raises(ValidationError):
        BoundaryRequirementSet(required_types=[BoundaryType.DISCLOSURE], policy_ref="p", policy_digest=D("1"), fail_closed=True)


def test_typed_requirement_requires_fail_closed():
    with pytest.raises(ValidationError):
        BoundaryRequirementSet(required_types=[BoundaryType.EXECUTION], policy_ref="p", policy_digest=D("1"), fail_closed=False)


def test_evaluation_schema_requires_binding():
    env = envelope(); assessed = assessment(env); raw = evaluation(env, assessed).model_dump(mode="json")
    raw.pop("boundary_assessment_binding")
    assert schema_errors("governance-evaluation-v0.2.schema.json", raw)


def test_determination_schema_requires_binding():
    env = envelope(); assessed = assessment(env); evaluated = evaluation(env, assessed)
    raw = determination(env, assessed, evaluated).model_dump(mode="json"); raw.pop("boundary_assessment_binding")
    assert schema_errors("admissibility-determination-v0.2.schema.json", raw)


def test_assessment_requires_execution_crossing():
    with pytest.raises(ValidationError):
        assessment(envelope(), [crossing(boundary_type=BoundaryType.DISCLOSURE, crossing_id="disclosure-1")])


def test_assessment_cannot_outlive_crossing_evidence():
    with pytest.raises(ValidationError):
        assessment(envelope(), [crossing(valid_until="2026-07-28T15:10:00Z")])


def test_crossing_policy_must_match_requirement_policy():
    with pytest.raises(ValidationError):
        assessment(envelope(), [crossing(policy_ref="other-policy")])


def test_technical_access_alone_cannot_authorize():
    with pytest.raises(ValidationError):
        crossing(state=BoundaryState.AUTHORIZED, floor=BoundaryResponseFloor.NONE, reasons=["TECHNICAL_ACCESS_ONLY"])


def test_valid_boundary_chain_accepts():
    env = envelope(); assessed = assessment(env); evaluated = evaluation(env, assessed); determined = determination(env, assessed, evaluated)
    result = verify_boundary_chain(action_envelope=env, assessment=assessed, evaluation=evaluated, determination=determined, verification_time="2026-07-28T15:05:00Z")
    assert (result.decision, result.reason_code) == ("ACCEPT", "BOUNDARY_ACCEPT")


def test_verifier_uses_envelope_digest_not_payload_digest():
    env = envelope(); assessed = assessment(env); evaluated = evaluation(env, assessed); determined = determination(env, assessed, evaluated)
    assert assessed.action_envelope_digest != env["payload_digest"]
    assert verify_boundary_chain(action_envelope=env, assessment=assessed, evaluation=evaluated, determination=determined, verification_time="2026-07-28T15:05:00Z").decision == "ACCEPT"


def test_missing_requirements_fail_closed():
    env = envelope(); assessed = assessment(env); evaluated = evaluation(env, assessed); raw = copy.deepcopy(env); raw.pop("boundary_requirements")
    result = verify_evaluation_boundary_binding(action_envelope=raw, assessment=assessed, evaluation=evaluated, verification_time="2026-07-28T15:05:00Z")
    assert result.reason_code == REASON_BOUNDARY_REQUIRED_MISSING


def test_tampered_assessment_digest_rejected():
    env = envelope(); assessed = assessment(env)
    evaluated = evaluation(env, assessed, boundary_assessment_binding=BoundaryAssessmentBinding(assessment_ref=assessed.assessment_id, assessment_digest=D("0")))
    result = verify_evaluation_boundary_binding(action_envelope=env, assessment=assessed, evaluation=evaluated, verification_time="2026-07-28T15:05:00Z")
    assert result.reason_code == REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH


def test_wrong_envelope_rejected_even_with_same_payload_digest():
    env = envelope(); assessed = assessment(env); evaluated = evaluation(env, assessed); changed = copy.deepcopy(env); changed["target_ref"] = "mail:other"
    result = verify_evaluation_boundary_binding(action_envelope=changed, assessment=assessed, evaluation=evaluated, verification_time="2026-07-28T15:05:00Z")
    assert changed["payload_digest"] == env["payload_digest"]
    assert result.reason_code == REASON_BOUNDARY_ENVELOPE_MISMATCH


def test_policy_mismatch_rejected():
    env = envelope(); changed = copy.deepcopy(env); changed["boundary_requirements"]["policy_ref"] = "boundary-policy:other"
    original = assessment(env)
    changed_assessment = BoundaryCrossingAssessment(**{**original.model_dump(mode="python"), "action_envelope_digest": sha256_digest(changed)})
    changed_evaluation = evaluation(changed, changed_assessment)
    result = verify_evaluation_boundary_binding(action_envelope=changed, assessment=changed_assessment, evaluation=changed_evaluation, verification_time="2026-07-28T15:05:00Z")
    assert result.reason_code == REASON_BOUNDARY_POLICY_MISMATCH


def test_required_boundary_type_missing_rejected():
    env = envelope(); env["boundary_requirements"]["required_types"] = ["EXECUTION", "DISCLOSURE"]
    assessed = assessment(env); evaluated = evaluation(env, assessed)
    result = verify_evaluation_boundary_binding(action_envelope=env, assessment=assessed, evaluation=evaluated, verification_time="2026-07-28T15:05:00Z")
    assert result.reason_code == REASON_BOUNDARY_TYPE_MISSING


def test_response_floor_cannot_be_downgraded_to_allow():
    env = envelope(); denied = crossing(state=BoundaryState.UNAUTHORIZED, floor=BoundaryResponseFloor.DENY, reasons=["TECHNICAL_ACCESS_ONLY"], authority=False)
    assessed = assessment(env, [denied]); evaluated = evaluation(env, assessed, decision=Decision.ALLOW)
    result = verify_evaluation_boundary_binding(action_envelope=env, assessment=assessed, evaluation=evaluated, verification_time="2026-07-28T15:05:00Z")
    assert result.reason_code == REASON_BOUNDARY_RESPONSE_FLOOR_VIOLATION


def test_expired_assessment_rejected():
    env = envelope(); assessed = assessment(env); evaluated = evaluation(env, assessed)
    result = verify_evaluation_boundary_binding(action_envelope=env, assessment=assessed, evaluation=evaluated, verification_time="2026-07-28T15:20:00Z")
    assert result.reason_code == REASON_BOUNDARY_ASSESSMENT_EXPIRED


def test_evaluation_cannot_outlive_assessment():
    env = envelope(); assessed = assessment(env); evaluated = evaluation(env, assessed, valid_until="2026-07-28T15:25:00Z")
    result = verify_evaluation_boundary_binding(action_envelope=env, assessment=assessed, evaluation=evaluated, verification_time="2026-07-28T15:05:00Z")
    assert result.reason_code == REASON_BOUNDARY_LIFETIME_MISMATCH


def test_nonclearable_assessment_cannot_become_admissible():
    env = envelope(); denied = crossing(state=BoundaryState.UNAUTHORIZED, floor=BoundaryResponseFloor.DENY, reasons=["TECHNICAL_ACCESS_ONLY"], authority=False)
    assessed = assessment(env, [denied]); evaluated = evaluation(env, assessed, decision=Decision.DENY)
    determined = determination(env, assessed, evaluated, state=AdmissibilityState.ADMISSIBLE)
    result = verify_determination_boundary_binding(assessment=assessed, evaluation=evaluated, determination=determined)
    assert result.reason_code == REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH


def test_final_clearance_verifier_requires_and_accepts_full_chain():
    env = envelope(); assessed = assessment(env); evaluated = evaluation(env, assessed); determined = determination(env, assessed, evaluated); cleared = clearance(env, determined)
    missing = verify_clearance_binding(cleared, determined, verification_time="2026-07-28T15:05:00Z")
    assert missing.reason_code == "BOUNDARY_ASSESSMENT_UNRESOLVED"
    complete = verify_clearance_binding(cleared, determined, action_envelope=env, governance_evaluation=evaluated, boundary_assessment=assessed, verification_time="2026-07-28T15:05:00Z")
    assert (complete.decision, complete.reason_code) == ("ACCEPT", "ACCEPT")
