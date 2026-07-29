"""Fail-closed cross-artifact verification for RACS v0.2 boundary assessments."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from .boundary_crossing import (
    BoundaryCrossingAssessment,
    BoundaryState,
    response_floor_satisfied,
)
from .digest import sha256_digest
from .models import AdmissibilityDetermination, GovernanceEvaluation

REASON_BOUNDARY_ACCEPT = "BOUNDARY_ACCEPT"
REASON_BOUNDARY_REQUIRED_MISSING = "BOUNDARY_REQUIRED_MISSING"
REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH = "BOUNDARY_ASSESSMENT_REF_MISMATCH"
REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH = "BOUNDARY_ASSESSMENT_DIGEST_MISMATCH"
REASON_BOUNDARY_ACTION_MISMATCH = "BOUNDARY_ACTION_MISMATCH"
REASON_BOUNDARY_ENVELOPE_MISMATCH = "BOUNDARY_ENVELOPE_MISMATCH"
REASON_BOUNDARY_TENANT_MISMATCH = "BOUNDARY_TENANT_MISMATCH"
REASON_BOUNDARY_POLICY_MISMATCH = "BOUNDARY_POLICY_MISMATCH"
REASON_BOUNDARY_TYPE_MISSING = "BOUNDARY_TYPE_MISSING"
REASON_BOUNDARY_RESPONSE_FLOOR_VIOLATION = "BOUNDARY_RESPONSE_FLOOR_VIOLATION"
REASON_BOUNDARY_ASSESSMENT_EXPIRED = "BOUNDARY_ASSESSMENT_EXPIRED"
REASON_BOUNDARY_ASSESSMENT_REVOKED = "BOUNDARY_ASSESSMENT_REVOKED"
REASON_BOUNDARY_BINDING_DROPPED = "BOUNDARY_BINDING_DROPPED"
REASON_BOUNDARY_BINDING_INJECTED = "BOUNDARY_BINDING_INJECTED"
REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH = "BOUNDARY_CLEARABLE_STATE_MISMATCH"
REASON_BOUNDARY_ASSESSMENT_UNRESOLVED = "BOUNDARY_ASSESSMENT_UNRESOLVED"
REASON_BOUNDARY_TIME_INVALID = "BOUNDARY_TIME_INVALID"
REASON_BOUNDARY_LIFETIME_MISMATCH = "BOUNDARY_LIFETIME_MISMATCH"


@dataclass(frozen=True)
class BoundaryVerificationResult:
    decision: str
    reason_code: str
    detail: Optional[str] = None


_NON_CLEARABLE = {
    BoundaryState.UNAUTHORIZED,
    BoundaryState.INDETERMINATE,
    BoundaryState.STALE,
    BoundaryState.REVOKED,
}


def _at(value: Optional[str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _requirements(action_envelope: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    raw = action_envelope.get("boundary_requirements")
    return raw if isinstance(raw, Mapping) else None


def verify_evaluation_boundary_binding(
    *,
    action_envelope: Mapping[str, Any],
    assessment: Optional[BoundaryCrossingAssessment],
    evaluation: GovernanceEvaluation,
    verification_time: Optional[str] = None,
) -> BoundaryVerificationResult:
    requirements = _requirements(action_envelope)
    binding = evaluation.boundary_assessment_binding

    if requirements is None:
        return BoundaryVerificationResult(
            "REJECT",
            REASON_BOUNDARY_REQUIRED_MISSING,
            "ActionEnvelope must declare fail-closed boundary requirements",
        )
    if assessment is None:
        return BoundaryVerificationResult(
            "REJECT",
            REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
            "evaluation binding cannot be resolved",
        )
    if binding is None:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_BINDING_DROPPED)
    if binding.assessment_ref != assessment.assessment_id:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH
        )
    if binding.assessment_digest != assessment.model_digest():
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH
        )
    if assessment.action_id != evaluation.action_id:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ACTION_MISMATCH)
    if assessment.tenant_id != evaluation.tenant_id:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_TENANT_MISMATCH)

    envelope_digest = sha256_digest(dict(action_envelope))
    if action_envelope.get("action_id") != assessment.action_id:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ACTION_MISMATCH)
    if action_envelope.get("tenant_id") != assessment.tenant_id:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_TENANT_MISMATCH)
    if assessment.action_envelope_digest != envelope_digest:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ENVELOPE_MISMATCH)
    if evaluation.action_envelope_digest != envelope_digest:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ENVELOPE_MISMATCH)

    if (
        requirements.get("policy_ref") != assessment.requirement_policy_ref
        or requirements.get("policy_digest") != assessment.requirement_policy_digest
    ):
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_POLICY_MISMATCH)

    required_types = set(requirements.get("required_types") or [])
    present_types = {item.boundary_type.value for item in assessment.crossings}
    missing = sorted(required_types - present_types)
    if missing:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_TYPE_MISSING, ",".join(missing)
        )

    try:
        at = _at(verification_time)
        assessed_at = _at(assessment.assessed_at)
        assessment_until = _at(assessment.valid_until)
        evaluated_at = _at(evaluation.evaluated_at)
        evaluation_until = _at(evaluation.valid_until)
    except ValueError as exc:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_TIME_INVALID, str(exc)
        )

    if assessed_at > evaluated_at:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_LIFETIME_MISMATCH, "evaluation predates assessment"
        )
    if evaluation_until > assessment_until:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_LIFETIME_MISMATCH, "evaluation outlives assessment"
        )
    if at >= assessment_until:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_EXPIRED
        )
    if assessment.aggregate_state is BoundaryState.REVOKED:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_REVOKED
        )
    if not response_floor_satisfied(
        assessment.required_response_floor,
        evaluation.decision.value,
    ):
        return BoundaryVerificationResult(
            "REJECT",
            REASON_BOUNDARY_RESPONSE_FLOOR_VIOLATION,
            f"{assessment.required_response_floor.value}>{evaluation.decision.value}",
        )
    return BoundaryVerificationResult("ACCEPT", REASON_BOUNDARY_ACCEPT)


def verify_determination_boundary_binding(
    *,
    assessment: Optional[BoundaryCrossingAssessment],
    evaluation: GovernanceEvaluation,
    determination: AdmissibilityDetermination,
) -> BoundaryVerificationResult:
    evaluation_binding = evaluation.boundary_assessment_binding
    determination_binding = determination.boundary_assessment_binding

    if evaluation_binding is None and determination_binding is None:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_REQUIRED_MISSING)
    if evaluation_binding is not None and determination_binding is None:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_BINDING_DROPPED)
    if evaluation_binding is None and determination_binding is not None:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_BINDING_INJECTED)
    if assessment is None:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_UNRESOLVED
        )
    assert evaluation_binding is not None and determination_binding is not None

    if evaluation_binding != determination_binding:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH
        )
    if determination_binding.assessment_ref != assessment.assessment_id:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH
        )
    if determination_binding.assessment_digest != assessment.model_digest():
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH
        )
    if determination.action_id != assessment.action_id:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ACTION_MISMATCH)
    if determination.tenant_id != assessment.tenant_id:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_TENANT_MISMATCH)
    if determination.action_envelope_digest != assessment.action_envelope_digest:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ENVELOPE_MISMATCH)
    if determination.action_id != evaluation.action_id:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ACTION_MISMATCH)
    if determination.action_envelope_digest != evaluation.action_envelope_digest:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ENVELOPE_MISMATCH)

    try:
        evaluated_at = _at(evaluation.evaluated_at)
        evaluation_until = _at(evaluation.valid_until)
        determined_at = _at(determination.determined_at)
        determination_until = _at(determination.valid_until)
        assessment_until = _at(assessment.valid_until)
    except ValueError as exc:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_TIME_INVALID, str(exc)
        )

    if determined_at < evaluated_at:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_LIFETIME_MISMATCH, "determination predates evaluation"
        )
    if determination_until > evaluation_until or determination_until > assessment_until:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_LIFETIME_MISMATCH, "determination outlives bound evidence"
        )

    if (
        assessment.aggregate_state in _NON_CLEARABLE
        and determination.state.value in {"ADMISSIBLE", "CONDITIONALLY_ADMISSIBLE"}
    ):
        return BoundaryVerificationResult(
            "REJECT",
            REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH,
            f"{assessment.aggregate_state.value}->{determination.state.value}",
        )
    if (
        assessment.aggregate_state is BoundaryState.CONDITIONALLY_AUTHORIZED
        and determination.state.value == "ADMISSIBLE"
    ):
        return BoundaryVerificationResult(
            "REJECT",
            REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH,
            "conditional assessment cannot become ADMISSIBLE",
        )
    return BoundaryVerificationResult("ACCEPT", REASON_BOUNDARY_ACCEPT)


def verify_clearance_boundary_resolution(
    *,
    determination: AdmissibilityDetermination,
    assessment: Optional[BoundaryCrossingAssessment],
) -> BoundaryVerificationResult:
    binding = determination.boundary_assessment_binding
    if binding is None:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_REQUIRED_MISSING)
    if assessment is None:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_UNRESOLVED
        )
    if binding.assessment_ref != assessment.assessment_id:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH
        )
    if binding.assessment_digest != assessment.model_digest():
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH
        )
    if assessment.aggregate_state in _NON_CLEARABLE:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH
        )
    return BoundaryVerificationResult("ACCEPT", REASON_BOUNDARY_ACCEPT)


def verify_boundary_chain(
    *,
    action_envelope: Mapping[str, Any],
    assessment: Optional[BoundaryCrossingAssessment],
    evaluation: GovernanceEvaluation,
    determination: AdmissibilityDetermination,
    verification_time: Optional[str] = None,
) -> BoundaryVerificationResult:
    evaluation_result = verify_evaluation_boundary_binding(
        action_envelope=action_envelope,
        assessment=assessment,
        evaluation=evaluation,
        verification_time=verification_time,
    )
    if evaluation_result.decision != "ACCEPT":
        return evaluation_result
    determination_result = verify_determination_boundary_binding(
        assessment=assessment,
        evaluation=evaluation,
        determination=determination,
    )
    if determination_result.decision != "ACCEPT":
        return determination_result
    return verify_clearance_boundary_resolution(
        determination=determination,
        assessment=assessment,
    )
