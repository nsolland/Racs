"""Cross-artifact verification for RACS v0.2 boundary assessments.

The assessment is non-authoritative evidence. These checks prove that a fail-closed
requirement declared by the ActionEnvelope is resolved by the exact assessment
bound into GovernanceEvaluation and copied unchanged into AdmissibilityDetermination.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from .boundary_crossing import (
    BoundaryCrossingAssessment,
    BoundaryState,
    response_floor_satisfied,
)
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
        parsed = parsed.replace(tzinfo=timezone.utc)
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

    if requirements is not None and binding is None:
        return BoundaryVerificationResult(
            "REJECT",
            REASON_BOUNDARY_REQUIRED_MISSING,
            "ActionEnvelope requires a boundary assessment",
        )
    if requirements is None and binding is None:
        return BoundaryVerificationResult("ACCEPT", REASON_BOUNDARY_ACCEPT)
    if assessment is None:
        return BoundaryVerificationResult(
            "REJECT",
            REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
            "evaluation binding cannot be resolved",
        )
    if binding is None:
        return BoundaryVerificationResult(
            "REJECT",
            REASON_BOUNDARY_BINDING_DROPPED,
            "assessment supplied but evaluation carries no binding",
        )

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
    if assessment.action_envelope_digest != evaluation.action_envelope_digest:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ENVELOPE_MISMATCH)

    envelope_action_id = action_envelope.get("action_id")
    envelope_tenant_id = action_envelope.get("tenant_id")
    envelope_digest = action_envelope.get("action_envelope_digest") or action_envelope.get(
        "payload_digest"
    )
    if envelope_action_id is not None and envelope_action_id != assessment.action_id:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ACTION_MISMATCH)
    if envelope_tenant_id is not None and envelope_tenant_id != assessment.tenant_id:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_TENANT_MISMATCH)
    if envelope_digest is not None and envelope_digest != assessment.action_envelope_digest:
        return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_ENVELOPE_MISMATCH)

    if requirements is not None:
        policy_ref = requirements.get("policy_ref")
        policy_digest = requirements.get("policy_digest")
        if (
            policy_ref != assessment.requirement_policy_ref
            or policy_digest != assessment.requirement_policy_digest
        ):
            return BoundaryVerificationResult("REJECT", REASON_BOUNDARY_POLICY_MISMATCH)
        required_types = set(requirements.get("required_types") or [])
        present_types = {item.boundary_type.value for item in assessment.crossings}
        missing = sorted(required_types - present_types)
        if missing:
            return BoundaryVerificationResult(
                "REJECT",
                REASON_BOUNDARY_TYPE_MISSING,
                ",".join(missing),
            )

    if assessment.aggregate_state is BoundaryState.REVOKED:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_REVOKED
        )
    if _at(verification_time) >= _at(assessment.valid_until):
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_ASSESSMENT_EXPIRED
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
        return BoundaryVerificationResult("ACCEPT", REASON_BOUNDARY_ACCEPT)
    if evaluation_binding is not None and determination_binding is None:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_BINDING_DROPPED
        )
    if evaluation_binding is None and determination_binding is not None:
        return BoundaryVerificationResult(
            "REJECT", REASON_BOUNDARY_BINDING_INJECTED
        )
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

    if (
        assessment.aggregate_state in _NON_CLEARABLE
        and determination.state.value
        in {"ADMISSIBLE", "CONDITIONALLY_ADMISSIBLE"}
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
        return BoundaryVerificationResult("ACCEPT", REASON_BOUNDARY_ACCEPT)
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
