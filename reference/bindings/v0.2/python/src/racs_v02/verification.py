"""RACS v0.2 cross-artifact verification."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .boundary_crossing import BoundaryCrossingAssessment
from .boundary_validation import (
    REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
    verify_boundary_chain,
    verify_determination_boundary_binding,
)
from .models import (
    AdmissibilityDetermination,
    GovernanceClearance,
    GovernanceEvaluation,
)
from .validation import (
    REASON_ACCEPT,
    REASON_CLEARANCE_ACTION_MISMATCH,
    REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS,
    REASON_CLEARANCE_ALLOW_STATE_MISMATCH,
    REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
    REASON_CLEARANCE_ENVELOPE_MISMATCH,
    REASON_CLEARANCE_EXPIRED,
    REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS,
    REASON_CLEARANCE_MODIFY_STATE_MISMATCH,
    REASON_CLEARANCE_NEGATIVE_STATE,
    REASON_CLEARANCE_REVOKED,
    REASON_EVALUATION_BINDING_DIGEST_MISMATCH,
    REASON_EVALUATION_BINDING_REF_MISMATCH,
)


@dataclass
class VerificationResult:
    decision: str
    reason_code: str
    detail: Optional[str] = None


_NON_CLEARABLE_STATES = {
    "NOT_ADMISSIBLE",
    "INDETERMINATE",
    "STALE",
    "REVOKED",
    "HALTED",
    "REQUIRES_STEP_UP",
}


def verify_evaluation_binding(
    determination: AdmissibilityDetermination,
    evaluation: GovernanceEvaluation,
    boundary_assessment: Optional[BoundaryCrossingAssessment] = None,
) -> VerificationResult:
    if determination.action_id != evaluation.action_id:
        return VerificationResult(
            "REJECT",
            REASON_CLEARANCE_ACTION_MISMATCH,
            "determination.action_id != evaluation.action_id",
        )
    if determination.action_envelope_digest != evaluation.action_envelope_digest:
        return VerificationResult(
            "REJECT", REASON_CLEARANCE_ENVELOPE_MISMATCH, "envelope digest mismatch"
        )

    expected = evaluation.model_digest()
    bindings = determination.evaluation_bindings
    if not any(binding.evaluation_ref == evaluation.evaluation_id for binding in bindings):
        return VerificationResult(
            "REJECT",
            REASON_EVALUATION_BINDING_REF_MISMATCH,
            f"no binding references {evaluation.evaluation_id}",
        )
    matching = [
        binding
        for binding in bindings
        if binding.evaluation_ref == evaluation.evaluation_id
    ]
    if any(binding.evaluation_digest != expected for binding in matching):
        return VerificationResult(
            "REJECT",
            REASON_EVALUATION_BINDING_DIGEST_MISMATCH,
            f"binding {evaluation.evaluation_id}: digest mismatch",
        )

    boundary = verify_determination_boundary_binding(
        assessment=boundary_assessment,
        evaluation=evaluation,
        determination=determination,
    )
    if boundary.decision != "ACCEPT":
        return VerificationResult(
            boundary.decision,
            boundary.reason_code,
            boundary.detail,
        )
    return VerificationResult("ACCEPT", REASON_ACCEPT)


def verify_clearance_binding(
    clearance: GovernanceClearance,
    determination: AdmissibilityDetermination,
    action_envelope: Optional[Dict[str, Any]] = None,
    verification_time: Optional[str] = None,
    governance_evaluation: Optional[GovernanceEvaluation] = None,
    boundary_assessment: Optional[BoundaryCrossingAssessment] = None,
) -> VerificationResult:
    if clearance.admissibility_determination_ref != determination.determination_id:
        return VerificationResult(
            "REJECT",
            REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
            "determination_ref mismatch",
        )
    if clearance.admissibility_determination_digest != determination.model_digest():
        return VerificationResult(
            "REJECT",
            REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
            "admissibility_determination_digest mismatch",
        )

    if clearance.action_id != determination.action_id:
        return VerificationResult(
            "REJECT", REASON_CLEARANCE_ACTION_MISMATCH, "action_id mismatch"
        )
    if clearance.action_envelope_digest != determination.action_envelope_digest:
        return VerificationResult(
            "REJECT",
            REASON_CLEARANCE_ENVELOPE_MISMATCH,
            "action_envelope_digest mismatch",
        )

    digest_pairs = [
        ("authority_digest", clearance.authority_digest, determination.authority_digest),
        (
            "delegation_chain_digest",
            clearance.delegation_chain_digest,
            determination.delegation_chain_digest,
        ),
        ("policy_digest", clearance.policy_digest, determination.policy_digest),
        ("evidence_digest", clearance.evidence_digest, determination.evidence_digest),
        ("purpose_digest", clearance.purpose_digest, determination.purpose_digest),
        ("state_digest", clearance.state_digest, determination.state_digest),
    ]
    for name, clearance_value, determination_value in digest_pairs:
        if clearance_value != determination_value:
            return VerificationResult(
                "REJECT",
                REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
                f"{name} mismatch",
            )

    if determination.state.value in _NON_CLEARABLE_STATES:
        return VerificationResult(
            "REJECT",
            REASON_CLEARANCE_NEGATIVE_STATE,
            f"determination.state={determination.state.value} is not clearable",
        )
    if clearance.decision.value == "ALLOW":
        if determination.state.value != "ADMISSIBLE":
            return VerificationResult(
                "REJECT", REASON_CLEARANCE_ALLOW_STATE_MISMATCH, "ALLOW requires ADMISSIBLE"
            )
        if clearance.constraints is not None:
            return VerificationResult(
                "REJECT", REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS, "ALLOW must not carry constraints"
            )
    elif clearance.decision.value == "MODIFY":
        if determination.state.value != "CONDITIONALLY_ADMISSIBLE":
            return VerificationResult(
                "REJECT",
                REASON_CLEARANCE_MODIFY_STATE_MISMATCH,
                "MODIFY requires CONDITIONALLY_ADMISSIBLE",
            )
        if clearance.constraints is None:
            return VerificationResult(
                "REJECT",
                REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS,
                "MODIFY requires constraints",
            )
        if not _enforceable_constraints(clearance.constraints):
            return VerificationResult(
                "REJECT",
                REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS,
                "constraints present but not enforceable",
            )

    if clearance.revocation_registry_ref == "":
        return VerificationResult(
            "REJECT", REASON_CLEARANCE_REVOKED, "empty revocation_registry_ref"
        )
    if _is_expired(
        clearance.valid_from,
        clearance.valid_until,
        verification_time=verification_time,
    ):
        return VerificationResult(
            "REJECT", REASON_CLEARANCE_EXPIRED, "validity window expired"
        )

    if (
        action_envelope is None
        or governance_evaluation is None
        or boundary_assessment is None
    ):
        return VerificationResult(
            "REJECT",
            REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
            "clearance verification requires envelope, evaluation and assessment",
        )

    boundary = verify_boundary_chain(
        action_envelope=action_envelope,
        assessment=boundary_assessment,
        evaluation=governance_evaluation,
        determination=determination,
        verification_time=verification_time,
    )
    if boundary.decision != "ACCEPT":
        return VerificationResult(
            boundary.decision,
            boundary.reason_code,
            boundary.detail,
        )
    return VerificationResult("ACCEPT", REASON_ACCEPT)


def _enforceable_constraints(constraints: Any) -> bool:
    if not isinstance(constraints, dict):
        return False
    rules = constraints.get("rules")
    if isinstance(rules, list) and len(rules) >= 1:
        return True
    ref = constraints.get("constraint_set_ref")
    digest = constraints.get("constraint_set_digest")
    return (
        isinstance(ref, str)
        and bool(ref)
        and isinstance(digest, str)
        and digest.startswith("sha256:")
    )


def _is_expired(
    valid_from: Optional[str],
    valid_until: Optional[str],
    *,
    verification_time: Optional[str] = None,
) -> bool:
    from datetime import datetime, timezone

    if not valid_until:
        return False
    try:
        until = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        at = (
            datetime.fromisoformat(verification_time.replace("Z", "+00:00"))
            if verification_time
            else datetime.now(timezone.utc)
        )
    except ValueError:
        return False
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return until < at
