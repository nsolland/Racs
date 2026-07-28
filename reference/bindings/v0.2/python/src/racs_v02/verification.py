"""RACS v0.2 runtime conformance — Stage 3C, Port B (cross-artifact verification).

JSON Schema cannot prove that referenced artifacts *exist* or that the digests
*match*. These functions enforce the binding rules between the three contract
artifacts. They operate on already-``Validated`` payloads (i.e. schema-conformant
typed models from :mod:`racs_v02.validation`).

Binding rules enforced
-----------------------
``verify_evaluation_binding(determination, evaluation)``
    * evaluation.payload_digest == evaluation_digest of every binding
    * at least one evaluation_binding.evaluation_ref == evaluation.evaluation_id
    * determination.action_id / action_envelope_digest MUST match evaluation

``verify_clearance_binding(clearance, determination, action_envelope)``
    * evaluation_digest == GovernanceEvaluation.payload_digest (delegated via
      the determination's evaluation_bindings)
    * determination-ref points at the correct determination
    * admissibility_determination_digest matches the actual determination
    * clearance and determination bind the same action_id + action_envelope_digest
    * authority/delegation/policy/evidence/purpose/state digests match
    * ALLOW only with ADMISSIBLE and WITHOUT constraints
    * MODIFY only with CONDITIONALLY_ADMISSIBLE and WITH enforceable constraints
    * negative admissibility state can never become a clearance
    * validity window (valid_from/valid_until) and revocation status checked
      before Verified[T] is produced

Return value: a :class:`VerificationResult` (decision ACCEPT/REJECT, normalized
reason code). On ACCEPT the caller may construct ``Verified[T]``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

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
    decision: str  # ACCEPT | REJECT
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
) -> VerificationResult:
    """Verify a determination's evaluation bindings against a resolved evaluation."""
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
    if not any(b.evaluation_ref == evaluation.evaluation_id for b in bindings):
        return VerificationResult(
            "REJECT",
            REASON_EVALUATION_BINDING_REF_MISMATCH,
            f"no binding references {evaluation.evaluation_id}",
        )
    for binding in bindings:
        if binding.evaluation_digest != expected:
            return VerificationResult(
                "REJECT",
                REASON_EVALUATION_BINDING_DIGEST_MISMATCH,
                f"binding {binding.evaluation_ref}: digest mismatch",
            )
    return VerificationResult("ACCEPT", REASON_ACCEPT)


def verify_clearance_binding(
    clearance: GovernanceClearance,
    determination: AdmissibilityDetermination,
    action_envelope: Optional[Dict[str, Any]] = None,
    verification_time: Optional[str] = None,
) -> VerificationResult:
    """Verify a clearance against its determination and optional action envelope.

    ``verification_time`` is an explicit RFC 3339 instant for deterministic
    conformance and replay. Production callers normally omit it, in which case the
    current UTC clock is used.
    """
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

    if determination.state in _NON_CLEARABLE_STATES:
        return VerificationResult(
            "REJECT",
            REASON_CLEARANCE_NEGATIVE_STATE,
            f"determination.state={determination.state} is not clearable",
        )
    if clearance.decision == "ALLOW":
        if determination.state != "ADMISSIBLE":
            return VerificationResult(
                "REJECT", REASON_CLEARANCE_ALLOW_STATE_MISMATCH, "ALLOW requires ADMISSIBLE"
            )
        if clearance.constraints is not None:
            return VerificationResult(
                "REJECT", REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS, "ALLOW must not carry constraints"
            )
    elif clearance.decision == "MODIFY":
        if determination.state != "CONDITIONALLY_ADMISSIBLE":
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

    if action_envelope is not None:
        envelope_digest = action_envelope.get("payload_digest") or action_envelope.get(
            "action_envelope_digest"
        )
        if (
            envelope_digest is not None
            and envelope_digest != clearance.action_envelope_digest
        ):
            return VerificationResult(
                "REJECT",
                REASON_CLEARANCE_ENVELOPE_MISMATCH,
                "resolved envelope digest mismatch",
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
