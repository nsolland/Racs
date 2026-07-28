"""RACS v0.2 runtime-continuity cross-artifact verification.

Verification proves that a launched session is bound to the exact admitted
capability, environment, evaluation and clearance artifacts. It also proves
that MODIFY_RUNTIME_BOUNDS only narrows the currently effective bounds.

These functions produce verification evidence. They do not create authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Sequence

from .continuity import (
    ContinuityDecision,
    ContinuityDecisionType,
    EnvironmentGovernanceProfile,
    GovernedCapabilityManifest,
    GovernedExecutionSession,
    SessionState,
)
from .models import (
    AdmissibilityState,
    Decision,
    GovernanceClearance,
    GovernanceEvaluation,
)

REASON_ACCEPT = "ACCEPT"
REASON_SESSION_TERMINAL = "SESSION_TERMINAL"
REASON_SESSION_ACTION_ENVELOPE_MISMATCH = "SESSION_ACTION_ENVELOPE_MISMATCH"
REASON_SESSION_AUTHORITY_MISMATCH = "SESSION_AUTHORITY_MISMATCH"
REASON_SESSION_CAPABILITY_MANIFEST_MISMATCH = "SESSION_CAPABILITY_MANIFEST_MISMATCH"
REASON_SESSION_ENVIRONMENT_PROFILE_MISMATCH = "SESSION_ENVIRONMENT_PROFILE_MISMATCH"
REASON_SESSION_EVALUATION_MISMATCH = "SESSION_EVALUATION_MISMATCH"
REASON_SESSION_CLEARANCE_MISMATCH = "SESSION_CLEARANCE_MISMATCH"
REASON_SESSION_TENANT_MISMATCH = "SESSION_TENANT_MISMATCH"
REASON_SESSION_EXECUTOR_NOT_ALLOWED = "SESSION_EXECUTOR_NOT_ALLOWED"
REASON_SESSION_CAPABILITY_NOT_PERMITTED = "SESSION_CAPABILITY_NOT_PERMITTED"
REASON_SESSION_CONSEQUENCE_NOT_ALLOWED = "SESSION_CONSEQUENCE_NOT_ALLOWED"
REASON_SESSION_PROFILE_NOT_REFERENCED = "SESSION_PROFILE_NOT_REFERENCED"
REASON_SESSION_CLEARANCE_NOT_EXECUTABLE = "SESSION_CLEARANCE_NOT_EXECUTABLE"
REASON_SESSION_ARTIFACT_NOT_CURRENT = "SESSION_ARTIFACT_NOT_CURRENT"
REASON_SESSION_DEADLINE_EXCEEDS_AUTHORIZATION = "SESSION_DEADLINE_EXCEEDS_AUTHORIZATION"

REASON_BOUNDS_NARROWED = "BOUNDS_NARROWED"
REASON_BOUNDS_WIDENED = "BOUNDS_WIDENED"
REASON_BOUNDS_UNPROVABLE = "BOUNDS_UNPROVABLE"
REASON_BOUNDS_NOT_NARROWER = "BOUNDS_NOT_NARROWER"

REASON_DECISION_SESSION_MISMATCH = "DECISION_SESSION_MISMATCH"
REASON_DECISION_SEQUENCE_MISMATCH = "DECISION_SEQUENCE_MISMATCH"
REASON_DECISION_ACTION_MISMATCH = "DECISION_ACTION_MISMATCH"
REASON_DECISION_CAPABILITY_MISMATCH = "DECISION_CAPABILITY_MISMATCH"
REASON_DECISION_ENVIRONMENT_MISMATCH = "DECISION_ENVIRONMENT_MISMATCH"
REASON_DECISION_AUTHORITY_MISMATCH = "DECISION_AUTHORITY_MISMATCH"
REASON_DECISION_EXPIRED = "DECISION_EXPIRED"
REASON_DECISION_OUTLIVES_SESSION = "DECISION_OUTLIVES_SESSION"

_TERMINAL_STATES = {
    SessionState.COMPLETED,
    SessionState.FAILED,
    SessionState.STOPPED,
    SessionState.HALTED,
}
_TIME_KEYS = {
    "deadline",
    "expires_at",
    "valid_until",
    "must_complete_by",
    "end_at",
    "latest_finish_at",
}


@dataclass(frozen=True)
class ContinuityVerificationResult:
    decision: str
    reason_code: str
    detail: Optional[str] = None
    effective_bounds: Optional[Dict[str, Any]] = None

    @classmethod
    def accept(
        cls,
        reason_code: str = REASON_ACCEPT,
        *,
        effective_bounds: Optional[Dict[str, Any]] = None,
    ) -> "ContinuityVerificationResult":
        return cls("ACCEPT", reason_code, effective_bounds=effective_bounds)

    @classmethod
    def reject(cls, reason_code: str, detail: str) -> "ContinuityVerificationResult":
        return cls("REJECT", reason_code, detail=detail)


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _verification_time(value: Optional[str]) -> datetime:
    return _parse_time(value) if value is not None else datetime.now(timezone.utc)


def _is_current(now: datetime, valid_from: str, valid_until: str) -> bool:
    return _parse_time(valid_from) <= now <= _parse_time(valid_until)


def verify_execution_session(
    session: GovernedExecutionSession,
    manifest: GovernedCapabilityManifest,
    profile: EnvironmentGovernanceProfile,
    evaluation: GovernanceEvaluation,
    clearance: GovernanceClearance,
    *,
    verification_time: Optional[str] = None,
) -> ContinuityVerificationResult:
    """Verify the exact artifact chain required for an active session."""

    if session.session_state in _TERMINAL_STATES:
        return ContinuityVerificationResult.reject(
            REASON_SESSION_TERMINAL,
            f"session_state={session.session_state.value} is terminal",
        )

    if (
        session.action_envelope_digest != evaluation.action_envelope_digest
        or session.action_envelope_digest != clearance.action_envelope_digest
    ):
        return ContinuityVerificationResult.reject(
            REASON_SESSION_ACTION_ENVELOPE_MISMATCH,
            "session, evaluation and clearance must bind the same ActionEnvelope",
        )
    if session.authority_digest != clearance.authority_digest:
        return ContinuityVerificationResult.reject(
            REASON_SESSION_AUTHORITY_MISMATCH,
            "session.authority_digest != clearance.authority_digest",
        )
    if session.capability_manifest_digest != manifest.model_digest():
        return ContinuityVerificationResult.reject(
            REASON_SESSION_CAPABILITY_MANIFEST_MISMATCH,
            "session does not bind the supplied capability manifest",
        )
    if session.environment_profile_digest != profile.model_digest():
        return ContinuityVerificationResult.reject(
            REASON_SESSION_ENVIRONMENT_PROFILE_MISMATCH,
            "session does not bind the supplied environment profile",
        )
    if session.governance_evaluation_digest != evaluation.model_digest():
        return ContinuityVerificationResult.reject(
            REASON_SESSION_EVALUATION_MISMATCH,
            "session does not bind the supplied GovernanceEvaluation",
        )
    if session.reht_clearance_digest != clearance.model_digest():
        return ContinuityVerificationResult.reject(
            REASON_SESSION_CLEARANCE_MISMATCH,
            "session does not bind the supplied GovernanceClearance",
        )

    if not (profile.tenant_id == evaluation.tenant_id == clearance.tenant_id):
        return ContinuityVerificationResult.reject(
            REASON_SESSION_TENANT_MISMATCH,
            "profile, evaluation and clearance tenant bindings differ",
        )
    if session.executor_id not in manifest.executor_binding.allowed_executor_ids:
        return ContinuityVerificationResult.reject(
            REASON_SESSION_EXECUTOR_NOT_ALLOWED,
            "executor_id is outside the admitted executor binding",
        )
    if clearance.capability not in manifest.permissions:
        return ContinuityVerificationResult.reject(
            REASON_SESSION_CAPABILITY_NOT_PERMITTED,
            "clearance capability is not admitted by the manifest",
        )
    if (
        clearance.consequence_class not in manifest.consequence_classes
        or clearance.consequence_class not in profile.allowed_consequence_classes
    ):
        return ContinuityVerificationResult.reject(
            REASON_SESSION_CONSEQUENCE_NOT_ALLOWED,
            "consequence class is outside manifest or environment admission",
        )
    accepted_profile_refs = {
        profile.profile_id,
        f"{profile.profile_id}@{profile.profile_version}",
    }
    if not accepted_profile_refs.intersection(manifest.environment_profile_refs):
        return ContinuityVerificationResult.reject(
            REASON_SESSION_PROFILE_NOT_REFERENCED,
            "manifest does not reference the bound environment profile",
        )
    if (
        clearance.decision not in {Decision.ALLOW, Decision.MODIFY}
        or clearance.admissibility_state
        not in {
            AdmissibilityState.ADMISSIBLE,
            AdmissibilityState.CONDITIONALLY_ADMISSIBLE,
        }
        or evaluation.decision not in {Decision.ALLOW, Decision.MODIFY}
    ):
        return ContinuityVerificationResult.reject(
            REASON_SESSION_CLEARANCE_NOT_EXECUTABLE,
            "evaluation or clearance is not executable",
        )

    now = _verification_time(verification_time)
    current_windows = (
        (manifest.issued_at, manifest.expires_at),
        (profile.valid_from, profile.expires_at),
        (clearance.valid_from, clearance.valid_until),
        (evaluation.evaluated_at, evaluation.valid_until),
    )
    if not all(_is_current(now, start, end) for start, end in current_windows):
        return ContinuityVerificationResult.reject(
            REASON_SESSION_ARTIFACT_NOT_CURRENT,
            "one or more bound artifacts are not current at verification time",
        )

    authorization_deadline = min(
        _parse_time(manifest.expires_at),
        _parse_time(profile.expires_at),
        _parse_time(evaluation.valid_until),
        _parse_time(clearance.valid_until),
    )
    if _parse_time(session.must_complete_by) > authorization_deadline:
        return ContinuityVerificationResult.reject(
            REASON_SESSION_DEADLINE_EXCEEDS_AUTHORIZATION,
            "session deadline exceeds a bound artifact validity window",
        )

    return ContinuityVerificationResult.accept()


def prove_runtime_bounds_narrowing(
    current_bounds: Mapping[str, Any],
    proposed_bounds: Mapping[str, Any],
) -> ContinuityVerificationResult:
    """Prove that every proposed runtime bound is equal or stricter.

    Unknown dimensions and semantically ambiguous changes fail closed.
    At least one dimension must become strictly narrower.
    """

    try:
        changed = _prove_mapping(current_bounds, proposed_bounds, path="")
    except _BoundsFailure as failure:
        return ContinuityVerificationResult.reject(failure.reason_code, failure.detail)
    if not changed:
        return ContinuityVerificationResult.reject(
            REASON_BOUNDS_NOT_NARROWER,
            "MODIFY_RUNTIME_BOUNDS must make at least one bound stricter",
        )
    return ContinuityVerificationResult.accept(
        REASON_BOUNDS_NARROWED,
        effective_bounds=dict(proposed_bounds),
    )


class _BoundsFailure(Exception):
    def __init__(self, reason_code: str, detail: str):
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


def _prove_mapping(
    current: Mapping[str, Any],
    proposed: Mapping[str, Any],
    *,
    path: str,
) -> bool:
    changed = False
    for key, proposed_value in proposed.items():
        item_path = f"{path}.{key}" if path else key
        if key not in current:
            raise _BoundsFailure(
                REASON_BOUNDS_UNPROVABLE,
                f"{item_path}: dimension is not present in the current bounds",
            )
        changed = _prove_value(
            key,
            current[key],
            proposed_value,
            path=item_path,
        ) or changed
    return changed


def _prove_value(key: str, current: Any, proposed: Any, *, path: str) -> bool:
    if isinstance(current, bool) or isinstance(proposed, bool):
        if type(current) is not type(proposed):
            raise _BoundsFailure(REASON_BOUNDS_UNPROVABLE, f"{path}: type changed")
        if current != proposed:
            raise _BoundsFailure(
                REASON_BOUNDS_UNPROVABLE,
                f"{path}: boolean direction is not declared",
            )
        return False

    if isinstance(current, (int, float)) and isinstance(proposed, (int, float)):
        minimum_dimension = key.startswith("min_") or "minimum" in key or "floor" in key
        if minimum_dimension:
            if proposed < current:
                raise _BoundsFailure(REASON_BOUNDS_WIDENED, f"{path}: minimum decreased")
            return proposed > current
        if proposed > current:
            raise _BoundsFailure(REASON_BOUNDS_WIDENED, f"{path}: upper bound increased")
        return proposed < current

    if isinstance(current, str) and isinstance(proposed, str):
        if key in _TIME_KEYS or key.endswith(("_deadline", "_expires_at", "_valid_until")):
            try:
                current_time = _parse_time(current)
                proposed_time = _parse_time(proposed)
            except ValueError as exc:
                raise _BoundsFailure(
                    REASON_BOUNDS_UNPROVABLE,
                    f"{path}: invalid time bound",
                ) from exc
            if proposed_time > current_time:
                raise _BoundsFailure(REASON_BOUNDS_WIDENED, f"{path}: deadline moved later")
            return proposed_time < current_time
        if current != proposed:
            raise _BoundsFailure(
                REASON_BOUNDS_UNPROVABLE,
                f"{path}: string direction is not declared",
            )
        return False

    if isinstance(current, Mapping) and isinstance(proposed, Mapping):
        return _prove_mapping(current, proposed, path=path)

    if isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
        if not isinstance(proposed, Sequence) or isinstance(proposed, (str, bytes)):
            raise _BoundsFailure(REASON_BOUNDS_UNPROVABLE, f"{path}: type changed")
        try:
            current_set = set(current)
            proposed_set = set(proposed)
        except TypeError as exc:
            raise _BoundsFailure(
                REASON_BOUNDS_UNPROVABLE,
                f"{path}: complex list membership cannot be proven",
            ) from exc
        if not proposed_set.issubset(current_set):
            raise _BoundsFailure(REASON_BOUNDS_WIDENED, f"{path}: allowed set expanded")
        return proposed_set != current_set

    if current is None or proposed is None:
        if current != proposed:
            raise _BoundsFailure(REASON_BOUNDS_UNPROVABLE, f"{path}: nullability changed")
        return False

    if type(current) is not type(proposed):
        raise _BoundsFailure(REASON_BOUNDS_UNPROVABLE, f"{path}: type changed")
    if current != proposed:
        raise _BoundsFailure(
            REASON_BOUNDS_UNPROVABLE,
            f"{path}: narrowing semantics are not declared",
        )
    return False


def verify_continuity_decision(
    session: GovernedExecutionSession,
    decision: ContinuityDecision,
    current_bounds: Mapping[str, Any],
    *,
    verification_time: Optional[str] = None,
) -> ContinuityVerificationResult:
    """Verify decision/session bindings and runtime-bound monotonicity."""

    if session.session_state in _TERMINAL_STATES:
        return ContinuityVerificationResult.reject(
            REASON_SESSION_TERMINAL,
            f"session_state={session.session_state.value} is terminal",
        )
    if decision.session_id != session.session_id:
        return ContinuityVerificationResult.reject(
            REASON_DECISION_SESSION_MISMATCH,
            "decision.session_id != session.session_id",
        )
    if decision.continuity_sequence != session.continuity_sequence + 1:
        return ContinuityVerificationResult.reject(
            REASON_DECISION_SEQUENCE_MISMATCH,
            "continuity sequence must advance by exactly one",
        )
    if decision.action_envelope_digest != session.action_envelope_digest:
        return ContinuityVerificationResult.reject(
            REASON_DECISION_ACTION_MISMATCH,
            "decision action binding differs from the session",
        )
    if decision.capability_manifest_digest != session.capability_manifest_digest:
        return ContinuityVerificationResult.reject(
            REASON_DECISION_CAPABILITY_MISMATCH,
            "decision capability binding differs from the session",
        )
    if decision.environment_profile_digest != session.environment_profile_digest:
        return ContinuityVerificationResult.reject(
            REASON_DECISION_ENVIRONMENT_MISMATCH,
            "decision environment binding differs from the session",
        )
    if decision.authority_state_digest != session.authority_digest:
        return ContinuityVerificationResult.reject(
            REASON_DECISION_AUTHORITY_MISMATCH,
            "decision authority state differs from the session",
        )

    now = _verification_time(verification_time)
    if _parse_time(decision.valid_until) < now:
        return ContinuityVerificationResult.reject(
            REASON_DECISION_EXPIRED,
            "continuity decision is expired",
        )
    if _parse_time(decision.valid_until) > _parse_time(session.must_complete_by):
        return ContinuityVerificationResult.reject(
            REASON_DECISION_OUTLIVES_SESSION,
            "continuity decision cannot outlive the session",
        )

    if decision.decision is ContinuityDecisionType.MODIFY_RUNTIME_BOUNDS:
        if decision.constraints is None:
            return ContinuityVerificationResult.reject(
                REASON_BOUNDS_UNPROVABLE,
                "MODIFY_RUNTIME_BOUNDS has no constraints",
            )
        return prove_runtime_bounds_narrowing(current_bounds, decision.constraints)

    return ContinuityVerificationResult.accept()
