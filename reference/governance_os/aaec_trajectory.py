"""Deterministic reference validation for AAEC trajectory governance.

This module validates additive RACS trajectory evidence. It does not establish
organisational authority, issue REHT clearance, mint execution permits, or
execute consequence-bearing actions.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Mapping, Sequence


class GovernanceError(ValueError):
    """Raised when an AAEC trajectory artifact fails deterministic validation."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


def parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise GovernanceError("AAEC_TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None:
        raise GovernanceError("AAEC_TIMESTAMP_INVALID")
    return parsed.astimezone(timezone.utc)


class ValidationStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    INCOMPLETE = "INCOMPLETE"
    UNVERIFIABLE = "UNVERIFIABLE"


class MinimumResponse(str, Enum):
    NONE = "NONE"
    STEP_UP = "STEP_UP"
    DENY = "DENY"
    HALT = "HALT"


_RESPONSE_PRECEDENCE = {
    MinimumResponse.NONE: 0,
    MinimumResponse.STEP_UP: 1,
    MinimumResponse.DENY: 2,
    MinimumResponse.HALT: 3,
}


class ReasonCode(str, Enum):
    CONTEXT_DIGEST_MISMATCH = "AAEC_CONTEXT_DIGEST_MISMATCH"
    UNSUPPORTED_VERSION = "AAEC_UNSUPPORTED_VERSION"
    AUTHORITY_CREATION_FORBIDDEN = "AAEC_AUTHORITY_CREATION_FORBIDDEN"
    CONTEXT_EXPIRED = "AAEC_CONTEXT_EXPIRED"
    CONTEXT_NOT_YET_VALID = "AAEC_CONTEXT_NOT_YET_VALID"
    TRAJECTORY_LINEAGE_MISSING = "AAEC_TRAJECTORY_LINEAGE_MISSING"
    TRAJECTORY_LINEAGE_MISMATCH = "AAEC_TRAJECTORY_LINEAGE_MISMATCH"
    ACTION_SEQUENCE_GAP = "AAEC_ACTION_SEQUENCE_GAP"
    AUTHORITY_LINEAGE_CHANGED = "AAEC_AUTHORITY_LINEAGE_CHANGED"
    PRINCIPAL_BINDING_CHANGED = "AAEC_PRINCIPAL_BINDING_CHANGED"
    AGENT_IDENTITY_CHANGED = "AAEC_AGENT_IDENTITY_CHANGED"
    TARGET_SET_DIGEST_MISMATCH = "AAEC_TARGET_SET_DIGEST_MISMATCH"
    TARGET_SET_EXPANSION = "AAEC_TARGET_SET_EXPANSION"
    TARGET_EXPANSION_EVIDENCE_MISSING = "AAEC_TARGET_EXPANSION_EVIDENCE_MISSING"
    COUNTER_REGRESSION = "AAEC_COUNTER_REGRESSION"
    COUNTER_TRANSITION_MISMATCH = "AAEC_COUNTER_TRANSITION_MISMATCH"
    CUMULATIVE_CEILING_EXCEEDED = "AAEC_CUMULATIVE_CEILING_EXCEEDED"
    HARVESTED_CREDENTIAL_PROVENANCE = "AAEC_HARVESTED_CREDENTIAL_PROVENANCE"
    SELF_CREATED_AUTHORITY = "AAEC_SELF_CREATED_AUTHORITY"
    MANDATORY_EVIDENCE_MISSING = "AAEC_MANDATORY_EVIDENCE_MISSING"
    DESTRUCTIVE_OBLIGATION_MISSING = "AAEC_DESTRUCTIVE_OBLIGATION_MISSING"
    UNVERIFIED_EXFILTRATION_CLAIM = "AAEC_UNVERIFIED_EXFILTRATION_CLAIM"
    VERIFIED_CLAIM_EVIDENCE_MISSING = "AAEC_VERIFIED_CLAIM_EVIDENCE_MISSING"
    MACHINE_SPEED_ADAPTIVE_RETRY = "AAEC_MACHINE_SPEED_ADAPTIVE_RETRY"
    INDEPENDENT_HALT = "AAEC_INDEPENDENT_HALT"


_COUNTER_FIELDS = (
    "action_count",
    "destructive_action_count",
    "irreversible_action_count",
    "secret_access_count",
    "privilege_change_count",
    "persistence_change_count",
    "lateral_target_expansion_count",
    "observed_egress_bytes",
)

_REQUIRED_FIELDS = (
    "trajectory_version",
    "trajectory_id",
    "trajectory_root_digest",
    "sequence_no",
    "prior_terminal_receipt_digest",
    "terminal_receipt_digest",
    "authority_lineage_digest",
    "principal_binding_digest",
    "agent_identity_digest",
    "target_ids",
    "target_set_digest",
    "cumulative_consequence",
    "ceilings",
    "action_observation",
    "evidence_bindings",
    "valid_from",
    "valid_until",
    "issued_at",
    "authority_effect",
    "execution_authority",
    "digest_profile",
    "context_digest",
)

_HIGH_RISK_EVIDENCE = {
    "IDENTITY_CREATE": ("authority_transition_clearance",),
    "PRIVILEGE_CHANGE": ("authority_transition_clearance",),
    "PERSISTENCE_CREATE": ("persistence_clearance",),
    "INTEGRITY_CONTROL_CHANGE": ("integrity_control_change_clearance",),
    "DATA_ENCRYPT": ("destructive_action_clearance", "reversibility_assessment"),
    "DATA_DELETE": ("destructive_action_clearance", "reversibility_assessment"),
    "DATABASE_DROP": (
        "destructive_action_clearance",
        "reversibility_assessment",
        "fresh_human_approval",
    ),
}


@dataclass(frozen=True)
class AAECValidationResult:
    validation_status: ValidationStatus
    minimum_response: MinimumResponse
    reason_codes: tuple[str, ...]
    context_digest: str
    trajectory_id: str
    sequence_no: int
    observed_claim_types: tuple[str, ...]
    unverified_claim_types: tuple[str, ...]
    execution_authority: str = "NONE"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["validation_status"] = self.validation_status.value
        value["minimum_response"] = self.minimum_response.value
        value["reason_codes"] = list(self.reason_codes)
        value["observed_claim_types"] = list(self.observed_claim_types)
        value["unverified_claim_types"] = list(self.unverified_claim_types)
        return value


def _require_keys(value: Mapping[str, Any], keys: Sequence[str]) -> list[str]:
    return sorted(set(keys) - set(value))


def _add(
    reasons: list[ReasonCode],
    responses: list[MinimumResponse],
    code: ReasonCode,
    response: MinimumResponse,
) -> None:
    if code not in reasons:
        reasons.append(code)
    responses.append(response)


def _minimum_response(values: Sequence[MinimumResponse]) -> MinimumResponse:
    return max(values or [MinimumResponse.NONE], key=_RESPONSE_PRECEDENCE.__getitem__)


def _identifier_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or not value:
        return None
    if any(not isinstance(item, str) or not item for item in value):
        return None
    if len(value) != len(set(value)):
        return None
    return sorted(value)


def target_set_digest(target_ids: Sequence[str]) -> str:
    return digest({"target_ids": sorted(set(target_ids))})


def _action_deltas(action: Mapping[str, Any]) -> dict[str, int]:
    discovered = action.get("new_target_ids", [])
    return {
        "action_count": 1,
        "destructive_action_count": int(bool(action.get("destructive"))),
        "irreversible_action_count": int(bool(action.get("irreversible"))),
        "secret_access_count": int(bool(action.get("secret_access"))),
        "privilege_change_count": int(bool(action.get("authority_amplification"))),
        "persistence_change_count": int(bool(action.get("persistence_creation"))),
        "lateral_target_expansion_count": len(discovered)
        if isinstance(discovered, list)
        else 0,
        "observed_egress_bytes": int(action.get("observed_egress_bytes", 0) or 0),
    }


def _status_for(reasons: Sequence[ReasonCode]) -> ValidationStatus:
    incomplete = {
        ReasonCode.TRAJECTORY_LINEAGE_MISSING,
        ReasonCode.TARGET_EXPANSION_EVIDENCE_MISSING,
        ReasonCode.MANDATORY_EVIDENCE_MISSING,
        ReasonCode.DESTRUCTIVE_OBLIGATION_MISSING,
        ReasonCode.VERIFIED_CLAIM_EVIDENCE_MISSING,
    }
    unverifiable = {
        ReasonCode.CONTEXT_DIGEST_MISMATCH,
        ReasonCode.TARGET_SET_DIGEST_MISMATCH,
    }
    if any(code in incomplete for code in reasons):
        return ValidationStatus.INCOMPLETE
    if any(code in unverifiable for code in reasons):
        return ValidationStatus.UNVERIFIABLE
    informational = {
        ReasonCode.UNVERIFIED_EXFILTRATION_CLAIM,
        ReasonCode.MACHINE_SPEED_ADAPTIVE_RETRY,
    }
    if any(code not in informational for code in reasons):
        return ValidationStatus.MISMATCH
    return ValidationStatus.MATCH


def validate_aaec_trajectory_context(
    context: Mapping[str, Any],
    *,
    previous_context: Mapping[str, Any] | None,
    expected_authority_lineage_digest: str,
    authorized_target_ids: Sequence[str],
    now: str,
) -> AAECValidationResult:
    """Validate additive AAEC evidence without creating execution authority."""
    item = deepcopy(dict(context))
    reasons: list[ReasonCode] = []
    responses: list[MinimumResponse] = []

    missing = _require_keys(item, _REQUIRED_FIELDS)
    if missing:
        return AAECValidationResult(
            validation_status=ValidationStatus.INCOMPLETE,
            minimum_response=MinimumResponse.DENY,
            reason_codes=(ReasonCode.MANDATORY_EVIDENCE_MISSING.value,),
            context_digest=str(item.get("context_digest", "")),
            trajectory_id=str(item.get("trajectory_id", "")),
            sequence_no=int(item.get("sequence_no", -1)),
            observed_claim_types=(),
            unverified_claim_types=(),
        )

    if item["trajectory_version"] != "aaec-trajectory-context-0.3":
        _add(reasons, responses, ReasonCode.UNSUPPORTED_VERSION, MinimumResponse.DENY)
    if item["digest_profile"] != "rfc8785-sha256-excluding:context_digest":
        _add(reasons, responses, ReasonCode.UNSUPPORTED_VERSION, MinimumResponse.DENY)
    if (
        item["authority_effect"] != "NO_AUTHORITY_CREATION"
        or item["execution_authority"] != "NONE"
    ):
        _add(
            reasons,
            responses,
            ReasonCode.AUTHORITY_CREATION_FORBIDDEN,
            MinimumResponse.DENY,
        )

    unsigned = {key: value for key, value in item.items() if key != "context_digest"}
    if item["context_digest"] != digest(unsigned):
        _add(
            reasons,
            responses,
            ReasonCode.CONTEXT_DIGEST_MISMATCH,
            MinimumResponse.DENY,
        )

    current = parse_time(now)
    valid_from = parse_time(item["valid_from"])
    valid_until = parse_time(item["valid_until"])
    issued_at = parse_time(item["issued_at"])
    if current < valid_from or issued_at > current:
        _add(
            reasons,
            responses,
            ReasonCode.CONTEXT_NOT_YET_VALID,
            MinimumResponse.DENY,
        )
    if current > valid_until:
        _add(reasons, responses, ReasonCode.CONTEXT_EXPIRED, MinimumResponse.DENY)

    try:
        sequence_no = int(item["sequence_no"])
    except (TypeError, ValueError):
        sequence_no = -1
        _add(reasons, responses, ReasonCode.ACTION_SEQUENCE_GAP, MinimumResponse.DENY)

    if previous_context is None:
        if sequence_no != 0:
            _add(reasons, responses, ReasonCode.ACTION_SEQUENCE_GAP, MinimumResponse.DENY)
        if item["prior_terminal_receipt_digest"] is not None:
            _add(
                reasons,
                responses,
                ReasonCode.TRAJECTORY_LINEAGE_MISMATCH,
                MinimumResponse.DENY,
            )
    else:
        previous = dict(previous_context)
        if sequence_no != int(previous.get("sequence_no", -1)) + 1:
            _add(reasons, responses, ReasonCode.ACTION_SEQUENCE_GAP, MinimumResponse.DENY)
        expected_receipt = previous.get("terminal_receipt_digest")
        if not item["prior_terminal_receipt_digest"]:
            _add(
                reasons,
                responses,
                ReasonCode.TRAJECTORY_LINEAGE_MISSING,
                MinimumResponse.DENY,
            )
        elif item["prior_terminal_receipt_digest"] != expected_receipt:
            _add(
                reasons,
                responses,
                ReasonCode.TRAJECTORY_LINEAGE_MISMATCH,
                MinimumResponse.DENY,
            )
        for field, code in (
            ("trajectory_id", ReasonCode.TRAJECTORY_LINEAGE_MISMATCH),
            ("trajectory_root_digest", ReasonCode.TRAJECTORY_LINEAGE_MISMATCH),
            ("authority_lineage_digest", ReasonCode.AUTHORITY_LINEAGE_CHANGED),
            ("principal_binding_digest", ReasonCode.PRINCIPAL_BINDING_CHANGED),
            ("agent_identity_digest", ReasonCode.AGENT_IDENTITY_CHANGED),
        ):
            if item.get(field) != previous.get(field):
                _add(reasons, responses, code, MinimumResponse.DENY)

    if item["authority_lineage_digest"] != expected_authority_lineage_digest:
        _add(
            reasons,
            responses,
            ReasonCode.AUTHORITY_LINEAGE_CHANGED,
            MinimumResponse.DENY,
        )

    target_ids = _identifier_list(item["target_ids"])
    if target_ids is None or item["target_set_digest"] != target_set_digest(target_ids or []):
        _add(
            reasons,
            responses,
            ReasonCode.TARGET_SET_DIGEST_MISMATCH,
            MinimumResponse.DENY,
        )
        target_ids = target_ids or []
    if not set(target_ids).issubset(set(authorized_target_ids)):
        _add(reasons, responses, ReasonCode.TARGET_SET_EXPANSION, MinimumResponse.DENY)

    action = item["action_observation"]
    if not isinstance(action, Mapping):
        action = {}
        _add(
            reasons,
            responses,
            ReasonCode.MANDATORY_EVIDENCE_MISSING,
            MinimumResponse.DENY,
        )

    previous_targets = set(previous_context.get("target_ids", [])) if previous_context else set()
    expanded_targets = set(target_ids) - previous_targets
    if previous_context and expanded_targets:
        if not action.get("target_expansion_authorized"):
            _add(reasons, responses, ReasonCode.TARGET_SET_EXPANSION, MinimumResponse.DENY)
        if not action.get("target_expansion_clearance_digest"):
            _add(
                reasons,
                responses,
                ReasonCode.TARGET_EXPANSION_EVIDENCE_MISSING,
                MinimumResponse.DENY,
            )

    if action.get("credential_provenance", "NOT_APPLICABLE") == "HARVESTED":
        _add(
            reasons,
            responses,
            ReasonCode.HARVESTED_CREDENTIAL_PROVENANCE,
            MinimumResponse.DENY,
        )
    if action.get("identity_provenance") == "SELF_CREATED_IN_TRAJECTORY":
        _add(reasons, responses, ReasonCode.SELF_CREATED_AUTHORITY, MinimumResponse.DENY)

    counters = item["cumulative_consequence"]
    ceilings = item["ceilings"]
    if not isinstance(counters, Mapping) or not isinstance(ceilings, Mapping):
        counters = {}
        ceilings = {}
        _add(
            reasons,
            responses,
            ReasonCode.MANDATORY_EVIDENCE_MISSING,
            MinimumResponse.DENY,
        )

    deltas = _action_deltas(action)
    previous_counters = (
        dict(previous_context.get("cumulative_consequence", {}))
        if previous_context
        else {field: 0 for field in _COUNTER_FIELDS}
    )
    for field in _COUNTER_FIELDS:
        try:
            actual = int(counters.get(field, -1))
            before = int(previous_counters.get(field, 0))
            ceiling = int(ceilings.get(field, -1))
        except (TypeError, ValueError):
            _add(
                reasons,
                responses,
                ReasonCode.MANDATORY_EVIDENCE_MISSING,
                MinimumResponse.DENY,
            )
            continue
        if actual < before:
            _add(reasons, responses, ReasonCode.COUNTER_REGRESSION, MinimumResponse.DENY)
        if actual != before + deltas[field]:
            _add(
                reasons,
                responses,
                ReasonCode.COUNTER_TRANSITION_MISMATCH,
                MinimumResponse.DENY,
            )
        if ceiling < 0 or actual > ceiling:
            _add(
                reasons,
                responses,
                ReasonCode.CUMULATIVE_CEILING_EXCEEDED,
                MinimumResponse.HALT,
            )

    evidence = item["evidence_bindings"]
    if not isinstance(evidence, Mapping):
        evidence = {}
        _add(
            reasons,
            responses,
            ReasonCode.MANDATORY_EVIDENCE_MISSING,
            MinimumResponse.DENY,
        )
    action_class = str(action.get("action_class", "GENERAL"))
    missing_evidence = [
        name for name in _HIGH_RISK_EVIDENCE.get(action_class, ()) if not evidence.get(name)
    ]
    if missing_evidence:
        code = (
            ReasonCode.DESTRUCTIVE_OBLIGATION_MISSING
            if action_class in {"DATA_ENCRYPT", "DATA_DELETE", "DATABASE_DROP"}
            else ReasonCode.MANDATORY_EVIDENCE_MISSING
        )
        _add(reasons, responses, code, MinimumResponse.DENY)

    if action.get("machine_speed_adaptive_retry"):
        _add(
            reasons,
            responses,
            ReasonCode.MACHINE_SPEED_ADAPTIVE_RETRY,
            MinimumResponse.STEP_UP,
        )

    observed_claims: list[str] = []
    unverified_claims: list[str] = []
    claims = action.get("claims", [])
    if not isinstance(claims, list):
        claims = []
        _add(
            reasons,
            responses,
            ReasonCode.MANDATORY_EVIDENCE_MISSING,
            MinimumResponse.DENY,
        )
    for claim in claims:
        if not isinstance(claim, Mapping):
            _add(
                reasons,
                responses,
                ReasonCode.MANDATORY_EVIDENCE_MISSING,
                MinimumResponse.DENY,
            )
            continue
        claim_type = str(claim.get("claim_type", "UNKNOWN"))
        if claim.get("verification_state") == "VERIFIED":
            if not claim.get("observed_evidence_digest"):
                _add(
                    reasons,
                    responses,
                    ReasonCode.VERIFIED_CLAIM_EVIDENCE_MISSING,
                    MinimumResponse.DENY,
                )
            else:
                observed_claims.append(claim_type)
        else:
            unverified_claims.append(claim_type)
            if claim_type == "EXFILTRATION":
                _add(
                    reasons,
                    responses,
                    ReasonCode.UNVERIFIED_EXFILTRATION_CLAIM,
                    MinimumResponse.STEP_UP,
                )

    if item.get("independent_halt") is True:
        _add(reasons, responses, ReasonCode.INDEPENDENT_HALT, MinimumResponse.HALT)

    return AAECValidationResult(
        validation_status=_status_for(reasons),
        minimum_response=_minimum_response(responses),
        reason_codes=tuple(sorted(code.value for code in reasons)),
        context_digest=str(item["context_digest"]),
        trajectory_id=str(item["trajectory_id"]),
        sequence_no=sequence_no,
        observed_claim_types=tuple(sorted(set(observed_claims))),
        unverified_claim_types=tuple(sorted(set(unverified_claims))),
    )
