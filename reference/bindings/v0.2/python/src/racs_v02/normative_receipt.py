"""Typed RACS v0.2 boundary receipt for normative non-execution outcomes."""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canonical import canonical_bytes
from .digest import sha256_digest


class BoundaryDecision(str, Enum):
    DEFER = "DEFER"
    STEP_UP = "STEP_UP"


class BoundaryAdmissibilityState(str, Enum):
    INDETERMINATE = "INDETERMINATE"
    REQUIRES_STEP_UP = "REQUIRES_STEP_UP"


class BoundaryDecisionReceiptV02(BaseModel):
    """Evidence that a boundary decision prevented execution.

    The receipt binds Research Factory, VAIG and REHT artifacts. The three false
    constants make it impossible to reinterpret the receipt as clearance,
    commit authorization or proof of execution.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    boundary_receipt_id: str
    tenant_id: str
    action_id: str
    action_envelope_digest: str
    decision: BoundaryDecision
    admissibility_state: BoundaryAdmissibilityState
    execution_occurred: Literal[False] = False
    clearance_issued: Literal[False] = False
    commit_token_issued: Literal[False] = False
    research_report_ref: str
    research_report_digest: str
    model_power_shadow_profile_digest: str
    counterposition_bundle_digest: Optional[str] = None
    adversarial_evaluation_digest: Optional[str] = None
    normative_scorecard_digest: str
    normative_influence_profile_digests: tuple[str, ...]
    vaig_evaluation_report_ref: str
    vaig_evaluation_report_digest: str
    vaig_normative_handoff_ref: str
    vaig_normative_handoff_digest: str
    reht_determination_ref: str
    reht_determination_digest: str
    reason_codes: tuple[str, ...]
    required_authority_class: Optional[str] = None
    recorded_at: str
    previous_receipt_hash: str

    @field_validator(
        "boundary_receipt_id",
        "tenant_id",
        "action_id",
        "research_report_ref",
        "vaig_evaluation_report_ref",
        "vaig_normative_handoff_ref",
        "reht_determination_ref",
        "recorded_at",
    )
    @classmethod
    def non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value

    @field_validator(
        "action_envelope_digest",
        "research_report_digest",
        "model_power_shadow_profile_digest",
        "counterposition_bundle_digest",
        "adversarial_evaluation_digest",
        "normative_scorecard_digest",
        "vaig_evaluation_report_digest",
        "vaig_normative_handoff_digest",
        "reht_determination_digest",
        "previous_receipt_hash",
    )
    @classmethod
    def valid_digest(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not _is_digest(normalized):
            raise ValueError("must be a RACS SHA-256 digest")
        return normalized

    @field_validator("normative_influence_profile_digests")
    @classmethod
    def valid_profile_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(dict.fromkeys(value.strip().lower() for value in values))
        if not normalized or any(not _is_digest(value) for value in normalized):
            raise ValueError("normative influence profile digests are required")
        return normalized

    @field_validator("reason_codes")
    @classmethod
    def valid_reason_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(dict.fromkeys(value.strip() for value in values if value.strip()))
        if not normalized:
            raise ValueError("at least one reason code is required")
        return normalized

    @model_validator(mode="after")
    def decision_state_pair(self) -> "BoundaryDecisionReceiptV02":
        expected = {
            BoundaryDecision.DEFER: BoundaryAdmissibilityState.INDETERMINATE,
            BoundaryDecision.STEP_UP: BoundaryAdmissibilityState.REQUIRES_STEP_UP,
        }[self.decision]
        if self.admissibility_state is not expected:
            raise ValueError("decision and admissibility_state mismatch")
        if self.decision is BoundaryDecision.STEP_UP:
            if not str(self.required_authority_class or "").strip():
                raise ValueError("STEP_UP requires required_authority_class")
        elif self.required_authority_class is not None:
            raise ValueError("DEFER cannot bind required_authority_class")
        return self

    def model_canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json", exclude_none=True))

    def model_digest(self) -> str:
        return sha256_digest(self.model_dump(mode="json", exclude_none=True))


def _is_digest(value: str) -> bool:
    if not value.startswith("sha256:"):
        return False
    suffix = value[7:]
    return len(suffix) == 64 and all(character in "0123456789abcdef" for character in suffix)
