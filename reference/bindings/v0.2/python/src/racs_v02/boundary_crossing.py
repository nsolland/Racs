"""RACS v0.2 typed boundary-crossing assessment contracts.

Boundary assessments are evidence artifacts. They cannot authorize, clear, or execute
an action. Cross-artifact verification binds their exact payload digest into the
existing ActionEnvelope -> GovernanceEvaluation -> AdmissibilityDetermination chain.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_bytes
from .digest import sha256_digest

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_BOUNDARY_ORDER = {
    "EXECUTION": 0,
    "DISCLOSURE": 1,
    "MANDATE": 2,
    "RESOURCE": 3,
    "EVALUATION": 4,
}
_STATE_RANK = {
    "NO_CROSSING": 0,
    "AUTHORIZED": 1,
    "CONDITIONALLY_AUTHORIZED": 2,
    "INDETERMINATE": 3,
    "UNAUTHORIZED": 4,
    "STALE": 5,
    "REVOKED": 6,
}
_RESPONSE_RANK = {
    "NONE": 0,
    "MODIFY": 1,
    "DEFER": 2,
    "STEP_UP": 3,
    "DENY": 4,
    "HALT": 5,
}


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed


class BoundaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    def model_canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json", exclude_none=True))

    def model_digest(self) -> str:
        return sha256_digest(self.model_dump(mode="json", exclude_none=True))


class BoundaryType(str, Enum):
    EXECUTION = "EXECUTION"
    DISCLOSURE = "DISCLOSURE"
    MANDATE = "MANDATE"
    RESOURCE = "RESOURCE"
    EVALUATION = "EVALUATION"


class BoundaryState(str, Enum):
    NO_CROSSING = "NO_CROSSING"
    AUTHORIZED = "AUTHORIZED"
    CONDITIONALLY_AUTHORIZED = "CONDITIONALLY_AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"
    INDETERMINATE = "INDETERMINATE"
    STALE = "STALE"
    REVOKED = "REVOKED"


class BoundaryResponseFloor(str, Enum):
    NONE = "NONE"
    MODIFY = "MODIFY"
    DEFER = "DEFER"
    STEP_UP = "STEP_UP"
    DENY = "DENY"
    HALT = "HALT"


class ArtifactBinding(BoundaryModel):
    ref: str = Field(min_length=1)
    digest: str = Field(pattern=_DIGEST_PATTERN)


class BoundaryAssessmentBinding(BoundaryModel):
    assessment_ref: str = Field(min_length=1)
    assessment_digest: str = Field(pattern=_DIGEST_PATTERN)


class BoundaryRequirementSet(BoundaryModel):
    required_types: List[BoundaryType] = Field(min_length=1, max_length=5)
    policy_ref: str = Field(min_length=1)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    fail_closed: bool

    @model_validator(mode="after")
    def validate_requirements(self) -> "BoundaryRequirementSet":
        values = [item.value for item in self.required_types]
        if len(values) != len(set(values)):
            raise ValueError("required_types must be unique")
        if values != sorted(values, key=_BOUNDARY_ORDER.__getitem__):
            raise ValueError("required_types must use canonical boundary order")
        if self.fail_closed is not True:
            raise ValueError("boundary requirements must be fail_closed")
        return self


class BoundaryCrossing(BoundaryModel):
    crossing_id: str = Field(min_length=1)
    boundary_type: BoundaryType
    crossing_detected: bool
    prior_state_digest: str = Field(pattern=_DIGEST_PATTERN)
    proposed_state_digest: str = Field(pattern=_DIGEST_PATTERN)
    authority_requirement_ref: str = Field(min_length=1)
    authority_binding: Optional[ArtifactBinding] = None
    policy_binding: ArtifactBinding
    evidence_binding: ArtifactBinding
    resource_reservation_binding: Optional[ArtifactBinding] = None
    evaluation_provenance_binding: Optional[ArtifactBinding] = None
    details_digest: str = Field(pattern=_DIGEST_PATTERN)
    state: BoundaryState
    required_response_floor: BoundaryResponseFloor
    reason_codes: List[str] = Field(default_factory=list)
    observed_at: str
    valid_until: str

    @model_validator(mode="after")
    def validate_crossing(self) -> "BoundaryCrossing":
        observed = _parse_time(self.observed_at)
        valid_until = _parse_time(self.valid_until)
        if valid_until <= observed:
            raise ValueError("crossing valid_until must be after observed_at")
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("reason_codes must be unique")
        if self.reason_codes != sorted(self.reason_codes):
            raise ValueError("reason_codes must be sorted")

        changed = self.prior_state_digest != self.proposed_state_digest
        if self.crossing_detected != changed:
            raise ValueError("crossing_detected must equal state-digest change")

        if not self.crossing_detected:
            if self.state is not BoundaryState.NO_CROSSING:
                raise ValueError("non-crossing must use NO_CROSSING")
            if self.required_response_floor is not BoundaryResponseFloor.NONE:
                raise ValueError("non-crossing must use NONE response")
            if self.reason_codes:
                raise ValueError("non-crossing cannot carry reason codes")
            return self

        if self.state is BoundaryState.NO_CROSSING:
            raise ValueError("detected crossing cannot use NO_CROSSING")
        if self.state in {BoundaryState.AUTHORIZED, BoundaryState.CONDITIONALLY_AUTHORIZED}:
            if self.authority_binding is None:
                raise ValueError("authorized crossing requires authority_binding")
        if (
            self.state is BoundaryState.AUTHORIZED
            and self.required_response_floor is not BoundaryResponseFloor.NONE
        ):
            raise ValueError("AUTHORIZED crossing must use NONE response")
        if (
            self.state is BoundaryState.CONDITIONALLY_AUTHORIZED
            and self.required_response_floor is not BoundaryResponseFloor.MODIFY
        ):
            raise ValueError("CONDITIONALLY_AUTHORIZED crossing must use MODIFY response")
        if (
            self.state is BoundaryState.INDETERMINATE
            and _RESPONSE_RANK[self.required_response_floor.value] < _RESPONSE_RANK["DEFER"]
        ):
            raise ValueError("INDETERMINATE crossing requires DEFER or stronger")
        if (
            self.state is BoundaryState.UNAUTHORIZED
            and _RESPONSE_RANK[self.required_response_floor.value] < _RESPONSE_RANK["DENY"]
        ):
            raise ValueError("UNAUTHORIZED crossing requires DENY or HALT")
        if (
            self.state is BoundaryState.STALE
            and _RESPONSE_RANK[self.required_response_floor.value] < _RESPONSE_RANK["DEFER"]
        ):
            raise ValueError("STALE crossing requires DEFER or stronger")
        if (
            self.state is BoundaryState.REVOKED
            and _RESPONSE_RANK[self.required_response_floor.value] < _RESPONSE_RANK["DENY"]
        ):
            raise ValueError("REVOKED crossing requires DENY or HALT")

        reasons = set(self.reason_codes)
        if "TECHNICAL_ACCESS_ONLY" in reasons:
            if self.state is not BoundaryState.UNAUTHORIZED:
                raise ValueError("technical access alone cannot authorize execution")
            if self.required_response_floor not in {
                BoundaryResponseFloor.DENY,
                BoundaryResponseFloor.HALT,
            }:
                raise ValueError("technical access alone requires DENY or HALT")
        if (
            "UNAUTHORIZED_DISCOVERABILITY" in reasons
            and self.state is not BoundaryState.UNAUTHORIZED
        ):
            raise ValueError("unauthorized discoverability must be UNAUTHORIZED")
        if (
            "RESOURCE_LIMIT_EXCEEDED" in reasons
            and self.state is not BoundaryState.UNAUTHORIZED
        ):
            raise ValueError("resource limit exceeded must be UNAUTHORIZED")
        if (
            self.boundary_type is BoundaryType.RESOURCE
            and self.resource_reservation_binding is None
            and self.state
            in {BoundaryState.AUTHORIZED, BoundaryState.CONDITIONALLY_AUTHORIZED}
        ):
            raise ValueError("authorized resource crossing requires reservation binding")
        if (
            self.boundary_type is BoundaryType.EVALUATION
            and self.evaluation_provenance_binding is None
        ):
            raise ValueError("evaluation crossing requires provenance binding")
        return self


class BoundaryCrossingAssessment(BoundaryModel):
    schema_version: str = Field(
        pattern=r"^racs\.boundary-crossing-assessment\.v0\.2$"
    )
    assessment_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    action_envelope_digest: str = Field(pattern=_DIGEST_PATTERN)
    tenant_id: str = Field(min_length=1)
    assessor_id: str = Field(min_length=1)
    assessor_version: str = Field(min_length=1)
    requirement_policy_ref: str = Field(min_length=1)
    requirement_policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    crossings: List[BoundaryCrossing] = Field(min_length=1, max_length=5)
    aggregate_state: BoundaryState
    required_response_floor: BoundaryResponseFloor
    reason_codes: List[str] = Field(default_factory=list)
    assessed_at: str
    valid_until: str
    revocation_registry_ref: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_assessment(self) -> "BoundaryCrossingAssessment":
        assessed = _parse_time(self.assessed_at)
        valid_until = _parse_time(self.valid_until)
        if valid_until <= assessed:
            raise ValueError("assessment valid_until must be after assessed_at")

        types = [item.boundary_type.value for item in self.crossings]
        if len(types) != len(set(types)):
            raise ValueError("assessment cannot repeat boundary types")
        if types != sorted(types, key=_BOUNDARY_ORDER.__getitem__):
            raise ValueError("crossings must use canonical boundary order")
        ids = [item.crossing_id for item in self.crossings]
        if len(ids) != len(set(ids)):
            raise ValueError("crossing_id values must be unique")

        expected_state = max(
            (item.state for item in self.crossings),
            key=lambda item: _STATE_RANK[item.value],
        )
        expected_response = max(
            (item.required_response_floor for item in self.crossings),
            key=lambda item: _RESPONSE_RANK[item.value],
        )
        expected_reasons = sorted(
            {reason for item in self.crossings for reason in item.reason_codes}
        )
        if self.aggregate_state is not expected_state:
            raise ValueError("aggregate_state does not match crossings")
        if self.required_response_floor is not expected_response:
            raise ValueError("required_response_floor does not match crossings")
        if self.reason_codes != expected_reasons:
            raise ValueError("assessment reason_codes must equal sorted crossing union")
        return self


def response_floor_satisfied(
    response_floor: BoundaryResponseFloor,
    decision: str,
) -> bool:
    allowed = {
        "NONE": {"ALLOW", "MODIFY", "DEFER", "STEP_UP", "DENY", "HALT"},
        "MODIFY": {"MODIFY", "DEFER", "STEP_UP", "DENY", "HALT"},
        "DEFER": {"DEFER", "STEP_UP", "DENY", "HALT"},
        "STEP_UP": {"STEP_UP", "DENY", "HALT"},
        "DENY": {"DENY", "HALT"},
        "HALT": {"HALT"},
    }
    return decision in allowed[response_floor.value]
