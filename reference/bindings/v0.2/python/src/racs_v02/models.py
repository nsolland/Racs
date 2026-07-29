"""Typed model bindings for the RACS v0.2 contract schemas (stage 3B).

These are faithful, typed representations of the core v0.2 payload schemas.
They are pure data types plus canonicalization helpers and do not create authority.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .boundary_crossing import BoundaryAssessmentBinding
from .canonical import canonical_bytes
from .digest import sha256_digest


class Decision(str, Enum):
    ALLOW = "ALLOW"
    MODIFY = "MODIFY"
    DEFER = "DEFER"
    DENY = "DENY"
    STEP_UP = "STEP_UP"
    HALT = "HALT"


class Status(str, Enum):
    PRESENT_AND_VALID = "PRESENT_AND_VALID"
    PRESENT_BUT_INVALID = "PRESENT_BUT_INVALID"
    MISSING = "MISSING"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"
    REVOKED = "REVOKED"
    CONFLICTING = "CONFLICTING"


class AdmissibilityState(str, Enum):
    ADMISSIBLE = "ADMISSIBLE"
    CONDITIONALLY_ADMISSIBLE = "CONDITIONALLY_ADMISSIBLE"
    NOT_ADMISSIBLE = "NOT_ADMISSIBLE"
    INDETERMINATE = "INDETERMINATE"
    STALE = "STALE"
    REVOKED = "REVOKED"
    HALTED = "HALTED"
    REQUIRES_STEP_UP = "REQUIRES_STEP_UP"


class ConsequenceClass(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Reversibility(str, Enum):
    REVERSIBLE = "REVERSIBLE"
    COMPENSATABLE = "COMPENSATABLE"
    IRREVERSIBLE = "IRREVERSIBLE"


class TraceCompleteness(str, Enum):
    FULL_VISIBLE_CONTEXT = "FULL_VISIBLE_CONTEXT"
    PARTIAL_VISIBLE_CONTEXT = "PARTIAL_VISIBLE_CONTEXT"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


class ReasoningTraceBinding(BaseModel):
    """Audit binding for visible model traces. Never authority for clearance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authoritative_for_clearance: Literal[False]
    trace_completeness: TraceCompleteness
    model_context_digest: Optional[str] = None
    prefill_digest: Optional[str] = None
    model_config_digest: Optional[str] = None
    generated_token_ranges_digest: Optional[str] = None
    trace_ref: Optional[str] = None


class EvaluationBinding(BaseModel):
    """Cryptographic binding to a signed GovernanceEvaluation payload."""

    model_config = ConfigDict(extra="forbid")

    evaluation_ref: str
    evaluation_digest: str


class GovernanceEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluation_id: str
    action_id: str
    action_envelope_digest: str
    tenant_id: str
    evaluator_id: str
    evaluator_version: str
    decision: Decision
    authority_status: Status
    policy_status: Status
    evidence_status: Status
    purpose_status: Status
    state_status: Status
    risk_status: Status
    reason_codes: List[str] = Field(default_factory=list)
    constraints: Optional[Dict[str, Any]] = None
    boundary_assessment_binding: BoundaryAssessmentBinding
    reasoning_authority: Optional[Literal[False]] = None
    reasoning_trace_binding: Optional[ReasoningTraceBinding] = None
    evaluated_at: str
    valid_until: str

    @model_validator(mode="after")
    def missing_authority_fails_closed(self) -> "GovernanceEvaluation":
        if self.authority_status is Status.MISSING and self.decision not in {
            Decision.DENY,
            Decision.HALT,
        }:
            raise ValueError("MISSING authority requires DENY or HALT")
        return self

    def model_canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json", exclude_none=True))

    def model_digest(self) -> str:
        return sha256_digest(self.model_dump(mode="json", exclude_none=True))


class AdmissibilityDetermination(BaseModel):
    model_config = ConfigDict(extra="forbid")

    determination_id: str
    action_id: str
    action_envelope_digest: str
    tenant_id: str
    authority_digest: str
    delegation_chain_digest: str
    policy_digest: str
    evidence_digest: str
    purpose_digest: str
    state_digest: str
    evaluation_bindings: List[EvaluationBinding]
    boundary_assessment_binding: BoundaryAssessmentBinding
    state: AdmissibilityState
    conditions: Optional[Dict[str, Any]] = None
    reason_codes: List[str] = Field(default_factory=list)
    determined_at: str
    valid_until: str
    revocation_registry_ref: str

    def model_canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json", exclude_none=True))

    def model_digest(self) -> str:
        return sha256_digest(self.model_dump(mode="json", exclude_none=True))


class GovernanceClearance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clearance_id: str
    action_id: str
    action_envelope_digest: str
    tenant_id: str
    decision: Decision
    admissibility_state: AdmissibilityState
    authority_digest: str
    delegation_chain_digest: str
    policy_digest: str
    evidence_digest: str
    purpose_digest: str
    state_digest: str
    target_digest: str
    payload_digest: str
    connector_id: str
    capability: str
    consequence_class: ConsequenceClass
    reversibility: Reversibility
    constraints: Optional[Dict[str, Any]] = None
    valid_from: str
    valid_until: str
    replay_nonce: str
    idempotency_key: str
    revocation_registry_ref: str
    evaluator_refs: List[str]
    admissibility_determination_ref: str
    admissibility_determination_digest: str

    def model_canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json", exclude_none=True))

    def model_digest(self) -> str:
        return sha256_digest(self.model_dump(mode="json", exclude_none=True))
