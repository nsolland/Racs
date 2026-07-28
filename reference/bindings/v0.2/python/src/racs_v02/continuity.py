"""RACS v0.2 runtime-continuity typed payload bindings.

These models extend the existing signed-artifact chain for active, multi-transition
or embodied execution. They are payload types only: capability admission,
observations, continuity decisions and recovery plans never create authority.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_bytes
from .digest import sha256_digest
from .models import ConsequenceClass, Reversibility

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class ContinuityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    def model_canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json", exclude_none=True))

    def model_digest(self) -> str:
        return sha256_digest(self.model_dump(mode="json", exclude_none=True))


class ExecutorType(str, Enum):
    PROCESS = "PROCESS"
    WORKFLOW = "WORKFLOW"
    BROWSER = "BROWSER"
    DEVICE = "DEVICE"
    ROBOT = "ROBOT"
    OTHER = "OTHER"


class HumanPresenceMode(str, Enum):
    NONE_EXPECTED = "NONE_EXPECTED"
    POSSIBLE = "POSSIBLE"
    SHARED = "SHARED"
    REQUIRED = "REQUIRED"


class FailClosedPolicy(str, Enum):
    PAUSE = "PAUSE"
    HALT = "HALT"


class SessionState(str, Enum):
    PREPARED = "PREPARED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    REAUTHORIZATION_REQUIRED = "REAUTHORIZATION_REQUIRED"
    RECOVERY_PENDING = "RECOVERY_PENDING"
    ROLLING_BACK = "ROLLING_BACK"
    HANDED_OVER = "HANDED_OVER"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"
    HALTED = "HALTED"


class ObservationSourceType(str, Enum):
    SENSOR = "SENSOR"
    CONTROLLER = "CONTROLLER"
    CONNECTOR = "CONNECTOR"
    DESTINATION_SYSTEM = "DESTINATION_SYSTEM"
    WATCHER = "WATCHER"
    AGENT_SELF_REPORT = "AGENT_SELF_REPORT"
    HUMAN = "HUMAN"
    OTHER = "OTHER"


class SignalClass(str, Enum):
    PROGRESS = "PROGRESS"
    POSITION_OR_STATE = "POSITION_OR_STATE"
    FORCE = "FORCE"
    SPEED = "SPEED"
    RATE = "RATE"
    COST = "COST"
    RESOURCE_USE = "RESOURCE_USE"
    HUMAN_PROXIMITY = "HUMAN_PROXIMITY"
    PROTECTED_ZONE = "PROTECTED_ZONE"
    RETRY_COUNT = "RETRY_COUNT"
    LOOP_COUNT = "LOOP_COUNT"
    SIDE_EFFECT = "SIDE_EFFECT"
    ENVIRONMENT_CHANGE = "ENVIRONMENT_CHANGE"
    POSTCONDITION = "POSTCONDITION"
    TELEMETRY_HEALTH = "TELEMETRY_HEALTH"
    WATCHER_HEALTH = "WATCHER_HEALTH"
    OTHER = "OTHER"


class ObservationQuality(str, Enum):
    PRESENT_AND_VALID = "PRESENT_AND_VALID"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    MISSING = "MISSING"
    UNVERIFIED = "UNVERIFIED"
    CONFLICTING = "CONFLICTING"


class ContinuityDecisionType(str, Enum):
    CONTINUE = "CONTINUE"
    MODIFY_RUNTIME_BOUNDS = "MODIFY_RUNTIME_BOUNDS"
    PAUSE = "PAUSE"
    STOP = "STOP"
    REAUTHORIZE = "REAUTHORIZE"
    ROLLBACK = "ROLLBACK"
    HANDOVER = "HANDOVER"
    HALT = "HALT"


class InterventionType(str, Enum):
    MODIFY_RUNTIME_BOUNDS = "MODIFY_RUNTIME_BOUNDS"
    PAUSE = "PAUSE"
    STOP = "STOP"
    REAUTHORIZE = "REAUTHORIZE"
    ROLLBACK = "ROLLBACK"
    HANDOVER = "HANDOVER"
    HALT = "HALT"


class InterventionResult(str, Enum):
    APPLIED = "APPLIED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RecoveryResult(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class RecoveryNextState(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    REAUTHORIZATION_REQUIRED = "REAUTHORIZATION_REQUIRED"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    HALTED = "HALTED"


class ProgressContract(ContinuityModel):
    phases: List[str] = Field(min_length=1)
    heartbeat_required: bool


class CompletionContract(ContinuityModel):
    terminal_states: List[str] = Field(min_length=1)
    postcondition_evidence_required: bool


class ExecutorBinding(ContinuityModel):
    executor_type: ExecutorType
    allowed_executor_ids: List[str] = Field(min_length=1)


class RecoveryBudget(ContinuityModel):
    max_duration_ms: int = Field(ge=1)
    max_attempts: int = Field(ge=1)


class GovernedCapabilityManifest(ContinuityModel):
    schema_version: str = Field(pattern=r"^racs\.governed-capability-manifest\.v0\.2$")
    capability_id: str
    capability_version: str
    publisher_id: str
    artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    interface_digest: str = Field(pattern=_DIGEST_PATTERN)
    input_schema_digest: str = Field(pattern=_DIGEST_PATTERN)
    output_schema_digest: str = Field(pattern=_DIGEST_PATTERN)
    preconditions: List[str] = Field(default_factory=list)
    postconditions: List[str] = Field(min_length=1)
    permissions: List[str] = Field(min_length=1)
    consequence_classes: List[ConsequenceClass] = Field(min_length=1)
    risk_class: ConsequenceClass
    reversibility: Reversibility
    rollback_capability_ref: Optional[str] = None
    environment_profile_refs: List[str] = Field(min_length=1)
    telemetry_contract_ref: str
    progress_contract: ProgressContract
    completion_contract: CompletionContract
    timeout_ms: int = Field(ge=1)
    retry_budget: int = Field(ge=0)
    executor_binding: ExecutorBinding
    controller_or_model_digest: str = Field(pattern=_DIGEST_PATTERN)
    supply_chain_attestation_ref: str
    issued_at: str
    expires_at: str

    @model_validator(mode="after")
    def validate_manifest(self) -> "GovernedCapabilityManifest":
        if self.reversibility is Reversibility.REVERSIBLE and not self.rollback_capability_ref:
            raise ValueError("REVERSIBLE capability requires rollback_capability_ref")
        if _parse_time(self.expires_at) <= _parse_time(self.issued_at):
            raise ValueError("expires_at must be later than issued_at")
        return self


class EnvironmentGovernanceProfile(ContinuityModel):
    schema_version: str = Field(pattern=r"^racs\.environment-governance-profile\.v0\.2$")
    profile_id: str
    profile_version: str
    environment_id: str
    tenant_id: str
    legal_entity_id: str
    zone: str
    human_presence_mode: HumanPresenceMode
    allowed_consequence_classes: List[ConsequenceClass] = Field(min_length=1)
    runtime_limits: Dict[str, Any]
    forbidden_zones_or_resources: List[str] = Field(default_factory=list)
    required_telemetry: List[str] = Field(min_length=1)
    required_interlocks: List[str] = Field(default_factory=list)
    required_human_roles: List[str] = Field(default_factory=list)
    fail_closed_policy: FailClosedPolicy
    valid_from: str
    expires_at: str

    @model_validator(mode="after")
    def validate_profile(self) -> "EnvironmentGovernanceProfile":
        if not self.runtime_limits:
            raise ValueError("runtime_limits must not be empty")
        if _parse_time(self.expires_at) <= _parse_time(self.valid_from):
            raise ValueError("expires_at must be later than valid_from")
        return self


class GovernedExecutionSession(ContinuityModel):
    schema_version: str = Field(pattern=r"^racs\.governed-execution-session\.v0\.2$")
    session_id: str
    action_envelope_digest: str = Field(pattern=_DIGEST_PATTERN)
    authority_digest: str = Field(pattern=_DIGEST_PATTERN)
    capability_manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    environment_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    governance_evaluation_digest: str = Field(pattern=_DIGEST_PATTERN)
    reht_clearance_digest: str = Field(pattern=_DIGEST_PATTERN)
    racs_decision_digest: str = Field(pattern=_DIGEST_PATTERN)
    execution_permit_digest: str = Field(pattern=_DIGEST_PATTERN)
    principal_id: str
    actor_id: str
    executor_id: str
    workflow_id: Optional[str] = None
    parent_session_id: Optional[str] = None
    started_at: str
    must_complete_by: str
    heartbeat_interval_ms: int = Field(ge=1)
    last_heartbeat_at: str
    session_state: SessionState
    continuity_sequence: int = Field(ge=0)
    previous_continuity_receipt_digest: Optional[str] = Field(
        default=None, pattern=_DIGEST_PATTERN
    )

    @model_validator(mode="after")
    def validate_session(self) -> "GovernedExecutionSession":
        started = _parse_time(self.started_at)
        if _parse_time(self.must_complete_by) <= started:
            raise ValueError("must_complete_by must be later than started_at")
        heartbeat = _parse_time(self.last_heartbeat_at)
        if heartbeat < started or heartbeat > _parse_time(self.must_complete_by):
            raise ValueError("last_heartbeat_at outside session lifetime")
        return self


class RuntimeObservation(ContinuityModel):
    schema_version: str = Field(pattern=r"^racs\.runtime-observation\.v0\.2$")
    observation_id: str
    session_id: str
    sequence: int = Field(ge=0)
    timestamp_ns: str = Field(pattern=r"^[0-9]+$")
    source_id: str
    source_type: ObservationSourceType
    signal_class: SignalClass
    signal_value: Optional[Any] = None
    signal_digest: Optional[str] = Field(default=None, pattern=_DIGEST_PATTERN)
    quality: ObservationQuality
    uncertainty: Optional[Dict[str, Any]] = None
    freshness_ms: int = Field(ge=0)
    integrity_attestation_ref: str
    environment_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    previous_observation_digest: Optional[str] = Field(default=None, pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_signal_binding(self) -> "RuntimeObservation":
        has_value = self.signal_value is not None
        has_digest = self.signal_digest is not None
        if has_value == has_digest:
            raise ValueError("exactly one of signal_value or signal_digest is required")
        return self


class ContinuityDecision(ContinuityModel):
    schema_version: str = Field(pattern=r"^racs\.continuity-decision\.v0\.2$")
    decision_id: str
    session_id: str
    continuity_sequence: int = Field(ge=1)
    action_envelope_digest: str = Field(pattern=_DIGEST_PATTERN)
    capability_manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    environment_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    observation_bundle_digest: str = Field(pattern=_DIGEST_PATTERN)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    authority_state_digest: str = Field(pattern=_DIGEST_PATTERN)
    decision: ContinuityDecisionType
    constraints: Optional[Dict[str, Any]] = None
    reason_codes: List[str] = Field(default_factory=list)
    valid_until: str
    next_review_at: str
    racs_contract_version: str = Field(pattern=r"^0\.2$")

    @model_validator(mode="after")
    def validate_decision_constraints(self) -> "ContinuityDecision":
        if self.decision is ContinuityDecisionType.MODIFY_RUNTIME_BOUNDS:
            if not self.constraints:
                raise ValueError("MODIFY_RUNTIME_BOUNDS requires constraints")
        if self.decision is ContinuityDecisionType.CONTINUE and self.constraints is not None:
            raise ValueError("CONTINUE cannot add constraints")
        if _parse_time(self.next_review_at) > _parse_time(self.valid_until):
            raise ValueError("next_review_at cannot be later than valid_until")
        return self


class InterventionReceipt(ContinuityModel):
    schema_version: str = Field(pattern=r"^racs\.intervention-receipt\.v0\.2$")
    intervention_id: str
    session_id: str
    continuity_decision_digest: str = Field(pattern=_DIGEST_PATTERN)
    intervention_type: InterventionType
    requested_at: str
    applied_at: str
    executor_id: str
    pre_state_digest: str = Field(pattern=_DIGEST_PATTERN)
    post_state_digest: str = Field(pattern=_DIGEST_PATTERN)
    result: InterventionResult
    failure_reason: Optional[str] = None
    previous_receipt_digest: Optional[str] = Field(default=None, pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_intervention(self) -> "InterventionReceipt":
        if _parse_time(self.applied_at) < _parse_time(self.requested_at):
            raise ValueError("applied_at cannot precede requested_at")
        if self.result in {InterventionResult.PARTIAL, InterventionResult.FAILED}:
            if not self.failure_reason:
                raise ValueError("partial or failed intervention requires failure_reason")
        return self


class RecoveryPlan(ContinuityModel):
    schema_version: str = Field(pattern=r"^racs\.recovery-plan\.v0\.2$")
    recovery_plan_id: str
    source_session_id: str
    source_incident_or_intervention_ref: str
    recovery_capability_manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    recovery_action_envelope_digest: str = Field(pattern=_DIGEST_PATTERN)
    rollback_authority_digest: str = Field(pattern=_DIGEST_PATTERN)
    safe_target_state_digest: str = Field(pattern=_DIGEST_PATTERN)
    recovery_budget: RecoveryBudget
    termination_conditions: List[str] = Field(min_length=1)
    fallback_halt_condition: str
    required_human_roles: List[str] = Field(default_factory=list)
    carries_execution_authority: bool = False

    @model_validator(mode="after")
    def validate_evidence_only(self) -> "RecoveryPlan":
        if self.carries_execution_authority:
            raise ValueError("RecoveryPlan cannot carry execution authority")
        return self


class RecoveryReceipt(ContinuityModel):
    schema_version: str = Field(pattern=r"^racs\.recovery-receipt\.v0\.2$")
    recovery_receipt_id: str
    recovery_plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_session_id: str
    recovery_session_id: str
    intervention_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    started_at: str
    completed_at: str
    result: RecoveryResult
    postcondition_evidence_digest: str = Field(pattern=_DIGEST_PATTERN)
    unresolved_effects: List[str] = Field(default_factory=list)
    next_state: RecoveryNextState
    previous_receipt_digest: Optional[str] = Field(default=None, pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_recovery(self) -> "RecoveryReceipt":
        if _parse_time(self.completed_at) < _parse_time(self.started_at):
            raise ValueError("completed_at cannot precede started_at")
        if self.result is RecoveryResult.FAILED and self.next_state is not RecoveryNextState.HALTED:
            raise ValueError("failed recovery must leave the session HALTED")
        return self
