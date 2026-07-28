//! RACS v0.2 runtime-continuity typed payload bindings.
//!
//! These payloads extend the existing signed-artifact chain for active,
//! multi-transition or embodied execution. They do not create authority.

use crate::{canonical_string, sha256_digest, ConsequenceClass, Reversibility};
use serde::{Deserialize, Serialize};
use std::error::Error;

pub trait ContinuityPayload: Serialize {
    fn canonical(&self) -> Result<String, Box<dyn Error>> {
        canonical_string(self)
    }

    fn digest(&self) -> Result<String, Box<dyn Error>> {
        sha256_digest(self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ExecutorType { Process, Workflow, Browser, Device, Robot, Other }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanPresenceMode { NoneExpected, Possible, Shared, Required }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FailClosedPolicy { Pause, Halt }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Prepared, Active, Paused, ReauthorizationRequired, RecoveryPending,
    RollingBack, HandedOver, Completed, Failed, Stopped, Halted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationSourceType {
    Sensor, Controller, Connector, DestinationSystem, Watcher,
    AgentSelfReport, Human, Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignalClass {
    Progress, PositionOrState, Force, Speed, Rate, Cost, ResourceUse,
    HumanProximity, ProtectedZone, RetryCount, LoopCount, SideEffect,
    EnvironmentChange, Postcondition, TelemetryHealth, WatcherHealth, Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationQuality { PresentAndValid, Degraded, Stale, Missing, Unverified, Conflicting }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContinuityDecisionType {
    Continue, ModifyRuntimeBounds, Pause, Stop, Reauthorize, Rollback, Handover, Halt,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InterventionType {
    ModifyRuntimeBounds, Pause, Stop, Reauthorize, Rollback, Handover, Halt,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InterventionResult { Applied, Partial, Failed, NotApplicable }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecoveryResult { Succeeded, Partial, Failed }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryNextState { Active, Paused, ReauthorizationRequired, Completed, Stopped, Halted }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProgressContract { pub phases: Vec<String>, pub heartbeat_required: bool }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompletionContract {
    pub terminal_states: Vec<String>,
    pub postcondition_evidence_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutorBinding {
    pub executor_type: ExecutorType,
    pub allowed_executor_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBudget { pub max_duration_ms: u64, pub max_attempts: u32 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GovernedCapabilityManifest {
    pub schema_version: String,
    pub capability_id: String,
    pub capability_version: String,
    pub publisher_id: String,
    pub artifact_digest: String,
    pub interface_digest: String,
    pub input_schema_digest: String,
    pub output_schema_digest: String,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub permissions: Vec<String>,
    pub consequence_classes: Vec<ConsequenceClass>,
    pub risk_class: ConsequenceClass,
    pub reversibility: Reversibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_capability_ref: Option<String>,
    pub environment_profile_refs: Vec<String>,
    pub telemetry_contract_ref: String,
    pub progress_contract: ProgressContract,
    pub completion_contract: CompletionContract,
    pub timeout_ms: u64,
    pub retry_budget: u32,
    pub executor_binding: ExecutorBinding,
    pub controller_or_model_digest: String,
    pub supply_chain_attestation_ref: String,
    pub issued_at: String,
    pub expires_at: String,
}
impl ContinuityPayload for GovernedCapabilityManifest {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentGovernanceProfile {
    pub schema_version: String,
    pub profile_id: String,
    pub profile_version: String,
    pub environment_id: String,
    pub tenant_id: String,
    pub legal_entity_id: String,
    pub zone: String,
    pub human_presence_mode: HumanPresenceMode,
    pub allowed_consequence_classes: Vec<ConsequenceClass>,
    pub runtime_limits: serde_json::Map<String, serde_json::Value>,
    pub forbidden_zones_or_resources: Vec<String>,
    pub required_telemetry: Vec<String>,
    pub required_interlocks: Vec<String>,
    pub required_human_roles: Vec<String>,
    pub fail_closed_policy: FailClosedPolicy,
    pub valid_from: String,
    pub expires_at: String,
}
impl ContinuityPayload for EnvironmentGovernanceProfile {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GovernedExecutionSession {
    pub schema_version: String,
    pub session_id: String,
    pub action_envelope_digest: String,
    pub authority_digest: String,
    pub capability_manifest_digest: String,
    pub environment_profile_digest: String,
    pub governance_evaluation_digest: String,
    pub reht_clearance_digest: String,
    pub racs_decision_digest: String,
    pub execution_permit_digest: String,
    pub principal_id: String,
    pub actor_id: String,
    pub executor_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    pub started_at: String,
    pub must_complete_by: String,
    pub heartbeat_interval_ms: u64,
    pub last_heartbeat_at: String,
    pub session_state: SessionState,
    pub continuity_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_continuity_receipt_digest: Option<String>,
}
impl ContinuityPayload for GovernedExecutionSession {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObservation {
    pub schema_version: String,
    pub observation_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub timestamp_ns: String,
    pub source_id: String,
    pub source_type: ObservationSourceType,
    pub signal_class: SignalClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_digest: Option<String>,
    pub quality: ObservationQuality,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncertainty: Option<serde_json::Value>,
    pub freshness_ms: u64,
    pub integrity_attestation_ref: String,
    pub environment_profile_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_observation_digest: Option<String>,
}
impl ContinuityPayload for RuntimeObservation {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContinuityDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub session_id: String,
    pub continuity_sequence: u64,
    pub action_envelope_digest: String,
    pub capability_manifest_digest: String,
    pub environment_profile_digest: String,
    pub observation_bundle_digest: String,
    pub policy_digest: String,
    pub authority_state_digest: String,
    pub decision: ContinuityDecisionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,
    pub reason_codes: Vec<String>,
    pub valid_until: String,
    pub next_review_at: String,
    pub racs_contract_version: String,
}
impl ContinuityPayload for ContinuityDecision {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InterventionReceipt {
    pub schema_version: String,
    pub intervention_id: String,
    pub session_id: String,
    pub continuity_decision_digest: String,
    pub intervention_type: InterventionType,
    pub requested_at: String,
    pub applied_at: String,
    pub executor_id: String,
    pub pre_state_digest: String,
    pub post_state_digest: String,
    pub result: InterventionResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_receipt_digest: Option<String>,
}
impl ContinuityPayload for InterventionReceipt {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPlan {
    pub schema_version: String,
    pub recovery_plan_id: String,
    pub source_session_id: String,
    pub source_incident_or_intervention_ref: String,
    pub recovery_capability_manifest_digest: String,
    pub recovery_action_envelope_digest: String,
    pub rollback_authority_digest: String,
    pub safe_target_state_digest: String,
    pub recovery_budget: RecoveryBudget,
    pub termination_conditions: Vec<String>,
    pub fallback_halt_condition: String,
    pub required_human_roles: Vec<String>,
    pub carries_execution_authority: bool,
}
impl ContinuityPayload for RecoveryPlan {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReceipt {
    pub schema_version: String,
    pub recovery_receipt_id: String,
    pub recovery_plan_digest: String,
    pub source_session_id: String,
    pub recovery_session_id: String,
    pub intervention_receipt_digest: String,
    pub started_at: String,
    pub completed_at: String,
    pub result: RecoveryResult,
    pub postcondition_evidence_digest: String,
    pub unresolved_effects: Vec<String>,
    pub next_state: RecoveryNextState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_receipt_digest: Option<String>,
}
impl ContinuityPayload for RecoveryReceipt {}
