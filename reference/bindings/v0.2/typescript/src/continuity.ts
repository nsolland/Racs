import * as jcs from "json-canonicalize";
import { createHash } from "node:crypto";

function digestPayload(value: unknown): string {
  const canonical = jcs.canonicalize(value);
  return "sha256:" + createHash("sha256").update(Buffer.from(canonical, "utf-8")).digest("hex");
}

abstract class ContinuityPayload {
  canonical(): string { return jcs.canonicalize(this); }
  digest(): string { return digestPayload(this); }
}

export type ExecutorType =
  | "PROCESS" | "WORKFLOW" | "BROWSER" | "DEVICE" | "ROBOT" | "OTHER";
export type HumanPresenceMode = "NONE_EXPECTED" | "POSSIBLE" | "SHARED" | "REQUIRED";
export type FailClosedPolicy = "PAUSE" | "HALT";
export type SessionState =
  | "PREPARED" | "ACTIVE" | "PAUSED" | "REAUTHORIZATION_REQUIRED"
  | "RECOVERY_PENDING" | "ROLLING_BACK" | "HANDED_OVER" | "COMPLETED"
  | "FAILED" | "STOPPED" | "HALTED";
export type ObservationSourceType =
  | "SENSOR" | "CONTROLLER" | "CONNECTOR" | "DESTINATION_SYSTEM"
  | "WATCHER" | "AGENT_SELF_REPORT" | "HUMAN" | "OTHER";
export type SignalClass =
  | "PROGRESS" | "POSITION_OR_STATE" | "FORCE" | "SPEED" | "RATE"
  | "COST" | "RESOURCE_USE" | "HUMAN_PROXIMITY" | "PROTECTED_ZONE"
  | "RETRY_COUNT" | "LOOP_COUNT" | "SIDE_EFFECT" | "ENVIRONMENT_CHANGE"
  | "POSTCONDITION" | "TELEMETRY_HEALTH" | "WATCHER_HEALTH" | "OTHER";
export type ObservationQuality =
  | "PRESENT_AND_VALID" | "DEGRADED" | "STALE" | "MISSING"
  | "UNVERIFIED" | "CONFLICTING";
export type ContinuityDecisionType =
  | "CONTINUE" | "MODIFY_RUNTIME_BOUNDS" | "PAUSE" | "STOP"
  | "REAUTHORIZE" | "ROLLBACK" | "HANDOVER" | "HALT";
export type InterventionType =
  | "MODIFY_RUNTIME_BOUNDS" | "PAUSE" | "STOP" | "REAUTHORIZE"
  | "ROLLBACK" | "HANDOVER" | "HALT";
export type InterventionResult = "APPLIED" | "PARTIAL" | "FAILED" | "NOT_APPLICABLE";
export type RecoveryResult = "SUCCEEDED" | "PARTIAL" | "FAILED";
export type RecoveryNextState =
  | "ACTIVE" | "PAUSED" | "REAUTHORIZATION_REQUIRED"
  | "COMPLETED" | "STOPPED" | "HALTED";
export type ConsequenceClass = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Reversibility = "REVERSIBLE" | "COMPENSATABLE" | "IRREVERSIBLE";

export interface ProgressContract { phases: string[]; heartbeat_required: boolean; }
export interface CompletionContract {
  terminal_states: string[];
  postcondition_evidence_required: boolean;
}
export interface ExecutorBinding { executor_type: ExecutorType; allowed_executor_ids: string[]; }
export interface RecoveryBudget { max_duration_ms: number; max_attempts: number; }

export class GovernedCapabilityManifest extends ContinuityPayload {
  schema_version!: "racs.governed-capability-manifest.v0.2";
  capability_id!: string;
  capability_version!: string;
  publisher_id!: string;
  artifact_digest!: string;
  interface_digest!: string;
  input_schema_digest!: string;
  output_schema_digest!: string;
  preconditions!: string[];
  postconditions!: string[];
  permissions!: string[];
  consequence_classes!: ConsequenceClass[];
  risk_class!: ConsequenceClass;
  reversibility!: Reversibility;
  rollback_capability_ref?: string;
  environment_profile_refs!: string[];
  telemetry_contract_ref!: string;
  progress_contract!: ProgressContract;
  completion_contract!: CompletionContract;
  timeout_ms!: number;
  retry_budget!: number;
  executor_binding!: ExecutorBinding;
  controller_or_model_digest!: string;
  supply_chain_attestation_ref!: string;
  issued_at!: string;
  expires_at!: string;
}

export class EnvironmentGovernanceProfile extends ContinuityPayload {
  schema_version!: "racs.environment-governance-profile.v0.2";
  profile_id!: string;
  profile_version!: string;
  environment_id!: string;
  tenant_id!: string;
  legal_entity_id!: string;
  zone!: string;
  human_presence_mode!: HumanPresenceMode;
  allowed_consequence_classes!: ConsequenceClass[];
  runtime_limits!: Record<string, string | number | boolean>;
  forbidden_zones_or_resources!: string[];
  required_telemetry!: string[];
  required_interlocks!: string[];
  required_human_roles!: string[];
  fail_closed_policy!: FailClosedPolicy;
  valid_from!: string;
  expires_at!: string;
}

export class GovernedExecutionSession extends ContinuityPayload {
  schema_version!: "racs.governed-execution-session.v0.2";
  session_id!: string;
  action_envelope_digest!: string;
  authority_digest!: string;
  capability_manifest_digest!: string;
  environment_profile_digest!: string;
  governance_evaluation_digest!: string;
  reht_clearance_digest!: string;
  racs_decision_digest!: string;
  execution_permit_digest!: string;
  principal_id!: string;
  actor_id!: string;
  executor_id!: string;
  workflow_id?: string;
  parent_session_id?: string;
  started_at!: string;
  must_complete_by!: string;
  heartbeat_interval_ms!: number;
  last_heartbeat_at!: string;
  session_state!: SessionState;
  continuity_sequence!: number;
  previous_continuity_receipt_digest?: string;
}

export class RuntimeObservation extends ContinuityPayload {
  schema_version!: "racs.runtime-observation.v0.2";
  observation_id!: string;
  session_id!: string;
  sequence!: number;
  timestamp_ns!: string;
  source_id!: string;
  source_type!: ObservationSourceType;
  signal_class!: SignalClass;
  signal_value?: unknown;
  signal_digest?: string;
  quality!: ObservationQuality;
  uncertainty?: Record<string, unknown>;
  freshness_ms!: number;
  integrity_attestation_ref!: string;
  environment_profile_digest!: string;
  previous_observation_digest?: string;
}

export class ContinuityDecision extends ContinuityPayload {
  schema_version!: "racs.continuity-decision.v0.2";
  decision_id!: string;
  session_id!: string;
  continuity_sequence!: number;
  action_envelope_digest!: string;
  capability_manifest_digest!: string;
  environment_profile_digest!: string;
  observation_bundle_digest!: string;
  policy_digest!: string;
  authority_state_digest!: string;
  decision!: ContinuityDecisionType;
  constraints?: Record<string, unknown>;
  reason_codes!: string[];
  valid_until!: string;
  next_review_at!: string;
  racs_contract_version!: "0.2";
}

export class InterventionReceipt extends ContinuityPayload {
  schema_version!: "racs.intervention-receipt.v0.2";
  intervention_id!: string;
  session_id!: string;
  continuity_decision_digest!: string;
  intervention_type!: InterventionType;
  requested_at!: string;
  applied_at!: string;
  executor_id!: string;
  pre_state_digest!: string;
  post_state_digest!: string;
  result!: InterventionResult;
  failure_reason?: string;
  previous_receipt_digest?: string;
}

export class RecoveryPlan extends ContinuityPayload {
  schema_version!: "racs.recovery-plan.v0.2";
  recovery_plan_id!: string;
  source_session_id!: string;
  source_incident_or_intervention_ref!: string;
  recovery_capability_manifest_digest!: string;
  recovery_action_envelope_digest!: string;
  rollback_authority_digest!: string;
  safe_target_state_digest!: string;
  recovery_budget!: RecoveryBudget;
  termination_conditions!: string[];
  fallback_halt_condition!: string;
  required_human_roles!: string[];
  carries_execution_authority!: false;
}

export class RecoveryReceipt extends ContinuityPayload {
  schema_version!: "racs.recovery-receipt.v0.2";
  recovery_receipt_id!: string;
  recovery_plan_digest!: string;
  source_session_id!: string;
  recovery_session_id!: string;
  intervention_receipt_digest!: string;
  started_at!: string;
  completed_at!: string;
  result!: RecoveryResult;
  postcondition_evidence_digest!: string;
  unresolved_effects!: string[];
  next_state!: RecoveryNextState;
  previous_receipt_digest?: string;
}
