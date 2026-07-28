import * as jcs from "json-canonicalize";
import { createHash } from "node:crypto";
import type { BoundaryAssessmentBinding } from "./boundary-crossing.js";

export interface Canonicalizable {
  canonical(): string;
  digest(): string;
}

export function canonicalString(value: unknown): string {
  return jcs.canonicalize(value);
}

export function sha256Digest(value: unknown): string {
  const canon = jcs.canonicalize(value);
  return "sha256:" + createHash("sha256").update(Buffer.from(canon, "utf-8")).digest("hex");
}

export type Decision =
  | "ALLOW" | "MODIFY" | "DEFER" | "DENY" | "STEP_UP" | "HALT";
export type Status =
  | "PRESENT_AND_VALID" | "PRESENT_BUT_INVALID" | "MISSING" | "UNKNOWN"
  | "UNAVAILABLE" | "STALE" | "REVOKED" | "CONFLICTING";
export type AdmissibilityState =
  | "ADMISSIBLE" | "CONDITIONALLY_ADMISSIBLE" | "NOT_ADMISSIBLE"
  | "INDETERMINATE" | "STALE" | "REVOKED" | "HALTED" | "REQUIRES_STEP_UP";
export type ConsequenceClass = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Reversibility = "REVERSIBLE" | "COMPENSATABLE" | "IRREVERSIBLE";

export interface EvaluationBinding {
  evaluation_ref: string;
  evaluation_digest: string;
}

export class GovernanceEvaluation implements Canonicalizable {
  evaluation_id!: string;
  action_id!: string;
  action_envelope_digest!: string;
  tenant_id!: string;
  evaluator_id!: string;
  evaluator_version!: string;
  decision!: Decision;
  authority_status!: Status;
  policy_status!: Status;
  evidence_status!: Status;
  purpose_status!: Status;
  state_status!: Status;
  risk_status!: Status;
  reason_codes?: string[];
  constraints?: unknown;
  boundary_assessment_binding!: BoundaryAssessmentBinding;
  evaluated_at!: string;
  valid_until!: string;
  canonical(): string { return jcs.canonicalize(this); }
  digest(): string { return sha256Digest(this); }
}

export class AdmissibilityDetermination implements Canonicalizable {
  determination_id!: string;
  action_id!: string;
  action_envelope_digest!: string;
  tenant_id!: string;
  authority_digest!: string;
  delegation_chain_digest!: string;
  policy_digest!: string;
  evidence_digest!: string;
  purpose_digest!: string;
  state_digest!: string;
  evaluation_bindings!: EvaluationBinding[];
  boundary_assessment_binding!: BoundaryAssessmentBinding;
  state!: AdmissibilityState;
  conditions?: unknown;
  reason_codes?: string[];
  determined_at!: string;
  valid_until!: string;
  revocation_registry_ref!: string;
  canonical(): string { return jcs.canonicalize(this); }
  digest(): string { return sha256Digest(this); }
}

export class GovernanceClearance implements Canonicalizable {
  clearance_id!: string;
  action_id!: string;
  action_envelope_digest!: string;
  tenant_id!: string;
  decision!: Decision;
  admissibility_state!: AdmissibilityState;
  authority_digest!: string;
  delegation_chain_digest!: string;
  policy_digest!: string;
  evidence_digest!: string;
  purpose_digest!: string;
  state_digest!: string;
  target_digest!: string;
  payload_digest!: string;
  connector_id!: string;
  capability!: string;
  consequence_class!: ConsequenceClass;
  reversibility!: Reversibility;
  constraints?: unknown;
  valid_from!: string;
  valid_until!: string;
  replay_nonce!: string;
  idempotency_key!: string;
  revocation_registry_ref!: string;
  evaluator_refs!: string[];
  admissibility_determination_ref!: string;
  admissibility_determination_digest!: string;
  canonical(): string { return jcs.canonicalize(this); }
  digest(): string { return sha256Digest(this); }
}

export * from "./boundary-crossing.js";
export * from "./boundary-validation.js";
export * from "./continuity.js";
export {
  REASON_SESSION_TERMINAL,
  REASON_SESSION_ACTION_ENVELOPE_MISMATCH,
  REASON_SESSION_AUTHORITY_MISMATCH,
  REASON_SESSION_CAPABILITY_MANIFEST_MISMATCH,
  REASON_SESSION_ENVIRONMENT_PROFILE_MISMATCH,
  REASON_SESSION_EVALUATION_MISMATCH,
  REASON_SESSION_CLEARANCE_MISMATCH,
  REASON_SESSION_TENANT_MISMATCH,
  REASON_SESSION_EXECUTOR_NOT_ALLOWED,
  REASON_SESSION_CAPABILITY_NOT_PERMITTED,
  REASON_SESSION_CONSEQUENCE_NOT_ALLOWED,
  REASON_SESSION_PROFILE_NOT_REFERENCED,
  REASON_SESSION_CLEARANCE_NOT_EXECUTABLE,
  REASON_SESSION_ARTIFACT_NOT_CURRENT,
  REASON_SESSION_DEADLINE_EXCEEDS_AUTHORIZATION,
  REASON_BOUNDS_NARROWED,
  REASON_BOUNDS_WIDENED,
  REASON_BOUNDS_UNPROVABLE,
  REASON_BOUNDS_NOT_NARROWER,
  REASON_DECISION_SESSION_MISMATCH,
  REASON_DECISION_SEQUENCE_MISMATCH,
  REASON_DECISION_ACTION_MISMATCH,
  REASON_DECISION_CAPABILITY_MISMATCH,
  REASON_DECISION_ENVIRONMENT_MISMATCH,
  REASON_DECISION_AUTHORITY_MISMATCH,
  REASON_DECISION_EXPIRED,
  REASON_DECISION_OUTLIVES_SESSION,
  verifyExecutionSession,
  proveRuntimeBoundsNarrowing,
  verifyContinuityDecision,
} from "./continuity-verification.js";
export type { ContinuityVerificationResult } from "./continuity-verification.js";
export * from "./validation.js";
export * from "./verification.js";
