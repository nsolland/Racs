import { sha256Digest } from "./index.js";
import {
  responseFloorSatisfied,
  type BoundaryCrossingAssessment,
  type BoundaryState,
} from "./boundary-crossing.js";
import type {
  AdmissibilityDetermination,
  GovernanceEvaluation,
} from "./index.js";

export interface BoundaryVerificationResult {
  decision: "ACCEPT" | "REJECT";
  reason_code: string;
  detail?: string;
}

export const REASON_BOUNDARY_ACCEPT = "BOUNDARY_ACCEPT";
export const REASON_BOUNDARY_REQUIRED_MISSING = "BOUNDARY_REQUIRED_MISSING";
export const REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH =
  "BOUNDARY_ASSESSMENT_REF_MISMATCH";
export const REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH =
  "BOUNDARY_ASSESSMENT_DIGEST_MISMATCH";
export const REASON_BOUNDARY_ACTION_MISMATCH = "BOUNDARY_ACTION_MISMATCH";
export const REASON_BOUNDARY_ENVELOPE_MISMATCH = "BOUNDARY_ENVELOPE_MISMATCH";
export const REASON_BOUNDARY_TENANT_MISMATCH = "BOUNDARY_TENANT_MISMATCH";
export const REASON_BOUNDARY_POLICY_MISMATCH = "BOUNDARY_POLICY_MISMATCH";
export const REASON_BOUNDARY_TYPE_MISSING = "BOUNDARY_TYPE_MISSING";
export const REASON_BOUNDARY_RESPONSE_FLOOR_VIOLATION =
  "BOUNDARY_RESPONSE_FLOOR_VIOLATION";
export const REASON_BOUNDARY_ASSESSMENT_EXPIRED =
  "BOUNDARY_ASSESSMENT_EXPIRED";
export const REASON_BOUNDARY_ASSESSMENT_REVOKED =
  "BOUNDARY_ASSESSMENT_REVOKED";
export const REASON_BOUNDARY_BINDING_DROPPED = "BOUNDARY_BINDING_DROPPED";
export const REASON_BOUNDARY_BINDING_INJECTED = "BOUNDARY_BINDING_INJECTED";
export const REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH =
  "BOUNDARY_CLEARABLE_STATE_MISMATCH";
export const REASON_BOUNDARY_ASSESSMENT_UNRESOLVED =
  "BOUNDARY_ASSESSMENT_UNRESOLVED";
export const REASON_BOUNDARY_TIME_INVALID = "BOUNDARY_TIME_INVALID";
export const REASON_BOUNDARY_LIFETIME_MISMATCH =
  "BOUNDARY_LIFETIME_MISMATCH";

const NON_CLEARABLE = new Set<BoundaryState>([
  "UNAUTHORIZED", "INDETERMINATE", "STALE", "REVOKED",
]);

function accept(): BoundaryVerificationResult {
  return { decision: "ACCEPT", reason_code: REASON_BOUNDARY_ACCEPT };
}

function reject(reason: string, detail?: string): BoundaryVerificationResult {
  return detail === undefined
    ? { decision: "REJECT", reason_code: reason }
    : { decision: "REJECT", reason_code: reason, detail };
}

function instant(value?: string): number {
  const raw = value ?? new Date().toISOString();
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed) || !/(Z|[+-]\d\d:\d\d)$/.test(raw)) {
    throw new Error("timestamp must include timezone");
  }
  return parsed;
}

export function verifyEvaluationBoundaryBinding(args: {
  actionEnvelope: Record<string, unknown>;
  assessment?: BoundaryCrossingAssessment;
  evaluation: GovernanceEvaluation;
  verificationTime?: string;
}): BoundaryVerificationResult {
  const { actionEnvelope, assessment, evaluation, verificationTime } = args;
  const requirements = actionEnvelope["boundary_requirements"] as
    | Record<string, unknown>
    | undefined;
  if (requirements === undefined || requirements === null) {
    return reject(
      REASON_BOUNDARY_REQUIRED_MISSING,
      "ActionEnvelope must declare fail-closed boundary requirements",
    );
  }
  if (assessment === undefined) {
    return reject(
      REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
      "evaluation binding cannot be resolved",
    );
  }
  const binding = evaluation.boundary_assessment_binding;
  if (binding === undefined) return reject(REASON_BOUNDARY_BINDING_DROPPED);
  if (binding.assessment_ref !== assessment.assessment_id) {
    return reject(REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH);
  }
  if (binding.assessment_digest !== sha256Digest(assessment)) {
    return reject(REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH);
  }
  if (assessment.action_id !== evaluation.action_id) {
    return reject(REASON_BOUNDARY_ACTION_MISMATCH);
  }
  if (assessment.tenant_id !== evaluation.tenant_id) {
    return reject(REASON_BOUNDARY_TENANT_MISMATCH);
  }

  const envelopeDigest = sha256Digest(actionEnvelope);
  if (actionEnvelope["action_id"] !== assessment.action_id) {
    return reject(REASON_BOUNDARY_ACTION_MISMATCH);
  }
  if (actionEnvelope["tenant_id"] !== assessment.tenant_id) {
    return reject(REASON_BOUNDARY_TENANT_MISMATCH);
  }
  if (
    assessment.action_envelope_digest !== envelopeDigest ||
    evaluation.action_envelope_digest !== envelopeDigest
  ) {
    return reject(REASON_BOUNDARY_ENVELOPE_MISMATCH);
  }

  if (
    requirements["policy_ref"] !== assessment.requirement_policy_ref ||
    requirements["policy_digest"] !== assessment.requirement_policy_digest
  ) {
    return reject(REASON_BOUNDARY_POLICY_MISMATCH);
  }
  const requiredTypes = new Set(
    Array.isArray(requirements["required_types"])
      ? requirements["required_types"] as string[]
      : [],
  );
  const presentTypes = new Set<string>(
    assessment.crossings.map((item) => item.boundary_type),
  );
  const missing = [...requiredTypes].filter((item) => !presentTypes.has(item)).sort();
  if (missing.length > 0) {
    return reject(REASON_BOUNDARY_TYPE_MISSING, missing.join(","));
  }

  try {
    const at = instant(verificationTime);
    const assessedAt = instant(assessment.assessed_at);
    const assessmentUntil = instant(assessment.valid_until);
    const evaluatedAt = instant(evaluation.evaluated_at);
    const evaluationUntil = instant(evaluation.valid_until);
    if (assessedAt > evaluatedAt) {
      return reject(
        REASON_BOUNDARY_LIFETIME_MISMATCH,
        "evaluation predates assessment",
      );
    }
    if (evaluationUntil > assessmentUntil) {
      return reject(
        REASON_BOUNDARY_LIFETIME_MISMATCH,
        "evaluation outlives assessment",
      );
    }
    if (at >= assessmentUntil) {
      return reject(REASON_BOUNDARY_ASSESSMENT_EXPIRED);
    }
  } catch (error) {
    return reject(REASON_BOUNDARY_TIME_INVALID, (error as Error).message);
  }

  if (assessment.aggregate_state === "REVOKED") {
    return reject(REASON_BOUNDARY_ASSESSMENT_REVOKED);
  }
  if (
    !responseFloorSatisfied(
      assessment.required_response_floor,
      evaluation.decision,
    )
  ) {
    return reject(
      REASON_BOUNDARY_RESPONSE_FLOOR_VIOLATION,
      `${assessment.required_response_floor}>${evaluation.decision}`,
    );
  }
  return accept();
}

export function verifyDeterminationBoundaryBinding(args: {
  assessment?: BoundaryCrossingAssessment;
  evaluation: GovernanceEvaluation;
  determination: AdmissibilityDetermination;
}): BoundaryVerificationResult {
  const { assessment, evaluation, determination } = args;
  const evaluationBinding = evaluation.boundary_assessment_binding;
  const determinationBinding = determination.boundary_assessment_binding;

  if (evaluationBinding === undefined && determinationBinding === undefined) {
    return reject(REASON_BOUNDARY_REQUIRED_MISSING);
  }
  if (evaluationBinding !== undefined && determinationBinding === undefined) {
    return reject(REASON_BOUNDARY_BINDING_DROPPED);
  }
  if (evaluationBinding === undefined && determinationBinding !== undefined) {
    return reject(REASON_BOUNDARY_BINDING_INJECTED);
  }
  if (assessment === undefined) {
    return reject(REASON_BOUNDARY_ASSESSMENT_UNRESOLVED);
  }
  if (
    evaluationBinding!.assessment_ref !== determinationBinding!.assessment_ref ||
    evaluationBinding!.assessment_digest !== determinationBinding!.assessment_digest
  ) {
    return reject(REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH);
  }
  if (determinationBinding!.assessment_ref !== assessment.assessment_id) {
    return reject(REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH);
  }
  if (determinationBinding!.assessment_digest !== sha256Digest(assessment)) {
    return reject(REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH);
  }
  if (
    determination.action_id !== assessment.action_id ||
    determination.action_id !== evaluation.action_id
  ) {
    return reject(REASON_BOUNDARY_ACTION_MISMATCH);
  }
  if (determination.tenant_id !== assessment.tenant_id) {
    return reject(REASON_BOUNDARY_TENANT_MISMATCH);
  }
  if (
    determination.action_envelope_digest !== assessment.action_envelope_digest ||
    determination.action_envelope_digest !== evaluation.action_envelope_digest
  ) {
    return reject(REASON_BOUNDARY_ENVELOPE_MISMATCH);
  }

  try {
    const evaluatedAt = instant(evaluation.evaluated_at);
    const evaluationUntil = instant(evaluation.valid_until);
    const determinedAt = instant(determination.determined_at);
    const determinationUntil = instant(determination.valid_until);
    const assessmentUntil = instant(assessment.valid_until);
    if (determinedAt < evaluatedAt) {
      return reject(
        REASON_BOUNDARY_LIFETIME_MISMATCH,
        "determination predates evaluation",
      );
    }
    if (
      determinationUntil > evaluationUntil ||
      determinationUntil > assessmentUntil
    ) {
      return reject(
        REASON_BOUNDARY_LIFETIME_MISMATCH,
        "determination outlives bound evidence",
      );
    }
  } catch (error) {
    return reject(REASON_BOUNDARY_TIME_INVALID, (error as Error).message);
  }

  if (
    NON_CLEARABLE.has(assessment.aggregate_state) &&
    (determination.state === "ADMISSIBLE" ||
      determination.state === "CONDITIONALLY_ADMISSIBLE")
  ) {
    return reject(
      REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH,
      `${assessment.aggregate_state}->${determination.state}`,
    );
  }
  if (
    assessment.aggregate_state === "CONDITIONALLY_AUTHORIZED" &&
    determination.state === "ADMISSIBLE"
  ) {
    return reject(
      REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH,
      "conditional assessment cannot become ADMISSIBLE",
    );
  }
  return accept();
}

export function verifyClearanceBoundaryResolution(args: {
  determination: AdmissibilityDetermination;
  assessment?: BoundaryCrossingAssessment;
}): BoundaryVerificationResult {
  const { determination, assessment } = args;
  const binding = determination.boundary_assessment_binding;
  if (binding === undefined) return reject(REASON_BOUNDARY_REQUIRED_MISSING);
  if (assessment === undefined) {
    return reject(REASON_BOUNDARY_ASSESSMENT_UNRESOLVED);
  }
  if (binding.assessment_ref !== assessment.assessment_id) {
    return reject(REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH);
  }
  if (binding.assessment_digest !== sha256Digest(assessment)) {
    return reject(REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH);
  }
  if (NON_CLEARABLE.has(assessment.aggregate_state)) {
    return reject(REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH);
  }
  return accept();
}

export function verifyBoundaryChain(args: {
  actionEnvelope: Record<string, unknown>;
  assessment?: BoundaryCrossingAssessment;
  evaluation: GovernanceEvaluation;
  determination: AdmissibilityDetermination;
  verificationTime?: string;
}): BoundaryVerificationResult {
  const evaluationResult = verifyEvaluationBoundaryBinding(args);
  if (evaluationResult.decision !== "ACCEPT") return evaluationResult;
  const determinationResult = verifyDeterminationBoundaryBinding(args);
  if (determinationResult.decision !== "ACCEPT") return determinationResult;
  return verifyClearanceBoundaryResolution(args);
}
