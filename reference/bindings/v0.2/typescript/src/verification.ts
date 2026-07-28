import {
  sha256Digest,
  type AdmissibilityDetermination,
  type GovernanceClearance,
  type GovernanceEvaluation,
} from "./index.js";
import type { BoundaryCrossingAssessment } from "./boundary-crossing.js";
import {
  REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
  verifyBoundaryChain,
} from "./boundary-validation.js";

export interface VerificationResult {
  decision: "ACCEPT" | "REJECT";
  reason_code: string;
  detail?: string;
}

export function accept(): VerificationResult {
  return { decision: "ACCEPT", reason_code: "ACCEPT" };
}

export function reject(reason: string, detail: string): VerificationResult {
  return { decision: "REJECT", reason_code: reason, detail };
}

const NON_CLEARABLE_STATES = new Set<string>([
  "NOT_ADMISSIBLE",
  "INDETERMINATE",
  "STALE",
  "REVOKED",
  "HALTED",
  "REQUIRES_STEP_UP",
]);

export function verifyEvaluationBinding(
  determination: AdmissibilityDetermination,
  evaluation: GovernanceEvaluation,
): VerificationResult {
  if (determination.action_id !== evaluation.action_id) {
    return reject(
      "CLEARANCE_ACTION_MISMATCH",
      "determination.action_id != evaluation.action_id",
    );
  }
  if (
    determination.action_envelope_digest !== evaluation.action_envelope_digest
  ) {
    return reject("CLEARANCE_ENVELOPE_MISMATCH", "envelope digest mismatch");
  }

  const expected = sha256Digest(evaluation);
  if (
    !determination.evaluation_bindings.some(
      (binding) => binding.evaluation_ref === evaluation.evaluation_id,
    )
  ) {
    return reject(
      "EVALUATION_BINDING_REF_MISMATCH",
      `no binding references ${evaluation.evaluation_id}`,
    );
  }
  for (const binding of determination.evaluation_bindings) {
    if (binding.evaluation_digest !== expected) {
      return reject(
        "EVALUATION_BINDING_DIGEST_MISMATCH",
        `binding ${binding.evaluation_ref}: digest mismatch`,
      );
    }
  }
  return accept();
}

export function verifyClearanceBinding(
  clearance: GovernanceClearance,
  determination: AdmissibilityDetermination,
  actionEnvelope?: Record<string, unknown>,
  verificationTime?: string,
  governanceEvaluation?: GovernanceEvaluation,
  boundaryAssessment?: BoundaryCrossingAssessment,
): VerificationResult {
  if (
    clearance.admissibility_determination_ref !== determination.determination_id
  ) {
    return reject(
      "CLEARANCE_DETERMINATION_DIGEST_MISMATCH",
      "determination_ref mismatch",
    );
  }
  if (
    clearance.admissibility_determination_digest !== sha256Digest(determination)
  ) {
    return reject(
      "CLEARANCE_DETERMINATION_DIGEST_MISMATCH",
      "admissibility_determination_digest mismatch",
    );
  }

  if (clearance.action_id !== determination.action_id) {
    return reject("CLEARANCE_ACTION_MISMATCH", "action_id mismatch");
  }
  if (
    clearance.action_envelope_digest !== determination.action_envelope_digest
  ) {
    return reject(
      "CLEARANCE_ENVELOPE_MISMATCH",
      "action_envelope_digest mismatch",
    );
  }

  const digestPairs: [string, string, string][] = [
    ["authority_digest", clearance.authority_digest, determination.authority_digest],
    [
      "delegation_chain_digest",
      clearance.delegation_chain_digest,
      determination.delegation_chain_digest,
    ],
    ["policy_digest", clearance.policy_digest, determination.policy_digest],
    ["evidence_digest", clearance.evidence_digest, determination.evidence_digest],
    ["purpose_digest", clearance.purpose_digest, determination.purpose_digest],
    ["state_digest", clearance.state_digest, determination.state_digest],
  ];
  for (const [name, clearanceValue, determinationValue] of digestPairs) {
    if (clearanceValue !== determinationValue) {
      return reject(
        "CLEARANCE_DETERMINATION_DIGEST_MISMATCH",
        `${name} mismatch`,
      );
    }
  }

  if (NON_CLEARABLE_STATES.has(determination.state)) {
    return reject(
      "CLEARANCE_NEGATIVE_STATE",
      `determination.state=${determination.state} is not clearable`,
    );
  }
  if (clearance.decision === "ALLOW") {
    if (determination.state !== "ADMISSIBLE") {
      return reject(
        "CLEARANCE_ALLOW_STATE_MISMATCH",
        "ALLOW requires ADMISSIBLE",
      );
    }
    if (clearance.constraints !== undefined && clearance.constraints !== null) {
      return reject(
        "CLEARANCE_ALLOW_HAS_CONSTRAINTS",
        "ALLOW must not carry constraints",
      );
    }
  } else if (clearance.decision === "MODIFY") {
    if (determination.state !== "CONDITIONALLY_ADMISSIBLE") {
      return reject(
        "CLEARANCE_MODIFY_STATE_MISMATCH",
        "MODIFY requires CONDITIONALLY_ADMISSIBLE",
      );
    }
    if (clearance.constraints === undefined || clearance.constraints === null) {
      return reject(
        "CLEARANCE_MODIFY_MISSING_CONSTRAINTS",
        "MODIFY requires constraints",
     );
    }
    if (!enforceable(clearance.constraints)) {
      return reject(
        "CLEARANCE_MODIFY_MISSING_CONSTRAINTS",
        "constraints present but not enforceable",
    );
    }
  }

  if (!clearance.revocation_registry_ref) {
    return reject("CLEARANCE_REVOKED", "empty revocation_registry_ref");
  }
  if (isExpired(clearance.valid_until, verificationTime)) {
    return reject("CLEARANCE_EXPIRED", "validity window expired");
  }

  if (
    actionEnvelope === undefined ||
    governanceEvaluation === undefined ||
    boundaryAssessment === undefined
  ) {
    return reject(
      REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
      "clearance verification requires envelope, evaluation and assessment",
    );
  }

  const boundary = verifyBoundaryChain({
    actionEnvelope,
    assessment: boundaryAssessment,
    evaluation: governanceEvaluation,
    determination,
    verificationTime,
  });
  if (boundary.decision !== "ACCEPT") {
    return {
      decision: boundary.decision,
      reason_code: boundary.reason_code,
      detail: boundary.detail,
    };
  }
  return accept();
}

function enforceable(constraints: unknown): boolean {
  if (typeof constraints !== "object" || constraints === null) return false;
  const values = constraints as Record<string, unknown>;
  const rules = values["rules"];
  if (Array.isArray(rules) && rules.length > 0) return true;
  return (
    typeof values["constraint_set_ref"] === "string" &&
    values["constraint_set_ref"].length > 0 &&
    typeof values["constraint_set_digest"] === "string" &&
    values["constraint_set_digest"].startsWith("sha256:")
  );
}

function isExpired(validUntil: string, verificationTime?: string): boolean {
  const until = Date.parse(validUntil);
  const at = verificationTime ? Date.parse(verificationTime) : Date.now();
  if (Number.isNaN(until) || Number.isNaN(at)) return false;
  return until < at;
}
