//! RACS v0.2 runtime conformance — Stage 3C, Port B (cross-artifact verification).

import {
  sha256Digest,
  type AdmissibilityDetermination,
  type GovernanceClearance,
  type GovernanceEvaluation,
} from "./index.js";

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

  let expected: string;
  try {
    expected = sha256Digest(evaluation);
  } catch (error) {
    return reject(
      "EVALUATION_BINDING_DIGEST_MISMATCH",
      (error as Error).message,
    );
  }
  const referenceMatches = determination.evaluation_bindings.some(
    (binding) => binding.evaluation_ref === evaluation.evaluation_id,
  );
  if (!referenceMatches) {
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
  actionEnvelope?: unknown,
  verificationTime?: string,
): VerificationResult {
  if (
    clearance.admissibility_determination_ref !== determination.determination_id
  ) {
    return reject(
      "CLEARANCE_DETERMINATION_DIGEST_MISMATCH",
      "determination_ref mismatch",
    );
  }
  let determinationDigest: string;
  try {
    determinationDigest = sha256Digest(determination);
  } catch (error) {
    return reject(
      "CLEARANCE_DETERMINATION_DIGEST_MISMATCH",
      (error as Error).message,
    );
  }
  if (
    clearance.admissibility_determination_digest !== determinationDigest
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

  const state = String(determination.state).toUpperCase();
  if (NON_CLEARABLE_STATES.has(state)) {
    return reject(
      "CLEARANCE_NEGATIVE_STATE",
      `determination.state=${state} is not clearable`,
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
    const constraints = clearance.constraints;
    if (constraints === undefined || constraints === null) {
      return reject(
        "CLEARANCE_MODIFY_MISSING_CONSTRAINTS",
        "MODIFY requires constraints",
      );
    }
    if (!enforceable(constraints)) {
      return reject(
        "CLEARANCE_MODIFY_MISSING_CONSTRAINTS",
        "constraints present but not enforceable",
      );
    }
  }

  if (
    clearance.revocation_registry_ref === undefined ||
    clearance.revocation_registry_ref === ""
  ) {
    return reject("CLEARANCE_REVOKED", "empty revocation_registry_ref");
  }
  if (isExpired(clearance.valid_until, verificationTime)) {
    return reject("CLEARANCE_EXPIRED", "validity window expired");
  }

  if (actionEnvelope !== undefined) {
    const envelope = actionEnvelope as Record<string, unknown>;
    const envelopeDigest =
      (typeof envelope["payload_digest"] === "string"
        ? envelope["payload_digest"]
        : undefined) ??
      (typeof envelope["action_envelope_digest"] === "string"
        ? envelope["action_envelope_digest"]
        : undefined);
    if (
      typeof envelopeDigest === "string" &&
      envelopeDigest !== clearance.action_envelope_digest
    ) {
      return reject(
        "CLEARANCE_ENVELOPE_MISMATCH",
        "resolved envelope digest mismatch",
      );
    }
  }

  return accept();
}

function enforceable(constraints: unknown): boolean {
  if (typeof constraints !== "object" || constraints === null) return false;
  const values = constraints as Record<string, unknown>;
  const rules = values["rules"];
  if (Array.isArray(rules) && rules.length > 0) return true;
  const referenceOk =
    typeof values["constraint_set_ref"] === "string" &&
    (values["constraint_set_ref"] as string).length > 0;
  const digestOk =
    typeof values["constraint_set_digest"] === "string" &&
    (values["constraint_set_digest"] as string).startsWith("sha256:");
  return referenceOk && digestOk;
}

function isExpired(validUntil: string, verificationTime?: string): boolean {
  if (!validUntil || validUntil.length === 0) return false;
  const until = Date.parse(validUntil.replace(/Z$/, "+00:00"));
  const at = verificationTime
    ? Date.parse(verificationTime.replace(/Z$/, "+00:00"))
    : Date.now();
  if (Number.isNaN(until) || Number.isNaN(at)) return false;
  return until < at;
}
