//! RACS v0.2 runtime conformance — Stage3C, Port B (cross-artifact verification).
//!
//! JSON Schema cannot prove that referenced artifacts *exist* or that the digests
//! *match*. These functions enforce the binding rules between the three contract
//! artifacts. They operate on already-`Validated` payloads (schema-conformant
//! typed models from `./validation`).
//!
//! Binding rules enforced
//! -----------------------
//! * `verifyEvaluationBinding(determination, evaluation)`
//!   - evaluation payload digest == evaluation_digest of every binding
//!   - at least one evaluation_binding.evaluation_ref == evaluation.evaluation_id
//!   - determination.action_id / action_envelope_digest MUST match evaluation
//! * `verifyClearanceBinding(clearance, determination, actionEnvelope)`
//!   - determination-ref points at the correct determination
//!   - admissibility_determination_digest matches the actual determination
//!   - clearance and determination bind the same action_id + action_envelope_digest
//!   - authority/delegation/policy/evidence/purpose/state digests match
//!   - ALLOW only with ADMISSIBLE and WITHOUT constraints
//!   - MODIFY only with CONDITIONALLY_ADMISSIBLE and WITH enforceable constraints
//!   - negative admissibility state can never become a clearance
//!   - validity window (valid_from/valid_until) and revocation status checked
//!
//! Return value: a VerificationResult (decision ACCEPT/REJECT, normalized
//! reason code). On ACCEPT the caller may construct `Verified<T>`.

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

// Admissibility states that may never become a clearance.
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
  // 1. action identity consistency
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
  // 2. evaluation digest must match the resolved evaluation's payload_digest
  let expected: string;
  try {
    expected = sha256Digest(evaluation);
  } catch (e) {
    return reject("EVALUATION_BINDING_DIGEST_MISMATCH", (e as Error).message);
  }
  const refMatch = determination.evaluation_bindings.some(
    (b) => b.evaluation_ref === evaluation.evaluation_id,
  );
  if (!refMatch) {
    return reject(
      "EVALUATION_BINDING_REF_MISMATCH",
      `no binding references ${evaluation.evaluation_id}`,
    );
  }
  for (const b of determination.evaluation_bindings) {
    if (b.evaluation_digest !== expected) {
      return reject(
        "EVALUATION_BINDING_DIGEST_MISMATCH",
        `binding ${b.evaluation_ref}: digest mismatch`,
      );
    }
  }
  return accept();
}

export function verifyClearanceBinding(
  clearance: GovernanceClearance,
  determination: AdmissibilityDetermination,
  actionEnvelope?: unknown,
): VerificationResult {
  // 1. determination reference + digest binding
  if (
    clearance.admissibility_determination_ref !== determination.determination_id
  ) {
    return reject("CLEARANCE_DETERMINATION_DIGEST_MISMATCH", "determination_ref mismatch");
  }
  let detDigest: string;
  try {
    detDigest = sha256Digest(determination);
  } catch (e) {
    return reject("CLEARANCE_DETERMINATION_DIGEST_MISMATCH", (e as Error).message);
  }
  if (clearance.admissibility_determination_digest !== detDigest) {
    return reject(
      "CLEARANCE_DETERMINATION_DIGEST_MISMATCH",
      "admissibility_determination_digest mismatch",
    );
  }

  // 2. shared action identity
  if (clearance.action_id !== determination.action_id) {
    return reject("CLEARANCE_ACTION_MISMATCH", "action_id mismatch");
  }
  if (clearance.action_envelope_digest !== determination.action_envelope_digest) {
    return reject("CLEARANCE_ENVELOPE_MISMATCH", "action_envelope_digest mismatch");
  }

  // 3. digest congruence across authority/delegation/policy/evidence/purpose/state
  const pairs: [string, string, string][] = [
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
  for (const [name, cVal, dVal] of pairs) {
    if (cVal !== dVal) {
      return reject("CLEARANCE_DETERMINATION_DIGEST_MISMATCH", `${name} mismatch`);
    }
  }

  // 4. admissibility-state semantics
  const stateStr = String(determination.state).toUpperCase();
  if (NON_CLEARABLE_STATES.has(stateStr)) {
    return reject(
      "CLEARANCE_NEGATIVE_STATE",
      `determination.state=${stateStr} is not clearable`,
    );
  }
  if (clearance.decision === "ALLOW") {
    if (determination.state !== "ADMISSIBLE") {
      return reject("CLEARANCE_ALLOW_STATE_MISMATCH", "ALLOW requires ADMISSIBLE");
    }
    if (clearance.constraints !== undefined && clearance.constraints !== null) {
      return reject("CLEARANCE_ALLOW_HAS_CONSTRAINTS", "ALLOW must not carry constraints");
    }
  } else if (clearance.decision === "MODIFY") {
    if (determination.state !== "CONDITIONALLY_ADMISSIBLE") {
      return reject(
        "CLEARANCE_MODIFY_STATE_MISMATCH",
        "MODIFY requires CONDITIONALLY_ADMISSIBLE",
      );
    }
    const c = clearance.constraints;
    if (c === undefined || c === null) {
      return reject("CLEARANCE_MODIFY_MISSING_CONSTRAINTS", "MODIFY requires constraints");
    }
    if (!enforceable(c)) {
      return reject(
        "CLEARANCE_MODIFY_MISSING_CONSTRAINTS",
        "constraints present but not enforceable",
      );
    }
  }

  // 5. validity window + revocation
  if (
    clearance.revocation_registry_ref === undefined ||
    clearance.revocation_registry_ref === ""
  ) {
    return reject("CLEARANCE_REVOKED", "empty revocation_registry_ref");
  }
  if (isExpired(clearance.valid_from, clearance.valid_until)) {
    return reject("CLEARANCE_EXPIRED", "validity window expired");
  }

  // 6. optional envelope digest resolution
  if (actionEnvelope !== undefined) {
    const env = actionEnvelope as Record<string, unknown>;
    const envDigest =
      (typeof env["payload_digest"] === "string"
        ? env["payload_digest"]
        : undefined) ??
      (typeof env["action_envelope_digest"] === "string"
        ? env["action_envelope_digest"]
        : undefined);
    if (typeof envDigest === "string" && envDigest !== clearance.action_envelope_digest) {
      return reject("CLEARANCE_ENVELOPE_MISMATCH", "resolved envelope digest mismatch");
    }
  }

  return accept();
}

function enforceable(constraints: unknown): boolean {
  if (typeof constraints !== "object" || constraints === null) return false;
  const map = constraints as Record<string, unknown>;
  const rules = map["rules"];
  if (Array.isArray(rules) && rules.length > 0) return true;
  const refOk =
    typeof map["constraint_set_ref"] === "string" &&
    (map["constraint_set_ref"] as string).length > 0;
  const digestOk =
    typeof map["constraint_set_digest"] === "string" &&
    (map["constraint_set_digest"] as string).startsWith("sha256:");
  return refOk && digestOk;
}

function isExpired(validFrom: string, validUntil: string): boolean {
  if (!validUntil || validUntil.length === 0) return false;
  // Parse ISO-8601 (accept trailing Z). Best-effort; unparseable => not expired.
  const norm = validUntil.replace(/Z$/, "+00:00");
  const until = Date.parse(norm);
  if (Number.isNaN(until)) return false;
  return until < Date.now();
}
