import * as jcs from "json-canonicalize";
import { createHash } from "node:crypto";

export interface Canonicalizable {
  canonical(): string;
  digest(): string;
}

/**
 * RACS v0.2 canonical contract bindings — canonicalization kernel (3A) + typed
 * model bindings (3B).
 *
 * Uses `json-canonicalize` (RFC 8785 / JCS). The canonical output MUST be
 * byte-for-byte identical across the Python, Rust, and TypeScript bindings.
 */

export function canonicalString(value: unknown): string {
  return jcs.canonicalize(value);
}

export function sha256Digest(value: unknown): string {
  const canon = jcs.canonicalize(value);
  return "sha256:" + createHash("sha256").update(Buffer.from(canon, "utf-8")).digest("hex");
}

// --- Enums (mirror schema `enum` constraints exactly) ----------------------

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

// --- Shared sub-types -------------------------------------------------------

export interface EvaluationBinding {
  evaluation_ref: string;
  evaluation_digest: string; // sha256:<64 hex>
}

// --- Typed model classes (pure data + canonical helpers) --------------------

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
  evaluated_at!: string;
  valid_until!: string;

  canonical(): string {
    return jcs.canonicalize(this);
  }
  digest(): string {
    return sha256Digest(this);
  }
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
  state!: AdmissibilityState;
  conditions?: unknown;
  reason_codes?: string[];
  determined_at!: string;
  valid_until!: string;
  revocation_registry_ref!: string;

  canonical(): string {
    return jcs.canonicalize(this);
  }
  digest(): string {
    return sha256Digest(this);
  }
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

  canonical(): string {
    return jcs.canonicalize(this);
  }
  digest(): string {
    return sha256Digest(this);
  }
}

// --- Stage 3C: runtime conformance (Port A schema + Port B cross-artifact) ---

export * from "./validation.js";
export * from "./verification.js";
