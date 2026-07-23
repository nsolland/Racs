//! RACS v0.2 runtime conformance — Stage 3C, Port A (schema validation).
//!
//! Turns the pure typed models from Stage 3B into governed types:
//!
//! * `Raw<T>`      — JSON parsed, NOT yet schema-conformant.
//! * `Validated<T>` — proven schema-conformant (Draft 2020-12) for its artifact type.
//! * `Verified<T>`  — schema-conformant AND all external cross-artifact bindings
//!                    resolved and checked (Stage 3C, Port B).
//!
//! The normative contract is the schema files under `spec/*.schema.json`. Nothing
//! may be promoted to `Validated` without passing the Ajv validator, and nothing
//! may be promoted to `Verified` without passing the cross-artifact verifier in
//! `./verification`.
//!
//! All three bindings (Python/Rust/TypeScript) MUST emit byte-identical:
//! * accept/reject decision
//! * normalized reason code
//! * canonical bytes (for accepted objects)
//! * payload digest (for accepted objects)

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as url from "node:url";
import { fileURLToPath } from "node:url";
import Ajv = require("ajv");
import addFormats = require("ajv-formats");
import { canonicalString, sha256Digest } from "./index.js";
import type {
  AdmissibilityDetermination,
  GovernanceClearance,
  GovernanceEvaluation,
} from "./index.js";

// --- normalized reason codes (language-agnostic) -----------------------------

export const REASON_ACCEPT = "ACCEPT";
export const REASON_SCHEMA_INVALID = "SCHEMA_INVALID";
export const REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS =
  "CLEARANCE_ALLOW_HAS_CONSTRAINTS";
export const REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS =
  "CLEARANCE_MODIFY_MISSING_CONSTRAINTS";
export const REASON_CLEARANCE_ALLOW_STATE_MISMATCH =
  "CLEARANCE_ALLOW_STATE_MISMATCH";
export const REASON_CLEARANCE_MODIFY_STATE_MISMATCH =
  "CLEARANCE_MODIFY_STATE_MISMATCH";
export const REASON_EVALUATION_BINDING_DIGEST_MISMATCH =
  "EVALUATION_BINDING_DIGEST_MISMATCH";
export const REASON_EVALUATION_BINDING_REF_MISMATCH =
  "EVALUATION_BINDING_REF_MISMATCH";
export const REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH =
  "CLEARANCE_DETERMINATION_DIGEST_MISMATCH";
export const REASON_CLEARANCE_ACTION_MISMATCH =
  "CLEARANCE_ACTION_MISMATCH";
export const REASON_CLEARANCE_ENVELOPE_MISMATCH =
  "CLEARANCE_ENVELOPE_MISMATCH";
export const REASON_CLEARANCE_NEGATIVE_STATE = "CLEARANCE_NEGATIVE_STATE";
export const REASON_CLEARANCE_EXPIRED = "CLEARANCE_EXPIRED";
export const REASON_CLEARANCE_REVOKED = "CLEARANCE_REVOKED";

// --- artifact type registry -------------------------------------------------

interface ArtifactType {
  schemaFile: string;
}

function artifactTypes(): Record<string, ArtifactType> {
  return {
    GovernanceEvaluation: {
      schemaFile: "governance-evaluation-v0.2.schema.json",
    },
    AdmissibilityDetermination: {
      schemaFile: "admissibility-determination-v0.2.schema.json",
    },
    GovernanceClearance: {
      schemaFile: "governance-clearance.schema.json",
    },
  };
}

// --- wrapper types ----------------------------------------------------------

export class Raw<T> {
  constructor(public data: unknown) {}
}

export interface Validated<T> {
  artifactType: string;
  model: T;
  payload: unknown;
}

export interface Verified<T> {
  artifactType: string;
  model: T;
  payload: unknown;
}

export interface ValidationResult {
  decision: "ACCEPT" | "REJECT";
  reason_code: string;
  canonical?: string;
  payload_digest?: string;
  error_path?: string;
}

export class SchemaValidationError extends Error {
  constructor(
    message: string,
    public path: string,
  ) {
    super(message);
    this.name = "SchemaValidationError";
  }
}

// --- schema loading ---------------------------------------------------------

function repoRoot(): string {
  // Walk up from this file until we find spec/governance-clearance.schema.json.
  const start = path.dirname(fileURLToPath(import.meta.url));
  let cand = start;
  for (;;) {
    if (
      fs.existsSync(
        path.join(cand, "spec", "governance-clearance.schema.json"),
      )
    ) {
      return cand;
    }
    const parent = path.dirname(cand);
    if (parent === cand) break;
    cand = parent;
  }
  throw new Error("could not locate RACS spec/ directory");
}

const validatorCache = new Map<string, any>();

function getValidator(artifactType: string): any {
  const cached = validatorCache.get(artifactType);
  if (cached) return cached;
  const types = artifactTypes();
  const entry = types[artifactType];
  if (!entry) {
    throw new Error(`unknown artifact_type: ${artifactType}`);
  }
  const schemaPath = path.join(repoRoot(), "spec", entry.schemaFile);
  const text = fs.readFileSync(schemaPath, "utf-8");
  const schema = JSON.parse(text);
  const ajv = new Ajv({ strict: false, draft: "2020-12", allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  validatorCache.set(artifactType, validate);
  return validate;
}

export function schemaSha256(artifactType: string): string {
  const types = artifactTypes();
  const entry = types[artifactType];
  if (!entry) {
    throw new Error(`unknown artifact_type: ${artifactType}`);
  }
  const schemaPath = path.join(repoRoot(), "spec", entry.schemaFile);
  const raw = fs.readFileSync(schemaPath);
  const h = createHash("sha256");
  h.update(raw);
  return "sha256:" + h.digest("hex");
}

// --- core validate entrypoint -----------------------------------------------

export function validate(
  artifactType: string,
  raw: unknown,
): Validated<unknown> {
  const validateFn = getValidator(artifactType);
  const ok = validateFn(raw);
  if (!ok) {
    const first = (validateFn.errors || [])[0];
    const path = first
      ? first.instancePath || (first.params as { missingProperty?: string })
          .missingProperty
        ? `${first.instancePath}/${(
            first.params as { missingProperty?: string }
          ).missingProperty}`
        : first.instancePath
      : "";
    const message = first ? first.message || "schema violation" : "schema violation";
    throw new SchemaValidationError(message, path);
  }
  return {
    artifactType,
    model: raw,
    payload: raw,
  };
}

function typedDigest(
  artifactType: string,
  raw: unknown,
): [string, string] {
  switch (artifactType) {
    case "GovernanceEvaluation": {
      const m = raw as GovernanceEvaluation;
      return [canonicalString(m), sha256Digest(m)];
    }
    case "AdmissibilityDetermination": {
      const m = raw as AdmissibilityDetermination;
      return [canonicalString(m), sha256Digest(m)];
    }
    case "GovernanceClearance": {
      const m = raw as GovernanceClearance;
      return [canonicalString(m), sha256Digest(m)];
    }
    default:
      throw new Error(`unknown artifact_type: ${artifactType}`);
  }
}

function clearanceIntraCheck(model: GovernanceClearance): string | null {
  if (model.decision === "ALLOW") {
    if (model.admissibility_state !== "ADMISSIBLE") {
      return REASON_CLEARANCE_ALLOW_STATE_MISMATCH;
    }
    if (model.constraints !== undefined && model.constraints !== null) {
      return REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS;
    }
  } else if (model.decision === "MODIFY") {
    if (model.admissibility_state !== "CONDITIONALLY_ADMISSIBLE") {
      return REASON_CLEARANCE_MODIFY_STATE_MISMATCH;
    }
    const c = model.constraints;
    if (c === undefined || c === null) {
      return REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS;
    }
    if (!enforceable(c as unknown)) {
      return REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS;
    }
  }
  return null;
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

/// Non-raising variant: returns an ACCEPT/REJECT ValidationResult with a
/// normalized reason code. For ACCEPT, canonical bytes + digest are attached.
export function check(
  artifactType: string,
  raw: unknown,
): ValidationResult {
  let validated: Validated<unknown>;
  try {
    validated = validate(artifactType, raw);
  } catch (e) {
    const err = e as SchemaValidationError;
    return {
      decision: "REJECT",
      reason_code: REASON_SCHEMA_INVALID,
      error_path: err.path,
    };
  }

  let canonical: string;
  let digest: string;
  try {
    [canonical, digest] = typedDigest(artifactType, validated.model);
  } catch (e) {
    return {
      decision: "REJECT",
      reason_code: REASON_SCHEMA_INVALID,
      error_path: (e as Error).message,
    };
  }

  if (artifactType === "GovernanceClearance") {
    const model = validated.model as GovernanceClearance;
    const sem = clearanceIntraCheck(model);
    if (sem !== null) {
      return { decision: "REJECT", reason_code: sem };
    }
  }

  return {
    decision: "ACCEPT",
    reason_code: REASON_ACCEPT,
    canonical,
    payload_digest: digest,
  };
}
