import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as AjvNs from "ajv/dist/2020.js";
import * as addFormatsNs from "ajv-formats";
const Ajv = (AjvNs as any).default ?? AjvNs;
const addFormats = (addFormatsNs as any).default ?? addFormatsNs;

import { canonicalString, sha256Digest } from "./index.js";
import {
  boundaryAssessmentSemanticError,
  type BoundaryCrossingAssessment,
} from "./boundary-crossing.js";
import type {
  AdmissibilityDetermination,
  GovernanceClearance,
  GovernanceEvaluation,
} from "./index.js";

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
export const REASON_CLEARANCE_ACTION_MISMATCH = "CLEARANCE_ACTION_MISMATCH";
export const REASON_CLEARANCE_ENVELOPE_MISMATCH =
  "CLEARANCE_ENVELOPE_MISMATCH";
export const REASON_CLEARANCE_NEGATIVE_STATE = "CLEARANCE_NEGATIVE_STATE";
export const REASON_CLEARANCE_EXPIRED = "CLEARANCE_EXPIRED";
export const REASON_CLEARANCE_REVOKED = "CLEARANCE_REVOKED";

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
    BoundaryCrossingAssessment: {
      schemaFile: "boundary-crossing-assessment-v0.2.schema.json",
    },
  };
}

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
  constructor(message: string, public path: string) {
    super(message);
    this.name = "SchemaValidationError";
  }
}

function repoRoot(): string {
  const start = path.dirname(fileURLToPath(import.meta.url));
  let candidate = start;
  for (;;) {
    if (
      fs.existsSync(
        path.join(candidate, "spec", "governance-clearance.schema.json"),
      )
    ) {
      return candidate;
    }
    const parent = path.dirname(candidate);
    if (parent === candidate) break;
    candidate = parent;
  }
  throw new Error("could not locate RACS spec/ directory");
}

const validatorCache = new Map<string, any>();

function getValidator(artifactType: string): any {
  const cached = validatorCache.get(artifactType);
  if (cached) return cached;
  const entry = artifactTypes()[artifactType];
  if (!entry) throw new Error(`unknown artifact_type: ${artifactType}`);
  const schema = JSON.parse(
    fs.readFileSync(path.join(repoRoot(), "spec", entry.schemaFile), "utf-8"),
  );
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  const validator = ajv.compile(schema);
  validatorCache.set(artifactType, validator);
  return validator;
}

export function schemaSha256(artifactType: string): string {
  const entry = artifactTypes()[artifactType];
  if (!entry) throw new Error(`unknown artifact_type: ${artifactType}`);
  const raw = fs.readFileSync(path.join(repoRoot(), "spec", entry.schemaFile));
  return "sha256:" + createHash("sha256").update(raw).digest("hex");
}

export function validate(
  artifactType: string,
  raw: unknown,
): Validated<unknown> {
  const validateFn = getValidator(artifactType);
  if (!validateFn(raw)) {
    const first = (validateFn.errors || [])[0];
    const missing = first?.params?.missingProperty;
    const errorPath = first
      ? missing
        ? `${first.instancePath}/${missing}`
        : first.instancePath
      : "";
    throw new SchemaValidationError(
      first?.message || "schema violation",
      errorPath,
    );
  }

  if (artifactType === "BoundaryCrossingAssessment") {
    try {
      const semanticError = boundaryAssessmentSemanticError(
        raw as BoundaryCrossingAssessment,
      );
      if (semanticError !== null) {
        throw new SchemaValidationError(semanticError, "");
      }
    } catch (error) {
      if (error instanceof SchemaValidationError) throw error;
      throw new SchemaValidationError((error as Error).message, "");
    }
  }

  return { artifactType, model: raw, payload: raw };
}

function typedDigest(
  artifactType: string,
  raw: unknown,
): [string, string] {
  switch (artifactType) {
    case "GovernanceEvaluation":
      return [
        canonicalString(raw as GovernanceEvaluation),
        sha256Digest(raw as GovernanceEvaluation),
      ];
    case "AdmissibilityDetermination":
      return [
        canonicalString(raw as AdmissibilityDetermination),
        sha256Digest(raw as AdmissibilityDetermination),
      ];
    case "GovernanceClearance":
      return [
        canonicalString(raw as GovernanceClearance),
        sha256Digest(raw as GovernanceClearance),
      ];
    case "BoundaryCrossingAssessment":
      return [
        canonicalString(raw as BoundaryCrossingAssessment),
        sha256Digest(raw as BoundaryCrossingAssessment),
      ];
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
    if (model.constraints === undefined || model.constraints === null) {
      return REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS;
    }
    if (!enforceable(model.constraints)) {
      return REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS;
    }
  }
  return null;
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

export function check(
  artifactType: string,
  raw: unknown,
): ValidationResult {
  let validated: Validated<unknown>;
  try {
    validated = validate(artifactType, raw);
  } catch (error) {
    const validationError = error as SchemaValidationError;
    return {
      decision: "REJECT",
      reason_code: REASON_SCHEMA_INVALID,
      error_path: validationError.path,
    };
  }

  let canonical: string;
  let digest: string;
  try {
    [canonical, digest] = typedDigest(artifactType, validated.model);
  } catch (error) {
    return {
      decision: "REJECT",
      reason_code: REASON_SCHEMA_INVALID,
      error_path: (error as Error).message,
    };
  }

  if (artifactType === "GovernanceClearance") {
    const reason = clearanceIntraCheck(
      validated.model as GovernanceClearance,
    );
    if (reason !== null) {
      return { decision: "REJECT", reason_code: reason };
    }
  }

  return {
    decision: "ACCEPT",
    reason_code: REASON_ACCEPT,
    canonical,
    payload_digest: digest,
  };
}
