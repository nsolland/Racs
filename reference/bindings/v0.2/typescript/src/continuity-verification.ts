//! RACS v0.2 runtime-continuity cross-artifact verification.
//!
//! Verification produces evidence and verified outcomes. It does not create
//! execution authority or widen a clearance.

import {
  sha256Digest,
  type GovernanceClearance,
  type GovernanceEvaluation,
} from "./index.js";
import type {
  ContinuityDecision,
  EnvironmentGovernanceProfile,
  GovernedCapabilityManifest,
  GovernedExecutionSession,
  SessionState,
} from "./continuity.js";

export const REASON_ACCEPT = "ACCEPT";
export const REASON_SESSION_TERMINAL = "SESSION_TERMINAL";
export const REASON_SESSION_ACTION_ENVELOPE_MISMATCH =
  "SESSION_ACTION_ENVELOPE_MISMATCH";
export const REASON_SESSION_AUTHORITY_MISMATCH = "SESSION_AUTHORITY_MISMATCH";
export const REASON_SESSION_CAPABILITY_MANIFEST_MISMATCH =
  "SESSION_CAPABILITY_MANIFEST_MISMATCH";
export const REASON_SESSION_ENVIRONMENT_PROFILE_MISMATCH =
  "SESSION_ENVIRONMENT_PROFILE_MISMATCH";
export const REASON_SESSION_EVALUATION_MISMATCH = "SESSION_EVALUATION_MISMATCH";
export const REASON_SESSION_CLEARANCE_MISMATCH = "SESSION_CLEARANCE_MISMATCH";
export const REASON_SESSION_TENANT_MISMATCH = "SESSION_TENANT_MISMATCH";
export const REASON_SESSION_EXECUTOR_NOT_ALLOWED =
  "SESSION_EXECUTOR_NOT_ALLOWED";
export const REASON_SESSION_CAPABILITY_NOT_PERMITTED =
  "SESSION_CAPABILITY_NOT_PERMITTED";
export const REASON_SESSION_CONSEQUENCE_NOT_ALLOWED =
  "SESSION_CONSEQUENCE_NOT_ALLOWED";
export const REASON_SESSION_PROFILE_NOT_REFERENCED =
  "SESSION_PROFILE_NOT_REFERENCED";
export const REASON_SESSION_CLEARANCE_NOT_EXECUTABLE =
  "SESSION_CLEARANCE_NOT_EXECUTABLE";
export const REASON_SESSION_ARTIFACT_NOT_CURRENT =
  "SESSION_ARTIFACT_NOT_CURRENT";
export const REASON_SESSION_DEADLINE_EXCEEDS_AUTHORIZATION =
  "SESSION_DEADLINE_EXCEEDS_AUTHORIZATION";

export const REASON_BOUNDS_NARROWED = "BOUNDS_NARROWED";
export const REASON_BOUNDS_WIDENED = "BOUNDS_WIDENED";
export const REASON_BOUNDS_UNPROVABLE = "BOUNDS_UNPROVABLE";
export const REASON_BOUNDS_NOT_NARROWER = "BOUNDS_NOT_NARROWER";

export const REASON_DECISION_SESSION_MISMATCH = "DECISION_SESSION_MISMATCH";
export const REASON_DECISION_SEQUENCE_MISMATCH = "DECISION_SEQUENCE_MISMATCH";
export const REASON_DECISION_ACTION_MISMATCH = "DECISION_ACTION_MISMATCH";
export const REASON_DECISION_CAPABILITY_MISMATCH =
  "DECISION_CAPABILITY_MISMATCH";
export const REASON_DECISION_ENVIRONMENT_MISMATCH =
  "DECISION_ENVIRONMENT_MISMATCH";
export const REASON_DECISION_AUTHORITY_MISMATCH =
  "DECISION_AUTHORITY_MISMATCH";
export const REASON_DECISION_EXPIRED = "DECISION_EXPIRED";
export const REASON_DECISION_OUTLIVES_SESSION = "DECISION_OUTLIVES_SESSION";

const TERMINAL_STATES = new Set<SessionState>([
  "COMPLETED",
  "FAILED",
  "STOPPED",
  "HALTED",
]);
const TIME_KEYS = new Set([
  "deadline",
  "expires_at",
  "valid_until",
  "must_complete_by",
  "end_at",
  "latest_finish_at",
]);

export interface ContinuityVerificationResult {
  decision: "ACCEPT" | "REJECT";
  reason_code: string;
  detail?: string;
  effective_bounds?: Record<string, unknown>;
}

function accept(
  reasonCode = REASON_ACCEPT,
  effectiveBounds?: Record<string, unknown>,
): ContinuityVerificationResult {
  return {
    decision: "ACCEPT",
    reason_code: reasonCode,
    ...(effectiveBounds === undefined ? {} : { effective_bounds: effectiveBounds }),
  };
}

function reject(reasonCode: string, detail: string): ContinuityVerificationResult {
  return { decision: "REJECT", reason_code: reasonCode, detail };
}

function parseTime(value: string): number {
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) throw new Error(`invalid date-time: ${value}`);
  return parsed;
}

function nowAt(value?: string): number {
  return value === undefined ? Date.now() : parseTime(value);
}

function isCurrent(now: number, validFrom: string, validUntil: string): boolean {
  return parseTime(validFrom) <= now && now <= parseTime(validUntil);
}

export function verifyExecutionSession(
  session: GovernedExecutionSession,
  manifest: GovernedCapabilityManifest,
  profile: EnvironmentGovernanceProfile,
  evaluation: GovernanceEvaluation,
  clearance: GovernanceClearance,
  verificationTime?: string,
): ContinuityVerificationResult {
  if (TERMINAL_STATES.has(session.session_state)) {
    return reject(
      REASON_SESSION_TERMINAL,
      `session_state=${session.session_state} is terminal`,
    );
  }

  if (
    session.action_envelope_digest !== evaluation.action_envelope_digest ||
    session.action_envelope_digest !== clearance.action_envelope_digest
  ) {
    return reject(
      REASON_SESSION_ACTION_ENVELOPE_MISMATCH,
      "session, evaluation and clearance must bind the same ActionEnvelope",
    );
  }
  if (session.authority_digest !== clearance.authority_digest) {
    return reject(
      REASON_SESSION_AUTHORITY_MISMATCH,
      "session.authority_digest != clearance.authority_digest",
    );
  }
  if (session.capability_manifest_digest !== sha256Digest(manifest)) {
    return reject(
      REASON_SESSION_CAPABILITY_MANIFEST_MISMATCH,
      "session does not bind the supplied capability manifest",
    );
  }
  if (session.environment_profile_digest !== sha256Digest(profile)) {
    return reject(
      REASON_SESSION_ENVIRONMENT_PROFILE_MISMATCH,
      "session does not bind the supplied environment profile",
    );
  }
  if (session.governance_evaluation_digest !== sha256Digest(evaluation)) {
    return reject(
      REASON_SESSION_EVALUATION_MISMATCH,
      "session does not bind the supplied GovernanceEvaluation",
    );
  }
  if (session.reht_clearance_digest !== sha256Digest(clearance)) {
    return reject(
      REASON_SESSION_CLEARANCE_MISMATCH,
      "session does not bind the supplied GovernanceClearance",
    );
  }

  if (
    profile.tenant_id !== evaluation.tenant_id ||
    profile.tenant_id !== clearance.tenant_id
  ) {
    return reject(
      REASON_SESSION_TENANT_MISMATCH,
      "profile, evaluation and clearance tenant bindings differ",
    );
  }
  if (!manifest.executor_binding.allowed_executor_ids.includes(session.executor_id)) {
    return reject(
      REASON_SESSION_EXECUTOR_NOT_ALLOWED,
      "executor_id is outside the admitted executor binding",
    );
  }
  if (!manifest.permissions.includes(clearance.capability)) {
    return reject(
      REASON_SESSION_CAPABILITY_NOT_PERMITTED,
      "clearance capability is not admitted by the manifest",
    );
  }
  if (
    !manifest.consequence_classes.includes(clearance.consequence_class) ||
    !profile.allowed_consequence_classes.includes(clearance.consequence_class)
  ) {
    return reject(
      REASON_SESSION_CONSEQUENCE_NOT_ALLOWED,
      "consequence class is outside manifest or environment admission",
    );
  }

  const profileRefs = new Set([
    profile.profile_id,
    `${profile.profile_id}@${profile.profile_version}`,
  ]);
  if (!manifest.environment_profile_refs.some((value) => profileRefs.has(value))) {
    return reject(
      REASON_SESSION_PROFILE_NOT_REFERENCED,
      "manifest does not reference the bound environment profile",
    );
  }

  const executableClearance =
    (clearance.decision === "ALLOW" || clearance.decision === "MODIFY") &&
    (clearance.admissibility_state === "ADMISSIBLE" ||
      clearance.admissibility_state === "CONDITIONALLY_ADMISSIBLE") &&
    (evaluation.decision === "ALLOW" || evaluation.decision === "MODIFY");
  if (!executableClearance) {
    return reject(
      REASON_SESSION_CLEARANCE_NOT_EXECUTABLE,
      "evaluation or clearance is not executable",
    );
  }

  try {
    const now = nowAt(verificationTime);
    const windows: Array<[string, string]> = [
      [manifest.issued_at, manifest.expires_at],
      [profile.valid_from, profile.expires_at],
      [clearance.valid_from, clearance.valid_until],
      [evaluation.evaluated_at, evaluation.valid_until],
    ];
    if (!windows.every(([start, end]) => isCurrent(now, start, end))) {
      return reject(
        REASON_SESSION_ARTIFACT_NOT_CURRENT,
        "one or more bound artifacts are not current at verification time",
      );
    }
  } catch (error) {
    return reject(REASON_SESSION_ARTIFACT_NOT_CURRENT, (error as Error).message);
  }

  try {
    const authorizationDeadline = Math.min(
      parseTime(manifest.expires_at),
      parseTime(profile.expires_at),
      parseTime(evaluation.valid_until),
      parseTime(clearance.valid_until),
    );
    if (parseTime(session.must_complete_by) > authorizationDeadline) {
      return reject(
        REASON_SESSION_DEADLINE_EXCEEDS_AUTHORIZATION,
        "session deadline exceeds a bound artifact validity window",
      );
    }
  } catch (error) {
    return reject(
      REASON_SESSION_DEADLINE_EXCEEDS_AUTHORIZATION,
      (error as Error).message,
    );
  }

  return accept();
}

class BoundsFailure extends Error {
  constructor(readonly reasonCode: string, message: string) {
    super(message);
  }
}

export function proveRuntimeBoundsNarrowing(
  currentBounds: Record<string, unknown>,
  proposedBounds: Record<string, unknown>,
): ContinuityVerificationResult {
  try {
    const changed = proveMapping(currentBounds, proposedBounds, "");
    if (!changed) {
      return reject(
        REASON_BOUNDS_NOT_NARROWER,
        "MODIFY_RUNTIME_BOUNDS must make at least one bound stricter",
      );
    }
    return accept(REASON_BOUNDS_NARROWED, proposedBounds);
  } catch (error) {
    const failure = error as BoundsFailure;
    return reject(failure.reasonCode, failure.message);
  }
}

function proveMapping(
  current: Record<string, unknown>,
  proposed: Record<string, unknown>,
  path: string,
): boolean {
  let changed = false;
  for (const [key, proposedValue] of Object.entries(proposed)) {
    const itemPath = path.length === 0 ? key : `${path}.${key}`;
    if (!Object.prototype.hasOwnProperty.call(current, key)) {
      throw new BoundsFailure(
        REASON_BOUNDS_UNPROVABLE,
        `${itemPath}: dimension is not present in the current bounds`,
      );
    }
    changed = proveValue(key, current[key], proposedValue, itemPath) || changed;
  }
  return changed;
}

function proveValue(
  key: string,
  current: unknown,
  proposed: unknown,
  path: string,
): boolean {
  if (typeof current === "boolean" || typeof proposed === "boolean") {
    if (typeof current !== typeof proposed) {
      throw new BoundsFailure(REASON_BOUNDS_UNPROVABLE, `${path}: type changed`);
    }
    if (current !== proposed) {
      throw new BoundsFailure(
        REASON_BOUNDS_UNPROVABLE,
        `${path}: boolean direction is not declared`,
      );
    }
    return false;
  }

  if (typeof current === "number" && typeof proposed === "number") {
    const minimumDimension =
      key.startsWith("min_") || key.includes("minimum") || key.includes("floor");
    if (minimumDimension) {
      if (proposed < current) {
        throw new BoundsFailure(REASON_BOUNDS_WIDENED, `${path}: minimum decreased`);
      }
      return proposed > current;
    }
    if (proposed > current) {
      throw new BoundsFailure(REASON_BOUNDS_WIDENED, `${path}: upper bound increased`);
    }
    return proposed < current;
  }

  if (typeof current === "string" && typeof proposed === "string") {
    const timeKey =
      TIME_KEYS.has(key) ||
      key.endsWith("_deadline") ||
      key.endsWith("_expires_at") ||
      key.endsWith("_valid_until");
    if (timeKey) {
      let currentTime: number;
      let proposedTime: number;
      try {
        currentTime = parseTime(current);
        proposedTime = parseTime(proposed);
      } catch {
        throw new BoundsFailure(
          REASON_BOUNDS_UNPROVABLE,
          `${path}: invalid time bound`,
        );
      }
      if (proposedTime > currentTime) {
        throw new BoundsFailure(REASON_BOUNDS_WIDENED, `${path}: deadline moved later`);
      }
      return proposedTime < currentTime;
    }
    if (current !== proposed) {
      throw new BoundsFailure(
        REASON_BOUNDS_UNPROVABLE,
        `${path}: string direction is not declared`,
      );
    }
    return false;
  }

  if (isRecord(current) && isRecord(proposed)) {
    return proveMapping(current, proposed, path);
  }

  if (Array.isArray(current) && Array.isArray(proposed)) {
    const currentSet = scalarSet(current, path);
    const proposedSet = scalarSet(proposed, path);
    for (const value of proposedSet) {
      if (!currentSet.has(value)) {
        throw new BoundsFailure(REASON_BOUNDS_WIDENED, `${path}: allowed set expanded`);
      }
    }
    if (currentSet.size !== proposedSet.size) return true;
    return [...currentSet].some((value) => !proposedSet.has(value));
  }

  if (current === null || proposed === null) {
    if (current !== proposed) {
      throw new BoundsFailure(REASON_BOUNDS_UNPROVABLE, `${path}: nullability changed`);
    }
    return false;
  }

  if (typeof current !== typeof proposed) {
    throw new BoundsFailure(REASON_BOUNDS_UNPROVABLE, `${path}: type changed`);
  }
  if (Object.is(current, proposed)) return false;
  throw new BoundsFailure(
    REASON_BOUNDS_UNPROVABLE,
    `${path}: narrowing semantics are not declared`,
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function scalarSet(values: unknown[], path: string): Set<string> {
  const result = new Set<string>();
  for (const value of values) {
    if (
      typeof value !== "string" &&
      typeof value !== "number" &&
      typeof value !== "boolean" &&
      value !== null
    ) {
      throw new BoundsFailure(
        REASON_BOUNDS_UNPROVABLE,
        `${path}: complex list membership cannot be proven`,
      );
    }
    result.add(`${typeof value}:${String(value)}`);
  }
  return result;
}

export function verifyContinuityDecision(
  session: GovernedExecutionSession,
  decision: ContinuityDecision,
  currentBounds: Record<string, unknown>,
  verificationTime?: string,
): ContinuityVerificationResult {
  if (TERMINAL_STATES.has(session.session_state)) {
    return reject(
      REASON_SESSION_TERMINAL,
      `session_state=${session.session_state} is terminal`,
    );
  }
  if (decision.session_id !== session.session_id) {
    return reject(
      REASON_DECISION_SESSION_MISMATCH,
      "decision.session_id != session.session_id",
    );
  }
  if (decision.continuity_sequence !== session.continuity_sequence + 1) {
    return reject(
      REASON_DECISION_SEQUENCE_MISMATCH,
      "continuity sequence must advance by exactly one",
    );
  }
  if (decision.action_envelope_digest !== session.action_envelope_digest) {
    return reject(
      REASON_DECISION_ACTION_MISMATCH,
      "decision action binding differs from the session",
    );
  }
  if (decision.capability_manifest_digest !== session.capability_manifest_digest) {
    return reject(
      REASON_DECISION_CAPABILITY_MISMATCH,
      "decision capability binding differs from the session",
    );
  }
  if (decision.environment_profile_digest !== session.environment_profile_digest) {
    return reject(
      REASON_DECISION_ENVIRONMENT_MISMATCH,
      "decision environment binding differs from the session",
    );
  }
  if (decision.authority_state_digest !== session.authority_digest) {
    return reject(
      REASON_DECISION_AUTHORITY_MISMATCH,
      "decision authority state differs from the session",
    );
  }

  try {
    const validUntil = parseTime(decision.valid_until);
    if (validUntil < nowAt(verificationTime)) {
      return reject(REASON_DECISION_EXPIRED, "continuity decision is expired");
    }
    if (validUntil > parseTime(session.must_complete_by)) {
      return reject(
        REASON_DECISION_OUTLIVES_SESSION,
        "continuity decision cannot outlive the session",
      );
    }
  } catch (error) {
    return reject(REASON_DECISION_EXPIRED, (error as Error).message);
  }

  if (decision.decision === "MODIFY_RUNTIME_BOUNDS") {
    if (!isRecord(decision.constraints)) {
      return reject(
        REASON_BOUNDS_UNPROVABLE,
        "MODIFY_RUNTIME_BOUNDS has no object constraints",
      );
    }
    return proveRuntimeBoundsNarrowing(currentBounds, decision.constraints);
  }

  return accept();
}
