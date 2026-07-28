import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  proveRuntimeBoundsNarrowing,
  verifyContinuityDecision,
  verifyExecutionSession,
} from "../src/continuity-verification.js";
import type {
  ContinuityDecision,
  EnvironmentGovernanceProfile,
  GovernedCapabilityManifest,
  GovernedExecutionSession,
} from "../src/continuity.js";
import type {
  GovernanceClearance,
  GovernanceEvaluation,
} from "../src/index.js";

const repoRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "..",
  "..",
  "..",
);
const vectorPath = join(
  repoRoot,
  "test-vectors",
  "0.2",
  "runtime-continuity",
  "verification-vectors.json",
);
const document = JSON.parse(readFileSync(vectorPath, "utf-8"));

function mutate(root: Record<string, any>, mutations: Record<string, unknown>): void {
  for (const [dottedPath, value] of Object.entries(mutations)) {
    const parts = dottedPath.split(".");
    let node: Record<string, any> = root;
    for (const part of parts.slice(0, -1)) node = node[part];
    node[parts[parts.length - 1]] = value;
  }
}

function models(mutations: Record<string, unknown> = {}) {
  const artifacts = structuredClone(document.artifacts);
  mutate(artifacts, mutations);
  return {
    manifest: artifacts.manifest as GovernedCapabilityManifest,
    profile: artifacts.profile as EnvironmentGovernanceProfile,
    evaluation: artifacts.evaluation as GovernanceEvaluation,
    clearance: artifacts.clearance as GovernanceClearance,
    session: artifacts.session as GovernedExecutionSession,
    decision: artifacts.decision as ContinuityDecision,
  };
}

test("Stage 2 session verification vectors", () => {
  for (const vector of document.session_cases) {
    const value = models(vector.mutations);
    const result = verifyExecutionSession(
      value.session,
      value.manifest,
      value.profile,
      value.evaluation,
      value.clearance,
      document.verification_time,
    );
    assert.equal(result.decision, vector.expected, vector.id);
    assert.equal(result.reason_code, vector.reason_code, vector.id);
  }
});

test("Stage 2 monotone runtime-bound vectors", () => {
  for (const vector of document.bounds_cases) {
    const result = proveRuntimeBoundsNarrowing(vector.current, vector.proposed);
    assert.equal(result.decision, vector.expected, vector.id);
    assert.equal(result.reason_code, vector.reason_code, vector.id);
  }
});

test("Stage 2 continuity-decision vectors", () => {
  for (const vector of document.decision_cases) {
    const value = models(vector.mutations);
    const result = verifyContinuityDecision(
      value.session,
      value.decision,
      value.profile.runtime_limits as Record<string, unknown>,
      document.verification_time,
    );
    assert.equal(result.decision, vector.expected, vector.id);
    assert.equal(result.reason_code, vector.reason_code, vector.id);
  }
});
