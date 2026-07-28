import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  check,
  sha256Digest,
  verifyBoundaryChain,
} from "../src/index.js";
import type {
  AdmissibilityDetermination,
  BoundaryCrossingAssessment,
  GovernanceEvaluation,
} from "../src/index.js";

const repoRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..", "..", "..", "..", "..", "..",
);

function vector(name: string): any {
  return JSON.parse(
    readFileSync(
      join(
        repoRoot,
        "test-vectors",
        "0.2",
        "runtime-validation",
        "cross-artifact-bindings",
        name,
      ),
      "utf-8",
    ),
  );
}

test("BoundaryCrossingAssessment validates and matches bound digest", () => {
  const chain = vector("chain_accept.json");
  const assessment =
    chain.resolved.boundary_assessment as BoundaryCrossingAssessment;
  const result = check("BoundaryCrossingAssessment", assessment);

  assert.equal(result.decision, "ACCEPT");
  assert.equal(result.reason_code, "ACCEPT");
  assert.equal(
    sha256Digest(assessment),
    chain.resolved.evaluation.boundary_assessment_binding.assessment_digest,
  );
});

test("full boundary chain accepts exact resolved artifacts", () => {
  const chain = vector("chain_accept.json");
  const result = verifyBoundaryChain({
    actionEnvelope: chain.resolved.action_envelope,
    assessment:
      chain.resolved.boundary_assessment as BoundaryCrossingAssessment,
    evaluation: chain.resolved.evaluation as GovernanceEvaluation,
    determination:
      chain.resolved.determination as AdmissibilityDetermination,
    verificationTime: chain.verification_time,
  });
  assert.equal(result.decision, "ACCEPT", result.detail);
});

test("boundary policy mismatch fails closed", () => {
  const chain = vector("chain_reject_boundary_policy_mismatch.json");
  const result = verifyBoundaryChain({
    actionEnvelope: chain.resolved.action_envelope,
    assessment:
      chain.resolved.boundary_assessment as BoundaryCrossingAssessment,
    evaluation: chain.resolved.evaluation as GovernanceEvaluation,
    determination:
      chain.resolved.determination as AdmissibilityDetermination,
    verificationTime: chain.verification_time,
  });
  assert.equal(result.decision, "REJECT");
  assert.equal(result.reason_code, "BOUNDARY_POLICY_MISMATCH");
});
