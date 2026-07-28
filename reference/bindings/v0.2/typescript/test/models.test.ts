import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  GovernanceEvaluation,
  sha256Digest,
  canonicalString,
  type Canonicalizable,
} from "../src/index.js";

const repoRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..", "..", "..", "..", "..", "..",
);
const GOLDEN = join(
  repoRoot,
  "test-vectors",
  "0.2",
  "governance-evaluation-golden.json",
);
const STEP2_DIGEST =
  "sha256:532d2a571f8536890bf9b79994703c63a44c01ba40f71b4733d045674bdb3273";

test("GovernanceEvaluation reproduces boundary-aware golden digest", () => {
  const vector = JSON.parse(readFileSync(GOLDEN, "utf-8"));
  const payload = vector.payload as Record<string, unknown>;
  const evaluation = Object.assign(
    new GovernanceEvaluation(),
    payload,
  ) as GovernanceEvaluation;

  assert.equal(evaluation.decision, "ALLOW");
  assert.equal(evaluation.authority_status, "PRESENT_AND_VALID");
  assert.equal(
    evaluation.boundary_assessment_binding.assessment_ref,
    "bca:gv_allow",
  );
  assert.equal(canonicalString(evaluation), canonicalString(payload));
  assert.equal(evaluation.digest(), sha256Digest(payload));
  assert.equal(evaluation.digest(), STEP2_DIGEST);
});

test("typed evaluation includes mandatory assessment binding", () => {
  const evaluation = Object.assign(new GovernanceEvaluation(), {
    evaluation_id: "e1",
    action_id: "a1",
    action_envelope_digest: "sha256:" + "0".repeat(64),
    tenant_id: "t1",
    evaluator_id: "ev1",
    evaluator_version: "v1",
    decision: "ALLOW",
    authority_status: "PRESENT_AND_VALID",
    policy_status: "PRESENT_AND_VALID",
    evidence_status: "PRESENT_AND_VALID",
    purpose_status: "PRESENT_AND_VALID",
    state_status: "PRESENT_AND_VALID",
    risk_status: "PRESENT_AND_VALID",
    boundary_assessment_binding: {
      assessment_ref: "bca-1",
      assessment_digest: "sha256:" + "1".repeat(64),
    },
    evaluated_at: "2026-07-23T00:00:00Z",
    valid_until: "2026-08-23T00:00:00Z",
  });
  assert.ok(
    (evaluation as unknown as Canonicalizable).digest().startsWith("sha256:"),
  );
});
