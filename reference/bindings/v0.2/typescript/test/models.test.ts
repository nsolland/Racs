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

// repo root: dist/test -> typescript(1) -> v0.2(2) -> bindings(3) -> reference(4) -> Racs(5) -> (6 extra for safety)
const repoRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..", "..", "..", "..", "..", ".."
);
const GOLDEN = join(
  repoRoot, "test-vectors", "0.2", "governance-evaluation-golden.json"
);
const STEP2_DIGEST =
  "sha256:58c8431515435642ee92d148a0636f2b20c5292c843fc8977a1fda3f5d94644c";

test("GovernanceEvaluation class parses golden and reproduces step-2 digest", () => {
  const v = JSON.parse(readFileSync(GOLDEN, "utf-8"));
  const payload = v.payload as Record<string, unknown>;
  const ev = Object.assign(new GovernanceEvaluation(), payload) as GovernanceEvaluation;

  assert.equal(ev.decision, "ALLOW");
  assert.equal(ev.authority_status, "PRESENT_AND_VALID");

  // canonical of the typed model must match canonical of the raw payload dict
  assert.equal(canonicalString(ev), canonicalString(payload));
  assert.equal(ev.digest(), sha256Digest(payload));
  assert.equal(ev.digest(), STEP2_DIGEST);
});

test("typed models implement Canonicalizable and round-trip digest", () => {
  const ev = Object.assign(new GovernanceEvaluation(), {
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
    evaluated_at: "2026-07-23T00:00:00Z",
    valid_until: "2026-08-23T00:00:00Z",
  });
  assert.ok((ev as unknown as Canonicalizable).digest().startsWith("sha256:"));
});
