import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  check,
  schemaSha256,
  verifyClearanceBinding,
  verifyEvaluationBinding,
} from "../src/index.js";
import type {
  AdmissibilityDetermination,
  GovernanceClearance,
  GovernanceEvaluation,
} from "../src/index.js";

// repo root: dist/test -> typescript(1) -> v0.2(2) -> bindings(3) -> reference(4) -> Racs(5)
const repoRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "..",
  "..",
  "..",
);

function loadVectors(dir: string): any[] {
  const base = join(repoRoot, "test-vectors", "0.2", "runtime-validation", dir);
  const out: any[] = [];
  for (const f of readdirSync(base)) {
    if (!f.endsWith(".json")) continue;
    out.push(JSON.parse(readFileSync(join(base, f), "utf-8")));
  }
  out.sort((a, b) => (a["id"] as string).localeCompare(b["id"] as string));
  return out;
}

test("RACS 3C conformance matrix (shared vectors)", () => {
  const dirs = [
    "governance-evaluation",
    "admissibility-determination",
    "governance-clearance",
    "cross-artifact-bindings",
  ];
  for (const dir of dirs) {
    for (const vec of loadVectors(dir)) {
      const artifactType = vec["artifact_type"] as string;
      const expected = vec["expected"] as string;
      const reason = vec["reason_code"] as string;
      const payload = vec["payload"];
      const vecId = vec["id"] as string;

      // `chain_reject_*` vectors are cross-artifact (Port B) rejections:
      // Port A schema/intra checks must NOT reject them. Skip in Port A.
      if (vecId.startsWith("chain_reject_")) continue;

      // Port A
      const res = check(artifactType, payload);
      assert.equal(res.decision, expected, `Port A decision mismatch for ${vecId}`);

      if (expected === "ACCEPT" && artifactType !== "GovernanceClearance") {
        assert.equal(res.reason_code, "ACCEPT");
        assert.ok(
          (res.payload_digest || "").startsWith("sha256:"),
          `digest missing for ${vecId}`,
        );
        continue;
      }

      // Resolved cross-artifact vectors go through Port B.
      const resolved = vec["resolved"];
      if (resolved) {
        if (artifactType === "GovernanceClearance") {
          const clr = payload as GovernanceClearance;
          const det = resolved["determination"] as AdmissibilityDetermination;
          const ev = resolved["evaluation"] as GovernanceEvaluation;
          const eb = verifyEvaluationBinding(det, ev);
          if (expected === "ACCEPT") {
            assert.equal(eb.decision, "ACCEPT", `eval binding: ${eb.detail}`);
            const cb = verifyClearanceBinding(clr, det, undefined);
            assert.equal(cb.decision, "ACCEPT", `clearance binding: ${cb.detail}`);
            assert.equal(cb.reason_code, "ACCEPT");
          } else {
            const decided = eb.decision === "REJECT" ? eb : verifyClearanceBinding(clr, det, undefined);
            assert.equal(decided.decision, expected, `${decided.detail}`);
            assert.equal(decided.reason_code, reason, "reason mismatch");
          }
        } else if (artifactType === "AdmissibilityDetermination") {
          const det = payload as AdmissibilityDetermination;
          const ev = resolved["evaluation"] as GovernanceEvaluation;
          const eb = verifyEvaluationBinding(det, ev);
          assert.equal(eb.decision, expected, `${eb.detail}`);
          assert.equal(eb.reason_code, reason, "reason mismatch");
        }
        continue;
      }

      // Non-resolved ACCEPT clearance only needs Port A.
      if (expected === "ACCEPT") {
        assert.equal(res.reason_code, "ACCEPT");
        assert.ok((res.payload_digest || "").startsWith("sha256:"));
        continue;
      }

      // Non-resolved REJECT (schema or intra-semantic) — reason must match.
      assert.equal(res.reason_code, reason, `reason mismatch for ${vecId}`);
    }
  }

  // Schema manifest pins are stable.
  schemaSha256("GovernanceEvaluation");
});
