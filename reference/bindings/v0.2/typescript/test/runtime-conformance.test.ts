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

const repoRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "..",
  "..",
  "..",
);

function loadVectors(directory: string): any[] {
  const base = join(
    repoRoot,
    "test-vectors",
    "0.2",
    "runtime-validation",
    directory,
  );
  const vectors: any[] = [];
  for (const filename of readdirSync(base)) {
    if (!filename.endsWith(".json")) continue;
    vectors.push(JSON.parse(readFileSync(join(base, filename), "utf-8")));
  }
  vectors.sort((left, right) =>
    (left["id"] as string).localeCompare(right["id"] as string),
  );
  return vectors;
}

test("RACS 3C conformance matrix (shared vectors)", () => {
  const directories = [
    "governance-evaluation",
    "admissibility-determination",
    "governance-clearance",
    "cross-artifact-bindings",
  ];
  for (const directory of directories) {
    for (const vector of loadVectors(directory)) {
      const artifactType = vector["artifact_type"] as string;
      const expected = vector["expected"] as string;
      const reason = vector["reason_code"] as string;
      const payload = vector["payload"];
      const vectorId = vector["id"] as string;
      const verificationTime = vector["verification_time"] as string | undefined;

      if (vectorId.startsWith("chain_reject_")) continue;

      const result = check(artifactType, payload);
      assert.equal(
        result.decision,
        expected,
        `Port A decision mismatch for ${vectorId}`,
      );

      if (expected === "ACCEPT" && artifactType !== "GovernanceClearance") {
        assert.equal(result.reason_code, "ACCEPT");
        assert.ok(
          (result.payload_digest || "").startsWith("sha256:"),
          `digest missing for ${vectorId}`,
        );
        continue;
      }

      const resolved = vector["resolved"];
      if (resolved) {
        if (artifactType === "GovernanceClearance") {
          const clearance = payload as GovernanceClearance;
          const determination =
            resolved["determination"] as AdmissibilityDetermination;
          const evaluation = resolved["evaluation"] as GovernanceEvaluation;
          const evaluationBinding = verifyEvaluationBinding(
            determination,
            evaluation,
          );
          const clearanceBinding = verifyClearanceBinding(
            clearance,
            determination,
            undefined,
            verificationTime,
          );
          if (expected === "ACCEPT") {
            assert.equal(
              evaluationBinding.decision,
              "ACCEPT",
              `eval binding: ${evaluationBinding.detail}`,
            );
            assert.equal(
              clearanceBinding.decision,
              "ACCEPT",
              `clearance binding: ${clearanceBinding.detail}`,
            );
            assert.equal(clearanceBinding.reason_code, "ACCEPT");
          } else {
            const decided =
              evaluationBinding.decision === "REJECT"
                ? evaluationBinding
                : clearanceBinding;
            assert.equal(decided.decision, expected, `${decided.detail}`);
            assert.equal(decided.reason_code, reason, "reason mismatch");
          }
        } else if (artifactType === "AdmissibilityDetermination") {
          const determination = payload as AdmissibilityDetermination;
          const evaluation = resolved["evaluation"] as GovernanceEvaluation;
          const evaluationBinding = verifyEvaluationBinding(
            determination,
            evaluation,
          );
          assert.equal(
            evaluationBinding.decision,
            expected,
            `${evaluationBinding.detail}`,
          );
          assert.equal(evaluationBinding.reason_code, reason, "reason mismatch");
        }
        continue;
      }

      if (expected === "ACCEPT") {
        assert.equal(result.reason_code, "ACCEPT");
        assert.ok((result.payload_digest || "").startsWith("sha256:"));
        continue;
      }

      assert.equal(
        result.reason_code,
        reason,
        `reason mismatch for ${vectorId}`,
      );
    }
  }

  schemaSha256("GovernanceEvaluation");
});
