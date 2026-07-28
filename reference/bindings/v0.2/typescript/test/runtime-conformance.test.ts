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
  BoundaryCrossingAssessment,
  GovernanceClearance,
  GovernanceEvaluation,
} from "../src/index.js";

const repoRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..", "..", "..", "..", "..", "..",
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

test("RACS 3C conformance matrix includes boundary chain", () => {
  for (const directory of [
    "governance-evaluation",
    "admissibility-determination",
    "governance-clearance",
    "cross-artifact-bindings",
  ]) {
    for (const vector of loadVectors(directory)) {
      const artifactType = vector["artifact_type"] as string;
      const expected = vector["expected"] as string;
      const reason = vector["reason_code"] as string;
      const payload = vector["payload"];
      const vectorId = vector["id"] as string;
      const verificationTime = vector["verification_time"] as string | undefined;
      const portA = check(artifactType, payload);

      if (!vector["resolved"]) {
        assert.equal(
          portA.decision,
          expected,
          `Port A decision mismatch for ${vectorId}`,
        );
        assert.equal(portA.reason_code, reason);
        if (expected === "ACCEPT") {
          assert.ok((portA.payload_digest || "").startsWith("sha256:"));
        }
        continue;
      }

      assert.equal(
        portA.decision,
        "ACCEPT",
        `resolved vector must pass Port A: ${vectorId}`,
      );
      const resolved = vector["resolved"];

      if (artifactType === "GovernanceClearance") {
        const clearance = payload as GovernanceClearance;
        const determination =
          resolved["determination"] as AdmissibilityDetermination;
        const evaluation = resolved["evaluation"] as GovernanceEvaluation;
        const assessment =
          resolved["boundary_assessment"] as BoundaryCrossingAssessment;
        const actionEnvelope =
          resolved["action_envelope"] as Record<string, unknown>;

        const evaluationBinding = verifyEvaluationBinding(
          determination,
          evaluation,
        );
        const decided =
          evaluationBinding.decision === "REJECT"
            ? evaluationBinding
            : verifyClearanceBinding(
                clearance,
                determination,
                actionEnvelope,
                verificationTime,
                evaluation,
                assessment,
              );

        assert.equal(decided.decision, expected, `${vectorId}: ${decided.detail}`);
        assert.equal(decided.reason_code, reason, `reason mismatch for ${vectorId}`);
      } else if (artifactType === "AdmissibilityDetermination") {
        const determination = payload as AdmissibilityDetermination;
        const evaluation = resolved["evaluation"] as GovernanceEvaluation;
        const decided = verifyEvaluationBinding(determination, evaluation);
        assert.equal(decided.decision, expected);
        assert.equal(decided.reason_code, reason);
      }
    }
  }

  schemaSha256("GovernanceEvaluation");
  schemaSha256("BoundaryCrossingAssessment");
});
