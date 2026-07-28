import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as AjvNs from "ajv/dist/2020.js";
import * as addFormatsNs from "ajv-formats";
import {
  ContinuityDecision,
  EnvironmentGovernanceProfile,
  GovernedCapabilityManifest,
  GovernedExecutionSession,
  InterventionReceipt,
  RecoveryPlan,
  RecoveryReceipt,
  RuntimeObservation,
} from "../src/index.js";

const Ajv2020 = (AjvNs as any).default ?? AjvNs;
const addFormats = (addFormatsNs as any).default ?? addFormatsNs;

interface CanonicalModel { canonical(): string; digest(): string; }
type Constructor = new () => CanonicalModel;

const repoRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..", "..", "..", "..", "..", ".."
);
const vectorPath = join(
  repoRoot, "test-vectors", "0.2", "runtime-continuity", "canonical-vectors.json"
);
const vectorDocument = JSON.parse(readFileSync(vectorPath, "utf-8")) as {
  vectors: Array<{
    name: string;
    payload: Record<string, unknown>;
    canonical: string;
    payload_digest: string;
  }>;
};

const constructors: Record<string, Constructor> = {
  governed_capability_manifest: GovernedCapabilityManifest,
  environment_governance_profile: EnvironmentGovernanceProfile,
  governed_execution_session: GovernedExecutionSession,
  runtime_observation: RuntimeObservation,
  continuity_decision: ContinuityDecision,
  intervention_receipt: InterventionReceipt,
  recovery_plan: RecoveryPlan,
  recovery_receipt: RecoveryReceipt,
};

test("runtime continuity models reproduce shared canonical vectors", () => {
  for (const vector of vectorDocument.vectors) {
    const Constructor = constructors[vector.name];
    assert.ok(Constructor, `missing constructor for ${vector.name}`);
    const model = Object.assign(new Constructor(), vector.payload);
    assert.equal(model.canonical(), vector.canonical, vector.name);
    assert.equal(model.digest(), vector.payload_digest, vector.name);
  }
});

function compileSchema(filename: string) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv.compile(
    JSON.parse(readFileSync(join(repoRoot, "spec", filename), "utf-8"))
  );
}

test("CONTINUE cannot add new constraints", () => {
  const validate = compileSchema("continuity-decision-v0.2.schema.json");
  const base = vectorDocument.vectors.find(v => v.name === "continuity_decision");
  assert.ok(base);
  const invalid = { ...base.payload, constraints: { max_speed_mm_s: 900 } };
  assert.equal(validate(invalid), false);
});

test("RecoveryPlan cannot carry execution authority", () => {
  const validate = compileSchema("recovery-plan-v0.2.schema.json");
  const base = vectorDocument.vectors.find(v => v.name === "recovery_plan");
  assert.ok(base);
  const invalid = { ...base.payload, carries_execution_authority: true };
  assert.equal(validate(invalid), false);
});

test("RuntimeObservation requires exactly one signal representation", () => {
  const validate = compileSchema("runtime-observation-v0.2.schema.json");
  const base = vectorDocument.vectors.find(v => v.name === "runtime_observation");
  assert.ok(base);
  const invalid = {
    ...base.payload,
    signal_digest: "sha256:" + "f".repeat(64),
  };
  assert.equal(validate(invalid), false);
});
