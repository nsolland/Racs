#!/usr/bin/env node
import { readFileSync } from "node:fs";
import {
  canonicalString,
  sha256Digest,
  GovernanceEvaluation,
  check,
  verifyClearanceBinding,
  verifyEvaluationBinding,
} from "./index.js";
import type {
  AdmissibilityDetermination,
  BoundaryCrossingAssessment,
  GovernanceClearance,
} from "./index.js";

function die(message: string): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(2);
}

function runtimeCheck(vector: any): Record<string, unknown> {
  const artifactType = vector["artifact_type"] as string;
  const payload = vector["payload"];
  const verificationTime = vector["verification_time"] as string | undefined;
  const portA = check(artifactType, payload);

  let decision = portA.decision;
  let reasonCode = portA.reason_code;

  if (decision === "ACCEPT" && vector["resolved"]) {
    const resolved = vector["resolved"];

    if (artifactType === "GovernanceClearance") {
      const clearance = payload as GovernanceClearance;
      const determination =
        resolved["determination"] as AdmissibilityDetermination;
      const evaluation = resolved["evaluation"] as GovernanceEvaluation;
      const actionEnvelope =
        resolved["action_envelope"] as Record<string, unknown> | undefined;
      const boundaryAssessment =
        resolved["boundary_assessment"] as BoundaryCrossingAssessment | undefined;

      let verification = verifyEvaluationBinding(determination, evaluation);
      if (verification.decision === "ACCEPT") {
        verification = verifyClearanceBinding(
          clearance,
          determination,
          actionEnvelope,
          verificationTime,
          evaluation,
          boundaryAssessment,
        );
      }
      if (verification.decision === "REJECT") {
        decision = verification.decision;
        reasonCode = verification.reason_code;
      }
    } else if (artifactType === "AdmissibilityDetermination") {
      const determination = payload as AdmissibilityDetermination;
      const evaluation = resolved["evaluation"] as GovernanceEvaluation;
      const verification = verifyEvaluationBinding(determination, evaluation);
      if (verification.decision === "REJECT") {
        decision = verification.decision;
        reasonCode = verification.reason_code;
      }
    }
  }

  const output: Record<string, unknown> = {
    id: vector["id"],
    decision,
    reason_code: reasonCode,
  };
  if (decision === "ACCEPT") {
    if (portA.canonical !== undefined) output["canonical"] = portA.canonical;
    if (portA.payload_digest !== undefined) {
      output["payload_digest"] = portA.payload_digest;
    }
  }

  const expected = vector["expected"];
  const expectedReason = vector["reason_code"];
  output["expected"] = expected;
  output["expected_reason_code"] = expectedReason;
  output["match"] = decision === expected && reasonCode === expectedReason;
  return output;
}

const mode = process.argv[2];
const filePath = process.argv[3];

if (mode === "--vector" && filePath) {
  const raw = JSON.parse(readFileSync(filePath, "utf-8"));
  const subject = raw.input ?? raw.payload;
  const expectedCanonical = raw.expected_canonical ?? raw.canonical_payload;
  const expectedDigest = raw.expected_digest ?? raw.payload_digest;
  const gotCanonical = canonicalString(subject);
  const gotDigest = sha256Digest(subject);
  const matches =
    gotCanonical === expectedCanonical && gotDigest === expectedDigest;
  console.log(
    JSON.stringify(
      {
        got_canonical: gotCanonical,
        got_digest: gotDigest,
        expected_canonical: expectedCanonical,
        expected_digest: expectedDigest,
        match: matches,
      },
      null,
      2,
    ),
  );
  if (!matches) process.exit(1);
} else if (mode === "--file" && filePath) {
  const value = JSON.parse(readFileSync(filePath, "utf-8"));
  console.log(
    JSON.stringify({ canonical: canonicalString(value), digest: sha256Digest(value) }),
  );
} else if (mode === "--model-digest" && filePath) {
  const raw = JSON.parse(readFileSync(filePath, "utf-8"));
  const evaluation = Object.assign(
    new GovernanceEvaluation(),
    raw.payload as Record<string, unknown>,
  ) as GovernanceEvaluation;
  console.log(JSON.stringify({ digest: evaluation.digest() }));
} else if (mode === "--check" && filePath) {
  const vector = JSON.parse(readFileSync(filePath, "utf-8"));
  const output = runtimeCheck(vector);
  console.log(JSON.stringify(output, null, 2));
  if (output["match"] !== true) process.exit(1);
} else {
  die(
    "usage: racs-v02 (--vector <file> | --file <file> | --model-digest <golden-file> | --check <runtime-vector-file>)",
  );
}
