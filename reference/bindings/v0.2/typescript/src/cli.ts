#!/usr/bin/env node
// Conformance CLI for canonicalization and Stage 3C runtime vectors.
//   racs-v02 --vector <jcs-vector-file>
//   racs-v02 --file <json-file>
//   racs-v02 --model-digest <golden-file>
//   racs-v02 --check <runtime-vector-file>
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
  GovernanceClearance,
} from "./index.js";

function die(msg: string): never {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(2);
}

function runtimeCheck(vec: any): Record<string, unknown> {
  const artifactType = vec["artifact_type"] as string;
  const payload = vec["payload"];
  const portA = check(artifactType, payload);

  let decision = portA.decision;
  let reasonCode = portA.reason_code;

  if (decision === "ACCEPT" && vec["resolved"]) {
    const resolved = vec["resolved"];

    if (artifactType === "GovernanceClearance") {
      const clearance = payload as GovernanceClearance;
      const determination = resolved["determination"] as AdmissibilityDetermination;
      const evaluation = resolved["evaluation"] as GovernanceEvaluation;
      let verification = verifyEvaluationBinding(determination, evaluation);
      if (verification.decision === "ACCEPT") {
        verification = verifyClearanceBinding(clearance, determination, undefined);
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

  const out: Record<string, unknown> = {
    id: vec["id"],
    decision,
    reason_code: reasonCode,
  };
  if (decision === "ACCEPT") {
    if (portA.canonical !== undefined) out["canonical"] = portA.canonical;
    if (portA.payload_digest !== undefined) {
      out["payload_digest"] = portA.payload_digest;
    }
  }

  const expected = vec["expected"];
  const expectedReason = vec["reason_code"];
  out["expected"] = expected;
  out["expected_reason_code"] = expectedReason;
  out["match"] = decision === expected && reasonCode === expectedReason;
  return out;
}

const mode = process.argv[2];
const path = process.argv[3];

if (mode === "--vector" && path) {
  const raw = JSON.parse(readFileSync(path, "utf-8"));
  const subject = raw.input ?? raw.payload;
  const expCanon = raw.expected_canonical ?? raw.canonical_payload;
  const expDigest = raw.expected_digest ?? raw.payload_digest;
  const gotCanon = canonicalString(subject);
  const gotDigest = sha256Digest(subject);
  const ok = gotCanon === expCanon && gotDigest === expDigest;
  console.log(
    JSON.stringify(
      {
        got_canonical: gotCanon,
        got_digest: gotDigest,
        expected_canonical: expCanon,
        expected_digest: expDigest,
        match: ok,
      },
      null,
      2,
    ),
  );
  if (!ok) process.exit(1);
} else if (mode === "--file" && path) {
  const val = JSON.parse(readFileSync(path, "utf-8"));
  console.log(
    JSON.stringify({ canonical: canonicalString(val), digest: sha256Digest(val) }),
  );
} else if (mode === "--model-digest" && path) {
  const raw = JSON.parse(readFileSync(path, "utf-8"));
  const payload = raw.payload as Record<string, unknown>;
  const ev = Object.assign(
    new GovernanceEvaluation(),
    payload,
  ) as GovernanceEvaluation;
  console.log(JSON.stringify({ digest: ev.digest() }));
} else if (mode === "--check" && path) {
  const vec = JSON.parse(readFileSync(path, "utf-8"));
  const out = runtimeCheck(vec);
  console.log(JSON.stringify(out, null, 2));
  if (out["match"] !== true) process.exit(1);
} else {
  die(
    "usage: racs-v02 (--vector <file> | --file <file> | --model-digest <golden-file> | --check <runtime-vector-file>)",
  );
}
