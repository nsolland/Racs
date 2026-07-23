#!/usr/bin/env node
// Conformance CLI: reads JCS vectors and emits canonical + digest.
//   racs-v02 --vector <jcs-vector-file>  -> {got_canonical,got_digest,...,match}
//   racs-v02 --file <json-file>          -> {canonical, digest}
import { readFileSync } from "node:fs";
import { canonicalString, sha256Digest } from "./index.js";

function die(msg: string): never {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(2);
}

const mode = process.argv[2];
const path = process.argv[3];

if (mode === "--vector" && path) {
  const raw = JSON.parse(readFileSync(path, "utf-8"));
  // support both official JCS vectors and RACS payload vectors
  const subject = raw.input ?? raw.payload;
  const expCanon = raw.expected_canonical ?? raw.canonical_payload;
  const expDigest = raw.expected_digest ?? raw.payload_digest;
  const gotCanon = canonicalString(subject);
  const gotDigest = sha256Digest(subject);
  const ok = gotCanon === expCanon && gotDigest === expDigest;
  console.log(
    JSON.stringify({
      got_canonical: gotCanon,
      got_digest: gotDigest,
      expected_canonical: expCanon,
      expected_digest: expDigest,
      match: ok,
    }, null, 2)
  );
  if (!ok) process.exit(1);
} else if (mode === "--file" && path) {
  const val = JSON.parse(readFileSync(path, "utf-8"));
  console.log(JSON.stringify({ canonical: canonicalString(val), digest: sha256Digest(val) }));
} else {
  die("usage: racs-v02 (--vector <file> | --file <file>)");
}
