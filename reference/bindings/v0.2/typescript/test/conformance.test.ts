import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalString, sha256Digest } from "../src/index.js";

// repo root: dist/test -> typescript(1) -> v0.2(2) -> bindings(3) -> reference(4) -> Racs(5)
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "..", "..");

test("official JCS vectors are byte-identical to shared expectations", () => {
  const dir = join(repoRoot, "test-vectors/jcs/official");
  let count = 0;
  for (const f of readdirSync(dir)) {
    if (!f.startsWith("vector-") || !f.endsWith(".json")) continue;
    const vec = JSON.parse(readFileSync(join(dir, f), "utf-8"));
    assert.equal(canonicalString(vec.input), vec.expected_canonical, `canonical ${f}`);
    assert.equal(sha256Digest(vec.input), vec.expected_digest, `digest ${f}`);
    count++;
  }
  assert.ok(count >= 6, `expected >=6 official vectors, got ${count}`);
});

test("RACS GovernanceEvaluation vector", () => {
  const vec = JSON.parse(
    readFileSync(join(repoRoot, "test-vectors/jcs/racs-v0.2/governance-evaluation.json"), "utf-8")
  );
  assert.equal(canonicalString(vec.payload), vec.canonical_payload);
  assert.equal(sha256Digest(vec.payload), vec.payload_digest);
});

test("RFC 8785 specifics (not json.dumps)", () => {
  const s = canonicalString({ a: -0.0, b: 1e-9, c: "€" });
  assert.ok(s.includes('"a":0'), "RFC 8785 renders -0.0 as 0");
  assert.ok(s.includes('"b":1e-9'), "RFC 8785 shortest exponent");
  assert.ok(s.includes("€"), "RFC 8785 non-ASCII 'as is'");
});
