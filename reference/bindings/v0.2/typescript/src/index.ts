import { canonicalize } from "json-canonicalize";
import { createHash } from "node:crypto";

/**
 * RACS v0.2 canonical contract bindings — canonicalization kernel (3A).
 *
 * Uses `json-canonicalize` (RFC 8785 / JCS). No model types (3B) and no
 * signing/trust logic. Canonical output MUST be byte-for-byte identical across
 * the Python, Rust, and TypeScript bindings.
 */

/** RFC 8785 canonical UTF-8 string for a JSON value. */
export function canonicalString(value: unknown): string {
  return canonicalize(value);
}

/** RFC 8785 canonical UTF-8 bytes for a JSON value. */
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), "utf-8");
}

/** SHA-256 over the RFC 8785 canonical bytes, as "sha256:<hex>". */
export function sha256Digest(value: unknown): string {
  const h = createHash("sha256");
  h.update(canonicalBytes(value));
  return "sha256:" + h.digest("hex");
}

/** Verify payload_digest equals the SHA-256 of the canonical payload. */
export function verifyPayloadDigest(payload: unknown, payloadDigest: string): boolean {
  return sha256Digest(payload) === payloadDigest;
}
