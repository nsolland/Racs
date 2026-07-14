# RACS Canonical Serialization — RACS-JCS-1

Status: Draft 0.2 normative profile

## Scope

RACS-JCS-1 defines the byte representation used for digests and signatures on RACS artifacts.

## Rules

1. Input MUST be valid UTF-8 JSON.
2. Objects MUST be serialized using RFC 8785 JSON Canonicalization Scheme semantics.
3. Object member names MUST be sorted lexicographically by Unicode code point.
4. No insignificant whitespace is permitted.
5. Numbers MUST use the shortest valid JSON representation and MUST NOT contain NaN or infinity.
6. Timestamps MUST be UTC RFC 3339 strings with `Z` suffix.
7. Optional fields that are absent MUST be omitted; they MUST NOT be materialized as `null` unless the schema explicitly permits `null`.
8. Digests use SHA-256 over canonical UTF-8 bytes and are represented as `sha256:<lowercase-hex>`.
9. The `payload_digest` is computed over the canonicalized `payload` object only.
10. The artifact signature input is the canonicalized outer artifact with `signature.value` replaced by the empty string.
11. The only signing algorithm in profile 0.2 is Ed25519.
12. Unknown schema versions, canonicalization identifiers or algorithms MUST fail closed for authoritative use.

## Verification order

1. Validate the outer artifact schema.
2. Resolve `issuer_id`, `key_id`, tenant and trust domain.
3. Confirm key validity and revocation status at `issued_at` and verification time.
4. Canonicalize `payload` and compare its SHA-256 digest with `payload_digest`.
5. Canonicalize the outer artifact signature input.
6. Verify the Ed25519 signature.
7. Validate the artifact-specific payload schema.
8. Validate temporal validity, revocation and artifact-specific bindings.

Schema validity alone does not make an artifact authoritative.
