//! RACS v0.2 canonical contract bindings — canonicalization kernel (3A).
//!
//! Provides RFC 8785 (JCS) canonicalization via `serde_jcs`, plus SHA-256
//! payload digests. No model types (those arrive in 3B) and no signing/trust
//! logic. The canonical output MUST be byte-for-byte identical across the
//! Python, Rust, and TypeScript bindings (see test-vectors/jcs/).

use serde::Serialize;
use serde_jcs::to_string as jcs_to_string;
use sha2::{Digest, Sha256};

/// Canonicalize any serializable value to an RFC 8785 UTF-8 String.
pub fn canonical_string<T: Serialize>(value: &T) -> Result<String, String> {
    jcs_to_string(value).map_err(|e| e.to_string())
}

/// Canonicalize any serializable value to RFC 8785 UTF-8 bytes.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    Ok(canonical_string(value)?.into_bytes())
}

/// SHA-256 over the RFC 8785 canonical bytes, as "sha256:<hex>".
pub fn sha256_digest<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonical_bytes(value)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::from("sha256:");
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Verify that `payload_digest` equals the SHA-256 of the canonical payload.
pub fn verify_payload_digest(payload: &serde_json::Value, payload_digest: &str) -> Result<bool, String> {
    let computed = sha256_digest(payload)?;
    Ok(&computed == payload_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc8785_numbers() {
        // -0.0 -> 0, 1e-9 shortest form, integer-valued float -> integer
        let v = json!({"a": -0.0, "b": 1e-9, "c": 1.0, "d": "€"});
        let s = canonical_string(&v).unwrap();
        assert!(s.contains("\"a\":0"), "got: {s}");
        assert!(s.contains("\"b\":1e-9"), "got: {s}");
        assert!(s.contains("\"c\":1"), "got: {s}");
        // RFC 8785: non-ASCII serialized "as is"
        assert!(s.contains("€"), "got: {s}");
    }

    #[test]
    fn digest_format() {
        let v = json!({"k": "v"});
        let d = sha256_digest(&v).unwrap();
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), 7 + 64);
    }
}
