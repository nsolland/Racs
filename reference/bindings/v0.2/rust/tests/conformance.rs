//! Integration test: read shared JCS vectors and assert byte-identical output.
//!
//! These are the SAME vectors the Python and TypeScript bindings run. CI asserts
//! all three produce identical canonical bytes + digest.

use std::fs;
use std::path::Path;

use racs_v02::{canonical_string, sha256_digest};
use serde_json::Value;

fn repo_root() -> std::path::PathBuf {
    // tests/ -> rust/ -> v0.2/ -> bindings/ -> reference/ -> Racs root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap()
        .to_path_buf()
}

#[test]
fn official_vectors() {
    let dir = repo_root().join("test-vectors/jcs/official");
    let mut count = 0;
    for entry in fs::read_dir(&dir).expect("official vectors dir") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if !path.file_name().unwrap().to_str().unwrap().starts_with("vector-") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let vec: Value = serde_json::from_str(&text).unwrap();
        let input = &vec["input"];
        let got_canon = canonical_string(input).unwrap();
        let got_digest = sha256_digest(input).unwrap();
        assert_eq!(got_canon, vec["expected_canonical"].as_str().unwrap(),
            "canonical mismatch for {}", path.display());
        assert_eq!(got_digest, vec["expected_digest"].as_str().unwrap(),
            "digest mismatch for {}", path.display());
        count += 1;
    }
    assert!(count >= 6, "expected at least 6 official vectors, got {count}");
}

#[test]
fn racs_governance_evaluation_vector() {
    let path = repo_root().join("test-vectors/jcs/racs-v0.2/governance-evaluation.json");
    let text = fs::read_to_string(&path).unwrap();
    let vec: Value = serde_json::from_str(&text).unwrap();
    let payload = &vec["payload"];
    let got_canon = canonical_string(payload).unwrap();
    let got_digest = sha256_digest(payload).unwrap();
    assert_eq!(got_canon, vec["canonical_payload"].as_str().unwrap());
    assert_eq!(got_digest, vec["payload_digest"].as_str().unwrap());
}
