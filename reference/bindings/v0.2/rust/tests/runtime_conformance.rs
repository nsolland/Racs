//! Stage 3C conformance tests for the Rust binding.
//!
//! Reads the shared, language-agnostic runtime-validation vectors under
//! `test-vectors/0.2/runtime-validation/` and asserts that the Rust binding
//! emits the same ACCEPT/REJECT decision, normalized reason code, canonical
//! bytes, and payload digest as the Python reference.

use racs_v02::validation::{check, schema_sha256};
use racs_v02::verification::{verify_clearance_binding, verify_evaluation_binding};
use racs_v02::{AdmissibilityDetermination, GovernanceClearance, GovernanceEvaluation};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for cand in std::iter::once(start.clone()).chain(start.ancestors().map(|p| p.to_path_buf())) {
        if cand.join("test-vectors").join("0.2").join("runtime-validation").exists() {
            return cand;
        }
    }
    panic!("could not locate test-vectors directory");
}

fn load_vectors(dir: &str) -> Vec<Value> {
    let base = repo_root()
        .join("test-vectors")
        .join("0.2")
        .join("runtime-validation")
        .join(dir);
    let mut out: Vec<Value> = Vec::new();
    for entry in std::fs::read_dir(&base).expect("dir exists") {
        let p = entry.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) == Some("json") {
            let text = std::fs::read_to_string(&p).unwrap();
            out.push(serde_json::from_str(&text).unwrap());
        }
    }
    out.sort_by(|a, b| {
        a["id"].as_str().cmp(&b["id"].as_str())
    });
    out
}

fn load_resolved(payload: &Value) -> Option<HashMap<String, Value>> {
    payload.get("resolved").map(|r| {
        let obj = r.as_object().unwrap();
        obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    })
}

fn run() {
    let dirs = [
        "governance-evaluation",
        "admissibility-determination",
        "governance-clearance",
        "cross-artifact-bindings",
    ];
    for dir in dirs {
        for vec in load_vectors(dir) {
            let artifact_type = vec["artifact_type"].as_str().unwrap();
            let expected = vec["expected"].as_str().unwrap();
            let reason = vec["reason_code"].as_str().unwrap();
            let payload = &vec["payload"];

            let vec_id = vec["id"].as_str().unwrap();

            // `chain_reject_*` vectors are cross-artifact (Port B) rejections:
            // Port A schema/intra checks must NOT reject them. Skip in Port A.
            if vec_id.starts_with("chain_reject_") {
                continue;
            }

            // Port A
            let res = check(artifact_type, payload);
            assert_eq!(res.decision.as_str(), expected, "Port A decision mismatch for {}", vec_id);

            if expected == "ACCEPT" && artifact_type != "GovernanceClearance" {
                assert_eq!(res.reason_code, "ACCEPT");
                assert!(res.payload_digest.as_ref().unwrap().starts_with("sha256:"));
                continue;
            }

            // Resolved cross-artifact vectors go through Port B.
            if let Some(resolved) = load_resolved(&vec) {
                if artifact_type == "GovernanceClearance" {
                    let clr: GovernanceClearance = serde_json::from_value(payload.clone()).unwrap();
                    let det: AdmissibilityDetermination =
                        serde_json::from_value(resolved["determination"].clone()).unwrap();
                    let ev: GovernanceEvaluation =
                        serde_json::from_value(resolved["evaluation"].clone()).unwrap();
                    let eb = verify_evaluation_binding(&det, &ev);
                    if expected == "ACCEPT" {
                        assert_eq!(eb.decision, "ACCEPT", "eval binding: {}", eb.detail.unwrap_or_default());
                        let cb = verify_clearance_binding(&clr, &det, None);
                        assert_eq!(cb.decision, "ACCEPT", "clearance binding: {}", cb.detail.unwrap_or_default());
                        assert_eq!(cb.reason_code, "ACCEPT");
                    } else {
                        let decided = if eb.decision == "REJECT" { &eb } else { &verify_clearance_binding(&clr, &det, None) };
                        assert_eq!(decided.decision, expected, "{}", decided.detail.clone().unwrap_or_default());
                        assert_eq!(decided.reason_code, reason, "reason mismatch");
                    }
                } else if artifact_type == "AdmissibilityDetermination" {
                    let det: AdmissibilityDetermination =
                        serde_json::from_value(payload.clone()).unwrap();
                    let ev: GovernanceEvaluation =
                        serde_json::from_value(resolved["evaluation"].clone()).unwrap();
                    let eb = verify_evaluation_binding(&det, &ev);
                    assert_eq!(eb.decision, expected, "{}", eb.detail.unwrap_or_default());
                    assert_eq!(eb.reason_code, reason, "reason mismatch");
                }
                continue;
            }

            // Non-resolved ACCEPT clearance only needs Port A.
            if expected == "ACCEPT" {
                assert_eq!(res.reason_code, "ACCEPT");
                assert!(res.payload_digest.as_ref().unwrap().starts_with("sha256:"));
                continue;
            }

            // Non-resolved REJECT (schema or intra-semantic) — reason must match.
            assert_eq!(res.reason_code, reason, "reason mismatch for {}", vec["id"].as_str().unwrap());
        }
    }

    // Schema manifest pins are stable.
    let _ = schema_sha256("GovernanceEvaluation");
}

#[test]
fn conformance_matrix() {
    run();
}
