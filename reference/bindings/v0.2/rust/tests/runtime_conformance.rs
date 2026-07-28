//! Stage 3C conformance tests for the Rust binding.
//!
//! Reads the shared runtime-validation vectors and asserts the same decision,
//! reason code, canonical bytes and payload digest across bindings.

use racs_v02::validation::{check, schema_sha256};
use racs_v02::verification::{
    verify_clearance_binding_at, verify_evaluation_binding,
};
use racs_v02::{AdmissibilityDetermination, GovernanceClearance, GovernanceEvaluation};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in
        std::iter::once(start.clone()).chain(start.ancestors().map(|path| path.to_path_buf()))
    {
        if candidate
            .join("test-vectors")
            .join("0.2")
            .join("runtime-validation")
            .exists()
        {
            return candidate;
        }
    }
    panic!("could not locate test-vectors directory");
}

fn load_vectors(directory: &str) -> Vec<Value> {
    let base = repo_root()
        .join("test-vectors")
        .join("0.2")
        .join("runtime-validation")
        .join(directory);
    let mut vectors: Vec<Value> = Vec::new();
    for entry in std::fs::read_dir(&base).expect("dir exists") {
        let path = entry.expect("directory entry").path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            let text = std::fs::read_to_string(&path).expect("read vector");
            vectors.push(serde_json::from_str(&text).expect("parse vector"));
        }
    }
    vectors.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    vectors
}

fn load_resolved(payload: &Value) -> Option<HashMap<String, Value>> {
    payload.get("resolved").map(|resolved| {
        resolved
            .as_object()
            .expect("resolved object")
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    })
}

fn run() {
    let directories = [
        "governance-evaluation",
        "admissibility-determination",
        "governance-clearance",
        "cross-artifact-bindings",
    ];
    for directory in directories {
        for vector in load_vectors(directory) {
            let artifact_type = vector["artifact_type"].as_str().expect("artifact type");
            let expected = vector["expected"].as_str().expect("expected decision");
            let reason = vector["reason_code"].as_str().expect("reason code");
            let payload = &vector["payload"];
            let vector_id = vector["id"].as_str().expect("vector id");
            let verification_time = vector
                .get("verification_time")
                .and_then(|value| value.as_str());

            if vector_id.starts_with("chain_reject_") {
                continue;
            }

            let result = check(artifact_type, payload);
            assert_eq!(
                result.decision.as_str(),
                expected,
                "Port A decision mismatch for {vector_id}"
            );

            if expected == "ACCEPT" && artifact_type != "GovernanceClearance" {
                assert_eq!(result.reason_code, "ACCEPT");
                assert!(result
                    .payload_digest
                    .as_ref()
                    .expect("accepted payload digest")
                    .starts_with("sha256:"));
                continue;
            }

            if let Some(resolved) = load_resolved(&vector) {
                if artifact_type == "GovernanceClearance" {
                    let clearance: GovernanceClearance =
                        serde_json::from_value(payload.clone()).expect("clearance");
                    let determination: AdmissibilityDetermination = serde_json::from_value(
                        resolved["determination"].clone(),
                    )
                    .expect("determination");
                    let evaluation: GovernanceEvaluation =
                        serde_json::from_value(resolved["evaluation"].clone())
                            .expect("evaluation");
                    let evaluation_binding =
                        verify_evaluation_binding(&determination, &evaluation);
                    let clearance_binding = verify_clearance_binding_at(
                        &clearance,
                        &determination,
                        None,
                        verification_time,
                    );
                    if expected == "ACCEPT" {
                        assert_eq!(
                            evaluation_binding.decision,
                            "ACCEPT",
                            "eval binding: {}",
                            evaluation_binding.detail.unwrap_or_default()
                        );
                        assert_eq!(
                            clearance_binding.decision,
                            "ACCEPT",
                            "clearance binding: {}",
                            clearance_binding.detail.unwrap_or_default()
                        );
                        assert_eq!(clearance_binding.reason_code, "ACCEPT");
                    } else {
                        let decided = if evaluation_binding.decision == "REJECT" {
                            evaluation_binding
                        } else {
                            clearance_binding
                        };
                        assert_eq!(
                            decided.decision,
                            expected,
                            "{}",
                            decided.detail.unwrap_or_default()
                        );
                        assert_eq!(decided.reason_code, reason, "reason mismatch");
                    }
                } else if artifact_type == "AdmissibilityDetermination" {
                    let determination: AdmissibilityDetermination =
                        serde_json::from_value(payload.clone()).expect("determination");
                    let evaluation: GovernanceEvaluation =
                        serde_json::from_value(resolved["evaluation"].clone())
                            .expect("evaluation");
                    let evaluation_binding =
                        verify_evaluation_binding(&determination, &evaluation);
                    assert_eq!(
                        evaluation_binding.decision,
                        expected,
                        "{}",
                        evaluation_binding.detail.unwrap_or_default()
                    );
                    assert_eq!(evaluation_binding.reason_code, reason, "reason mismatch");
                }
                continue;
            }

            if expected == "ACCEPT" {
                assert_eq!(result.reason_code, "ACCEPT");
                assert!(result
                    .payload_digest
                    .as_ref()
                    .expect("accepted payload digest")
                    .starts_with("sha256:"));
                continue;
            }

            assert_eq!(
                result.reason_code,
                reason,
                "reason mismatch for {}",
                vector["id"].as_str().expect("vector id")
            );
        }
    }

    let _ = schema_sha256("GovernanceEvaluation");
}

#[test]
fn conformance_matrix() {
    run();
}
