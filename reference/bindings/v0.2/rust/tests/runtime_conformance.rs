//! Stage 3C conformance tests for the Rust binding.

use racs_v02::validation::{check, schema_sha256};
use racs_v02::verification::{
    verify_clearance_binding_with_boundary_at, verify_evaluation_binding,
};
use racs_v02::{
    AdmissibilityDetermination, BoundaryCrossingAssessment,
    GovernanceClearance, GovernanceEvaluation,
};
use serde_json::Value;
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
    let mut vectors = Vec::new();
    for entry in std::fs::read_dir(base).expect("dir exists") {
        let path = entry.expect("directory entry").path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            let text = std::fs::read_to_string(path).expect("read vector");
            vectors.push(serde_json::from_str(&text).expect("parse vector"));
        }
    }
    vectors.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    vectors
}

#[test]
fn conformance_matrix() {
    for directory in [
        "governance-evaluation",
        "admissibility-determination",
        "governance-clearance",
        "cross-artifact-bindings",
    ] {
        for vector in load_vectors(directory) {
            let artifact_type = vector["artifact_type"].as_str().expect("artifact type");
            let expected = vector["expected"].as_str().expect("expected decision");
            let reason = vector["reason_code"].as_str().expect("reason code");
            let payload = &vector["payload"];
            let vector_id = vector["id"].as_str().expect("vector id");
            let verification_time = vector
                .get("verification_time")
                .and_then(Value::as_str);

            let port_a = check(artifact_type, payload);
            if vector.get("resolved").is_none() {
                assert_eq!(
                    port_a.decision, expected,
                    "Port A decision mismatch for {vector_id}"
                );
                assert_eq!(port_a.reason_code, reason);
                if expected == "ACCEPT" {
                    assert!(port_a
                        .payload_digest
                        .as_ref()
                        .expect("accepted digest")
                        .starts_with("sha256:"));
                }
                continue;
            }

            assert_eq!(
                port_a.decision, "ACCEPT",
                "resolved vector must pass Port A: {vector_id}"
            );
            let resolved = &vector["resolved"];

            if artifact_type == "GovernanceClearance" {
                let clearance: GovernanceClearance =
                    serde_json::from_value(payload.clone()).expect("clearance");
                let determination: AdmissibilityDetermination =
                    serde_json::from_value(resolved["determination"].clone())
                        .expect("determination");
                let evaluation: GovernanceEvaluation =
                    serde_json::from_value(resolved["evaluation"].clone())
                        .expect("evaluation");
                let assessment: BoundaryCrossingAssessment =
                    serde_json::from_value(resolved["boundary_assessment"].clone())
                        .expect("boundary assessment");
                let action_envelope = &resolved["action_envelope"];

                let evaluation_binding =
                    verify_evaluation_binding(&determination, &evaluation);
                let decided = if evaluation_binding.decision == "REJECT" {
                    evaluation_binding
                } else {
                    verify_clearance_binding_with_boundary_at(
                        &clearance,
                        &determination,
                        Some(action_envelope),
                        verification_time,
                        Some(&evaluation),
                        Some(&assessment),
                    )
                };
                assert_eq!(
                    decided.decision, expected,
                    "{}: {}",
                    vector_id,
                    decided.detail.unwrap_or_default()
                );
                assert_eq!(decided.reason_code, reason, "reason mismatch for {vector_id}");
            } else if artifact_type == "AdmissibilityDetermination" {
                let determination: AdmissibilityDetermination =
                    serde_json::from_value(payload.clone()).expect("determination");
                let evaluation: GovernanceEvaluation =
                    serde_json::from_value(resolved["evaluation"].clone())
                        .expect("evaluation");
                let decided = verify_evaluation_binding(&determination, &evaluation);
                assert_eq!(decided.decision, expected);
                assert_eq!(decided.reason_code, reason);
            }
        }
    }

    schema_sha256("GovernanceEvaluation").expect("schema digest");
    schema_sha256("BoundaryCrossingAssessment").expect("boundary schema digest");
}
