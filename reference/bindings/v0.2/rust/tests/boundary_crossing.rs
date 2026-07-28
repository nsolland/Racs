use racs_v02::{
    check, verify_boundary_chain, BoundaryCrossingAssessment,
    AdmissibilityDetermination, GovernanceEvaluation,
};
use serde_json::Value;
use std::fs;

fn chain() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test-vectors/0.2/runtime-validation/cross-artifact-bindings/chain_accept.json"
    );
    serde_json::from_str(&fs::read_to_string(path).expect("read chain"))
        .expect("parse chain")
}

#[test]
fn boundary_assessment_is_typed_and_canonical() {
    let vector = chain();
    let assessment_value = vector["resolved"]["boundary_assessment"].clone();
    let result = check("BoundaryCrossingAssessment", &assessment_value);
    assert_eq!(result.decision, "ACCEPT");
    assert_eq!(result.reason_code, "ACCEPT");

    let assessment: BoundaryCrossingAssessment =
        serde_json::from_value(assessment_value).expect("assessment");
    assessment.validate_semantics().expect("semantic validation");
    assert_eq!(
        assessment.digest().expect("digest"),
        vector["resolved"]["evaluation"]["boundary_assessment_binding"]
            ["assessment_digest"]
            .as_str()
            .expect("bound digest")
    );
}

#[test]
fn full_boundary_chain_accepts_exact_resolved_artifacts() {
    let vector = chain();
    let resolved = &vector["resolved"];
    let assessment: BoundaryCrossingAssessment =
        serde_json::from_value(resolved["boundary_assessment"].clone())
            .expect("assessment");
    let evaluation: GovernanceEvaluation =
        serde_json::from_value(resolved["evaluation"].clone())
            .expect("evaluation");
    let determination: AdmissibilityDetermination =
        serde_json::from_value(resolved["determination"].clone())
            .expect("determination");

    let result = verify_boundary_chain(
        &resolved["action_envelope"],
        Some(&assessment),
        &evaluation,
        &determination,
        vector["verification_time"].as_str(),
    );
    assert_eq!(result.decision, "ACCEPT", "{:?}", result.detail);
}

#[test]
fn boundary_policy_mismatch_fails_closed() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test-vectors/0.2/runtime-validation/cross-artifact-bindings/chain_reject_boundary_policy_mismatch.json"
    );
    let vector: Value = serde_json::from_str(
        &fs::read_to_string(path).expect("read mismatch vector"),
    )
    .expect("parse mismatch vector");
    let resolved = &vector["resolved"];
    let assessment: BoundaryCrossingAssessment =
        serde_json::from_value(resolved["boundary_assessment"].clone())
            .expect("assessment");
    let evaluation: GovernanceEvaluation =
        serde_json::from_value(resolved["evaluation"].clone())
            .expect("evaluation");
    let determination: AdmissibilityDetermination =
        serde_json::from_value(resolved["determination"].clone())
            .expect("determination");

    let result = verify_boundary_chain(
        &resolved["action_envelope"],
        Some(&assessment),
        &evaluation,
        &determination,
        vector["verification_time"].as_str(),
    );
    assert_eq!(result.decision, "REJECT");
    assert_eq!(result.reason_code, "BOUNDARY_POLICY_MISMATCH");
}
