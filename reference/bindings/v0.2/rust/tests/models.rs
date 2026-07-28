//! Stage 3B typed-model digest conformance.

use racs_v02::{sha256_digest, GovernanceEvaluation};
use std::fs;

const STEP2_DIGEST: &str =
    "sha256:532d2a571f8536890bf9b79994703c63a44c01ba40f71b4733d045674bdb3273";

#[test]
fn governance_evaluation_parses_golden_and_reproduces_step2_digest() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test-vectors/0.2/governance-evaluation-golden.json"
    );
    let text = fs::read_to_string(path).expect("read golden");
    let vector: serde_json::Value = serde_json::from_str(&text).expect("parse golden");
    let evaluation: GovernanceEvaluation =
        serde_json::from_value(vector["payload"].clone()).expect("model parse golden");

    assert_eq!(evaluation.decision, racs_v02::Decision::Allow);
    assert_eq!(
        evaluation.authority_status,
        racs_v02::Status::PresentAndValid
    );
    assert_eq!(
        evaluation.boundary_assessment_binding.assessment_ref,
        "bca:gv_allow"
    );
    assert_eq!(
        sha256_digest(&evaluation).expect("digest"),
        STEP2_DIGEST
    );
}
