//! Stage 3B integration test: typed models parse the shared RACS golden
//! GovernanceEvaluation payload and reproduce the step-2 `payload_digest`.

use std::fs;
use racs_v02::{GovernanceEvaluation, sha256_digest};

const STEP2_DIGEST: &str =
    "sha256:58c8431515435642ee92d148a0636f2b20c5292c843fc8977a1fda3f5d94644c";

#[test]
fn governance_evaluation_parses_golden_and_reproduces_step2_digest() {
    // repo root: tests -> rust -> v0.2 -> bindings -> reference -> Racs
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test-vectors/0.2/governance-evaluation-golden.json"
    );
    let text = fs::read_to_string(path).expect("read golden");
    let v: serde_json::Value = serde_json::from_str(&text).expect("parse golden");
    let payload = &v["payload"];
    let ev: GovernanceEvaluation =
        serde_json::from_value(payload.clone()).expect("model parse golden");

    assert_eq!(ev.decision, racs_v02::Decision::Allow);
    assert_eq!(ev.authority_status, racs_v02::Status::PresentAndValid);

    let digest = sha256_digest(&ev).expect("digest");
    assert_eq!(digest, STEP2_DIGEST);
}
