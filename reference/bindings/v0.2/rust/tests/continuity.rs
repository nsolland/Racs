//! Cross-language golden vectors for RACS v0.2 runtime continuity.

use racs_v02::{
    ContinuityDecision, ContinuityPayload, EnvironmentGovernanceProfile,
    GovernedCapabilityManifest, GovernedExecutionSession, InterventionReceipt,
    RecoveryPlan, RecoveryReceipt, RuntimeObservation,
};
use serde_json::Value;
use std::fs;

fn digest_for(name: &str, payload: Value) -> String {
    match name {
        "governed_capability_manifest" => serde_json::from_value::<GovernedCapabilityManifest>(payload)
            .expect("parse manifest").digest().expect("digest manifest"),
        "environment_governance_profile" => serde_json::from_value::<EnvironmentGovernanceProfile>(payload)
            .expect("parse environment profile").digest().expect("digest environment profile"),
        "governed_execution_session" => serde_json::from_value::<GovernedExecutionSession>(payload)
            .expect("parse execution session").digest().expect("digest execution session"),
        "runtime_observation" => serde_json::from_value::<RuntimeObservation>(payload)
            .expect("parse observation").digest().expect("digest observation"),
        "continuity_decision" => serde_json::from_value::<ContinuityDecision>(payload)
            .expect("parse continuity decision").digest().expect("digest continuity decision"),
        "intervention_receipt" => serde_json::from_value::<InterventionReceipt>(payload)
            .expect("parse intervention receipt").digest().expect("digest intervention receipt"),
        "recovery_plan" => serde_json::from_value::<RecoveryPlan>(payload)
            .expect("parse recovery plan").digest().expect("digest recovery plan"),
        "recovery_receipt" => serde_json::from_value::<RecoveryReceipt>(payload)
            .expect("parse recovery receipt").digest().expect("digest recovery receipt"),
        other => panic!("unknown vector {other}"),
    }
}

#[test]
fn runtime_continuity_models_reproduce_shared_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test-vectors/0.2/runtime-continuity/canonical-vectors.json"
    );
    let text = fs::read_to_string(path).expect("read runtime continuity vectors");
    let document: Value = serde_json::from_str(&text).expect("parse vectors");

    for vector in document["vectors"].as_array().expect("vectors array") {
        let name = vector["name"].as_str().expect("vector name");
        let payload = vector["payload"].clone();
        let expected = vector["payload_digest"].as_str().expect("payload digest");
        assert_eq!(digest_for(name, payload), expected, "{name}");
    }
}

#[test]
fn runtime_continuity_types_reject_unknown_fields() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../test-vectors/0.2/runtime-continuity/canonical-vectors.json"
    );
    let text = fs::read_to_string(path).expect("read vectors");
    let document: Value = serde_json::from_str(&text).expect("parse vectors");
    let vector = document["vectors"].as_array().expect("vectors array").iter()
        .find(|item| item["name"] == "continuity_decision")
        .expect("continuity vector");

    let mut payload = vector["payload"].as_object().expect("payload object").clone();
    payload.insert("watcher_authorized".to_string(), Value::Bool(true));
    assert!(serde_json::from_value::<ContinuityDecision>(Value::Object(payload)).is_err());
}
