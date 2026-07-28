//! Shared Stage 2 verification vectors.

use racs_v02::continuity_verification::{
    prove_runtime_bounds_narrowing, verify_continuity_decision, verify_execution_session,
};
use racs_v02::{
    ContinuityDecision, EnvironmentGovernanceProfile, GovernanceClearance,
    GovernanceEvaluation, GovernedCapabilityManifest, GovernedExecutionSession,
};
use serde_json::{Map, Value};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in
        std::iter::once(start.clone()).chain(start.ancestors().map(|path| path.to_path_buf()))
    {
        if candidate
            .join("test-vectors")
            .join("0.2")
            .join("runtime-continuity")
            .join("verification-vectors.json")
            .exists()
        {
            return candidate;
        }
    }
    panic!("could not locate verification vectors");
}

fn document() -> Value {
    let path = repo_root()
        .join("test-vectors")
        .join("0.2")
        .join("runtime-continuity")
        .join("verification-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors"))
        .expect("parse vectors")
}

fn apply_mutations(root: &mut Value, mutations: &Map<String, Value>) {
    for (dotted_path, value) in mutations {
        let parts: Vec<&str> = dotted_path.split('.').collect();
        let mut node = &mut *root;
        for part in &parts[..parts.len() - 1] {
            node = node
                .as_object_mut()
                .expect("mutation object")
                .get_mut(*part)
                .expect("mutation path");
        }
        node.as_object_mut()
            .expect("mutation target")
            .insert(parts[parts.len() - 1].to_string(), value.clone());
    }
}

struct Models {
    manifest: GovernedCapabilityManifest,
    profile: EnvironmentGovernanceProfile,
    evaluation: GovernanceEvaluation,
    clearance: GovernanceClearance,
    session: GovernedExecutionSession,
    decision: ContinuityDecision,
}

fn models(document: &Value, mutations: &Map<String, Value>) -> Models {
    let mut artifacts = document["artifacts"].clone();
    apply_mutations(&mut artifacts, mutations);
    Models {
        manifest: serde_json::from_value(artifacts["manifest"].clone()).expect("manifest"),
        profile: serde_json::from_value(artifacts["profile"].clone()).expect("profile"),
        evaluation: serde_json::from_value(artifacts["evaluation"].clone()).expect("evaluation"),
        clearance: serde_json::from_value(artifacts["clearance"].clone()).expect("clearance"),
        session: serde_json::from_value(artifacts["session"].clone()).expect("session"),
        decision: serde_json::from_value(artifacts["decision"].clone()).expect("decision"),
    }
}

#[test]
fn session_verification_vectors() {
    let document = document();
    let verification_time = document["verification_time"].as_str().expect("verification time");
    for case in document["session_cases"].as_array().expect("session cases") {
        let mutations = case["mutations"].as_object().expect("mutations");
        let models = models(&document, mutations);
        let result = verify_execution_session(
            &models.session,
            &models.manifest,
            &models.profile,
            &models.evaluation,
            &models.clearance,
            Some(verification_time),
        );
        assert_eq!(result.decision, case["expected"].as_str().unwrap(), "{}", case["id"]);
        assert_eq!(result.reason_code, case["reason_code"].as_str().unwrap(), "{}", case["id"]);
    }
}

#[test]
fn bounds_narrowing_vectors() {
    let document = document();
    for case in document["bounds_cases"].as_array().expect("bounds cases") {
        let current = case["current"].as_object().expect("current bounds");
        let proposed = case["proposed"].as_object().expect("proposed bounds");
        let result = prove_runtime_bounds_narrowing(current, proposed);
        assert_eq!(result.decision, case["expected"].as_str().unwrap(), "{}", case["id"]);
        assert_eq!(result.reason_code, case["reason_code"].as_str().unwrap(), "{}", case["id"]);
    }
}

#[test]
fn decision_verification_vectors() {
    let document = document();
    let verification_time = document["verification_time"].as_str().expect("verification time");
    for case in document["decision_cases"].as_array().expect("decision cases") {
        let mutations = case["mutations"].as_object().expect("mutations");
        let models = models(&document, mutations);
        let result = verify_continuity_decision(
            &models.session,
            &models.decision,
            &models.profile.runtime_limits,
            Some(verification_time),
        );
        assert_eq!(result.decision, case["expected"].as_str().unwrap(), "{}", case["id"]);
        assert_eq!(result.reason_code, case["reason_code"].as_str().unwrap(), "{}", case["id"]);
    }
}
