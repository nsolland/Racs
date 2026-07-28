//! Conformance binary for canonicalization and Stage 3C runtime vectors.

use std::env;
use std::fs;
use std::process;

use racs_v02::validation::check;
use racs_v02::verification::{
    verify_clearance_binding_with_boundary_at, verify_evaluation_binding,
};
use racs_v02::{
    canonical_string, sha256_digest, AdmissibilityDetermination,
    BoundaryCrossingAssessment, GovernanceClearance, GovernanceEvaluation,
};
use serde_json::Value;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(String::as_str);
    let path = args.get(2).map(String::as_str);

    match (mode, path) {
        (Some("--vector"), Some(path)) => {
            let vector = read_json(path);
            let (subject, expected_canonical, expected_digest) =
                if vector.get("input").is_some() {
                    (
                        vector["input"].clone(),
                        vector["expected_canonical"].clone(),
                        vector["expected_digest"].clone(),
                    )
                } else if vector.get("payload").is_some() {
                    (
                        vector["payload"].clone(),
                        vector["canonical_payload"].clone(),
                        vector["payload_digest"].clone(),
                    )
                } else {
                    die("vector has neither 'input' nor 'payload'");
                };
            let got_canonical = canonical_string(&subject).unwrap();
            let got_digest = sha256_digest(&subject).unwrap();
            let expected_canonical = expected_canonical.as_str().unwrap_or("");
            let expected_digest = expected_digest.as_str().unwrap_or("");
            let matches =
                got_canonical == expected_canonical && got_digest == expected_digest;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "got_canonical": got_canonical,
                    "got_digest": got_digest,
                    "expected_canonical": expected_canonical,
                    "expected_digest": expected_digest,
                    "match": matches,
                }))
                .unwrap()
            );
            if !matches {
                process::exit(1);
            }
        }
        (Some("--file"), Some(path)) => {
            let value = read_json(path);
            println!(
                "{}",
                serde_json::json!({
                    "canonical": canonical_string(&value).unwrap(),
                    "digest": sha256_digest(&value).unwrap(),
                })
            );
        }
        (Some("--model-digest"), Some(path)) => {
            let vector = read_json(path);
            let evaluation: GovernanceEvaluation =
                serde_json::from_value(vector["payload"].clone())
                    .unwrap_or_else(|error| die(&format!("model: {error}")));
            println!(
                "{}",
                serde_json::json!({"digest": evaluation.digest().unwrap()})
            );
        }
        (Some("--check"), Some(path)) => {
            let vector = read_json(path);
            let artifact_type = vector["artifact_type"]
                .as_str()
                .unwrap_or_else(|| die("runtime vector has no artifact_type"));
            let payload = &vector["payload"];
            let verification_time = vector
                .get("verification_time")
                .and_then(Value::as_str);
            let port_a = check(artifact_type, payload);
            let mut decision = port_a.decision.clone();
            let mut reason_code = port_a.reason_code.clone();

            if decision == "ACCEPT" {
                if let Some(resolved) = vector.get("resolved") {
                    if artifact_type == "GovernanceClearance" {
                        let clearance: GovernanceClearance =
                            serde_json::from_value(payload.clone())
                                .unwrap_or_else(|error| {
                                    die(&format!("clearance model: {error}"))
                                });
                        let determination: AdmissibilityDetermination =
                            serde_json::from_value(resolved["determination"].clone())
                                .unwrap_or_else(|error| {
                                    die(&format!("determination model: {error}"))
                                });
                        let evaluation: GovernanceEvaluation =
                            serde_json::from_value(resolved["evaluation"].clone())
                                .unwrap_or_else(|error| {
                                    die(&format!("evaluation model: {error}"))
                                });
                        let action_envelope = resolved.get("action_envelope");
                        let assessment: Option<BoundaryCrossingAssessment> = resolved
                            .get("boundary_assessment")
                            .cloned()
                            .map(|value| {
                                serde_json::from_value(value).unwrap_or_else(|error| {
                                    die(&format!("boundary assessment model: {error}"))
                                })
                            });

                        let mut verification =
                            verify_evaluation_binding(&determination, &evaluation);
                        if verification.decision == "ACCEPT" {
                            verification = verify_clearance_binding_with_boundary_at(
                                &clearance,
                                &determination,
                                action_envelope,
                                verification_time,
                                Some(&evaluation),
                                assessment.as_ref(),
                            );
                        }
                        if verification.decision == "REJECT" {
                            decision = verification.decision;
                            reason_code = verification.reason_code;
                        }
                    } else if artifact_type == "AdmissibilityDetermination" {
                        let determination: AdmissibilityDetermination =
                            serde_json::from_value(payload.clone())
                                .unwrap_or_else(|error| {
                                    die(&format!("determination model: {error}"))
                                });
                        let evaluation: GovernanceEvaluation =
                            serde_json::from_value(resolved["evaluation"].clone())
                                .unwrap_or_else(|error| {
                                    die(&format!("evaluation model: {error}"))
                                });
                        let verification =
                            verify_evaluation_binding(&determination, &evaluation);
                        if verification.decision == "REJECT" {
                            decision = verification.decision;
                            reason_code = verification.reason_code;
                        }
                    }
                }
            }

            let mut output = serde_json::Map::new();
            output.insert(
                "id".into(),
                vector.get("id").cloned().unwrap_or(Value::Null),
            );
            output.insert("decision".into(), Value::String(decision.clone()));
            output.insert("reason_code".into(), Value::String(reason_code.clone()));
            if decision == "ACCEPT" {
                if let Some(canonical) = port_a.canonical {
                    output.insert("canonical".into(), Value::String(canonical));
                }
                if let Some(digest) = port_a.payload_digest {
                    output.insert("payload_digest".into(), Value::String(digest));
                }
            }

            let expected = vector.get("expected").cloned().unwrap_or(Value::Null);
            let expected_reason = vector
                .get("reason_code")
                .cloned()
                .unwrap_or(Value::Null);
            let matches = expected.as_str() == Some(decision.as_str())
                && expected_reason.as_str() == Some(reason_code.as_str());
            output.insert("expected".into(), expected);
            output.insert("expected_reason_code".into(), expected_reason);
            output.insert("match".into(), Value::Bool(matches));

            println!(
                "{}",
                serde_json::to_string_pretty(&Value::Object(output)).unwrap()
            );
            if !matches {
                process::exit(1);
            }
        }
        _ => die(
            "usage: racs-v02-conformance (--vector <file> | --file <file> | --model-digest <golden-file> | --check <runtime-vector-file>)",
        ),
    }
}

fn read_json(path: &str) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| die(&format!("read {path}: {error}")));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| die(&format!("parse {path}: {error}")))
}

fn die(message: &str) -> ! {
    eprintln!("error: {message}");
    process::exit(2);
}
