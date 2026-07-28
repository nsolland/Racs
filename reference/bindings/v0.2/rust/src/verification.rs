//! RACS v0.2 runtime conformance — Stage 3C, Port B (cross-artifact verification).
//!
//! JSON Schema cannot prove that referenced artifacts *exist* or that the digests
//! *match*. These functions enforce the binding rules between the three contract
//! artifacts. They operate on already-`Validated` payloads (schema-conformant
//! typed models from [`crate::validation`]).

use crate::validation::{
    REASON_ACCEPT, REASON_CLEARANCE_ACTION_MISMATCH, REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS,
    REASON_CLEARANCE_ALLOW_STATE_MISMATCH, REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
    REASON_CLEARANCE_ENVELOPE_MISMATCH, REASON_CLEARANCE_EXPIRED,
    REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS, REASON_CLEARANCE_MODIFY_STATE_MISMATCH,
    REASON_CLEARANCE_NEGATIVE_STATE, REASON_CLEARANCE_REVOKED,
    REASON_EVALUATION_BINDING_DIGEST_MISMATCH, REASON_EVALUATION_BINDING_REF_MISMATCH,
};
use crate::{AdmissibilityDetermination, GovernanceClearance, GovernanceEvaluation};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub decision: String,
    pub reason_code: String,
    pub detail: Option<String>,
}

impl VerificationResult {
    pub fn accept() -> Self {
        VerificationResult {
            decision: "ACCEPT".into(),
            reason_code: REASON_ACCEPT.into(),
            detail: None,
        }
    }

    pub fn reject(reason: &'static str, detail: &str) -> Self {
        VerificationResult {
            decision: "REJECT".into(),
            reason_code: reason.into(),
            detail: Some(detail.into()),
        }
    }
}

fn non_clearable_states() -> &'static [&'static str; 6] {
    &[
        "NOT_ADMISSIBLE",
        "INDETERMINATE",
        "STALE",
        "REVOKED",
        "HALTED",
        "REQUIRES_STEP_UP",
    ]
}

pub fn verify_evaluation_binding(
    determination: &AdmissibilityDetermination,
    evaluation: &GovernanceEvaluation,
) -> VerificationResult {
    if determination.action_id != evaluation.action_id {
        return VerificationResult::reject(
            REASON_CLEARANCE_ACTION_MISMATCH,
            "determination.action_id != evaluation.action_id",
        );
    }
    if determination.action_envelope_digest != evaluation.action_envelope_digest {
        return VerificationResult::reject(
            REASON_CLEARANCE_ENVELOPE_MISMATCH,
            "envelope digest mismatch",
        );
    }

    let expected = match evaluation.digest() {
        Ok(digest) => digest,
        Err(error) => {
            return VerificationResult::reject(
                REASON_EVALUATION_BINDING_DIGEST_MISMATCH,
                &error.to_string(),
            )
        }
    };
    if !determination
        .evaluation_bindings
        .iter()
        .any(|binding| binding.evaluation_ref == evaluation.evaluation_id)
    {
        return VerificationResult::reject(
            REASON_EVALUATION_BINDING_REF_MISMATCH,
            &format!("no binding references {}", evaluation.evaluation_id),
        );
    }
    for binding in &determination.evaluation_bindings {
        if binding.evaluation_digest != expected {
            return VerificationResult::reject(
                REASON_EVALUATION_BINDING_DIGEST_MISMATCH,
                &format!("binding {}: digest mismatch", binding.evaluation_ref),
            );
        }
    }
    VerificationResult::accept()
}

pub fn verify_clearance_binding(
    clearance: &GovernanceClearance,
    determination: &AdmissibilityDetermination,
    action_envelope: Option<&Value>,
) -> VerificationResult {
    verify_clearance_binding_at(clearance, determination, action_envelope, None)
}

pub fn verify_clearance_binding_at(
    clearance: &GovernanceClearance,
    determination: &AdmissibilityDetermination,
    action_envelope: Option<&Value>,
    verification_time: Option<&str>,
) -> VerificationResult {
    if clearance.admissibility_determination_ref != determination.determination_id {
        return VerificationResult::reject(
            REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
            "determination_ref mismatch",
        );
    }
    let determination_digest = match determination.digest() {
        Ok(digest) => digest,
        Err(error) => {
            return VerificationResult::reject(
                REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
                &error.to_string(),
            )
        }
    };
    if clearance.admissibility_determination_digest != determination_digest {
        return VerificationResult::reject(
            REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
            "admissibility_determination_digest mismatch",
        );
    }

    if clearance.action_id != determination.action_id {
        return VerificationResult::reject(
            REASON_CLEARANCE_ACTION_MISMATCH,
            "action_id mismatch",
        );
    }
    if clearance.action_envelope_digest != determination.action_envelope_digest {
        return VerificationResult::reject(
            REASON_CLEARANCE_ENVELOPE_MISMATCH,
            "action_envelope_digest mismatch",
        );
    }

    let digest_pairs: &[(&str, &String, &String)] = &[
        (
            "authority_digest",
            &clearance.authority_digest,
            &determination.authority_digest,
        ),
        (
            "delegation_chain_digest",
            &clearance.delegation_chain_digest,
            &determination.delegation_chain_digest,
        ),
        (
            "policy_digest",
            &clearance.policy_digest,
            &determination.policy_digest,
        ),
        (
            "evidence_digest",
            &clearance.evidence_digest,
            &determination.evidence_digest,
        ),
        (
            "purpose_digest",
            &clearance.purpose_digest,
            &determination.purpose_digest,
        ),
        (
            "state_digest",
            &clearance.state_digest,
            &determination.state_digest,
        ),
    ];
    for (name, clearance_value, determination_value) in digest_pairs {
        if clearance_value != determination_value {
            return VerificationResult::reject(
                REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
                &format!("{name} mismatch"),
            );
        }
    }

    let state = format!("{:?}", determination.state).to_uppercase();
    if non_clearable_states().contains(&state.as_str()) {
        return VerificationResult::reject(
            REASON_CLEARANCE_NEGATIVE_STATE,
            &format!("determination.state={state} is not clearable"),
        );
    }
    match clearance.decision {
        crate::Decision::Allow => {
            if determination.state != crate::AdmissibilityState::Admissible {
                return VerificationResult::reject(
                    REASON_CLEARANCE_ALLOW_STATE_MISMATCH,
                    "ALLOW requires ADMISSIBLE",
                );
            }
            if clearance.constraints.is_some() {
                return VerificationResult::reject(
                    REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS,
                    "ALLOW must not carry constraints",
                );
            }
        }
        crate::Decision::Modify => {
            if determination.state != crate::AdmissibilityState::ConditionallyAdmissible {
                return VerificationResult::reject(
                    REASON_CLEARANCE_MODIFY_STATE_MISMATCH,
                    "MODIFY requires CONDITIONALLY_ADMISSIBLE",
                );
            }
            match &clearance.constraints {
                None => {
                    return VerificationResult::reject(
                        REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS,
                        "MODIFY requires constraints",
                    )
                }
                Some(constraints) => {
                    if !enforceable(constraints) {
                        return VerificationResult::reject(
                            REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS,
                            "constraints present but not enforceable",
                        );
                    }
                }
            }
        }
        _ => {}
    }

    if clearance.revocation_registry_ref.is_empty() {
        return VerificationResult::reject(
            REASON_CLEARANCE_REVOKED,
            "empty revocation_registry_ref",
        );
    }
    if is_expired(
        &clearance.valid_from,
        &clearance.valid_until,
        verification_time,
    ) {
        return VerificationResult::reject(
            REASON_CLEARANCE_EXPIRED,
            "validity window expired",
        );
    }

    if let Some(envelope) = action_envelope {
        let envelope_digest = envelope
            .get("payload_digest")
            .or_else(|| envelope.get("action_envelope_digest"))
            .and_then(|value| value.as_str());
        if let Some(digest) = envelope_digest {
            if digest != clearance.action_envelope_digest {
                return VerificationResult::reject(
                    REASON_CLEARANCE_ENVELOPE_MISMATCH,
                    "resolved envelope digest mismatch",
                );
            }
        }
    }

    VerificationResult::accept()
}

fn enforceable(constraints: &Value) -> bool {
    match constraints {
        Value::Object(map) => {
            if let Some(Value::Array(rules)) = map.get("rules") {
                if !rules.is_empty() {
                    return true;
                }
            }
            let reference_ok =
                matches!(map.get("constraint_set_ref"), Some(Value::String(value)) if !value.is_empty());
            let digest_ok = matches!(
                map.get("constraint_set_digest"),
                Some(Value::String(value)) if value.starts_with("sha256:")
            );
            reference_ok && digest_ok
        }
        _ => false,
    }
}

fn is_expired(valid_from: &str, valid_until: &str, verification_time: Option<&str>) -> bool {
    if valid_until.is_empty() {
        return false;
    }
    let normalized_until = valid_until.replace('Z', "+00:00");
    let until = match chrono::DateTime::parse_from_rfc3339(&normalized_until) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let at = match verification_time {
        Some(raw) => {
            let normalized = raw.replace('Z', "+00:00");
            match chrono::DateTime::parse_from_rfc3339(&normalized) {
                Ok(value) => value,
                Err(_) => return false,
            }
        }
        None => chrono::Utc::now().fixed_offset(),
    };
    until < at
}
