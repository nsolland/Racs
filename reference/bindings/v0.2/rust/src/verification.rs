//! RACS v0.2 runtime conformance — Stage 3C, Port B (cross-artifact verification).
//!
//! JSON Schema cannot prove that referenced artifacts *exist* or that the digests
//! *match*. These functions enforce the binding rules between the three contract
//! artifacts. They operate on already-`Validated` payloads (schema-conformant
//! typed models from [`crate::validation`]).
//!
//! Binding rules enforced
//! -----------------------
//! * `verify_evaluation_binding(determination, evaluation)`
//!   - evaluation payload digest == evaluation_digest of every binding
//!   - at least one evaluation_binding.evaluation_ref == evaluation.evaluation_id
//!   - determination.action_id / action_envelope_digest MUST match evaluation
//! * `verify_clearance_binding(clearance, determination, action_envelope)`
//!   - determination-ref points at the correct determination
//!   - admissibility_determination_digest matches the actual determination
//!   - clearance and determination bind the same action_id + action_envelope_digest
//!   - authority/delegation/policy/evidence/purpose/state digests match
//!   - ALLOW only with ADMISSIBLE and WITHOUT constraints
//!   - MODIFY only with CONDITIONALLY_ADMISSIBLE and WITH enforceable constraints
//!   - negative admissibility state can never become a clearance
//!   - validity window (valid_from/valid_until) and revocation status checked
//!
//! Return value: a [`VerificationResult`] (decision ACCEPT/REJECT, normalized
//! reason code). On ACCEPT the caller may construct `Verified<T>`.

use crate::validation::{
    REASON_ACCEPT, REASON_CLEARANCE_ACTION_MISMATCH, REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS,
    REASON_CLEARANCE_ALLOW_STATE_MISMATCH, REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
    REASON_CLEARANCE_ENVELOPE_MISMATCH, REASON_CLEARANCE_EXPIRED, REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS,
    REASON_CLEARANCE_MODIFY_STATE_MISMATCH, REASON_CLEARANCE_NEGATIVE_STATE, REASON_CLEARANCE_REVOKED,
    REASON_EVALUATION_BINDING_DIGEST_MISMATCH, REASON_EVALUATION_BINDING_REF_MISMATCH,
};
use crate::{AdmissibilityDetermination, GovernanceClearance, GovernanceEvaluation};
use serde_json::Value;
use std::error::Error;

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

// Admissibility states that may never become a clearance.
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
    // 1. action identity consistency
    if determination.action_id != evaluation.action_id {
        return VerificationResult::reject(
            REASON_CLEARANCE_ACTION_MISMATCH,
            "determination.action_id != evaluation.action_id",
        );
    }
    if determination.action_envelope_digest != evaluation.action_envelope_digest {
        return VerificationResult::reject(REASON_CLEARANCE_ENVELOPE_MISMATCH, "envelope digest mismatch");
    }
    // 2. evaluation digest must match the resolved evaluation's payload_digest
    let expected = match evaluation.digest() {
        Ok(d) => d,
        Err(e) => return VerificationResult::reject(REASON_EVALUATION_BINDING_DIGEST_MISMATCH, &e.to_string()),
    };
    if !determination
        .evaluation_bindings
        .iter()
        .any(|b| b.evaluation_ref == evaluation.evaluation_id)
    {
        return VerificationResult::reject(
            REASON_EVALUATION_BINDING_REF_MISMATCH,
            &format!("no binding references {}", evaluation.evaluation_id),
        );
    }
    for b in &determination.evaluation_bindings {
        if b.evaluation_digest != expected {
            return VerificationResult::reject(
                REASON_EVALUATION_BINDING_DIGEST_MISMATCH,
                &format!("binding {}: digest mismatch", b.evaluation_ref),
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
    // 1. determination reference + digest binding
    if clearance.admissibility_determination_ref != determination.determination_id {
        return VerificationResult::reject(
            REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
            "determination_ref mismatch",
        );
    }
    let det_digest = match determination.digest() {
        Ok(d) => d,
        Err(e) => {
            return VerificationResult::reject(REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH, &e.to_string())
        }
    };
    if clearance.admissibility_determination_digest != det_digest {
        return VerificationResult::reject(
            REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
            "admissibility_determination_digest mismatch",
        );
    }

    // 2. shared action identity
    if clearance.action_id != determination.action_id {
        return VerificationResult::reject(REASON_CLEARANCE_ACTION_MISMATCH, "action_id mismatch");
    }
    if clearance.action_envelope_digest != determination.action_envelope_digest {
        return VerificationResult::reject(REASON_CLEARANCE_ENVELOPE_MISMATCH, "action_envelope_digest mismatch");
    }

    // 3. digest congruence across authority/delegation/policy/evidence/purpose/state
    let digest_pairs: &[(&str, &String, &String)] = &[
        ("authority_digest", &clearance.authority_digest, &determination.authority_digest),
        (
            "delegation_chain_digest",
            &clearance.delegation_chain_digest,
            &determination.delegation_chain_digest,
        ),
        ("policy_digest", &clearance.policy_digest, &determination.policy_digest),
        ("evidence_digest", &clearance.evidence_digest, &determination.evidence_digest),
        ("purpose_digest", &clearance.purpose_digest, &determination.purpose_digest),
        ("state_digest", &clearance.state_digest, &determination.state_digest),
    ];
    for (name, c_val, d_val) in digest_pairs {
        if c_val != d_val {
            return VerificationResult::reject(REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH, &format!("{name} mismatch"));
        }
    }

    // 4. admissibility-state semantics
    let state_str = format!("{:?}", determination.state).to_uppercase();
    if non_clearable_states().contains(&state_str.as_str()) {
        return VerificationResult::reject(
            REASON_CLEARANCE_NEGATIVE_STATE,
            &format!("determination.state={state_str} is not clearable"),
        );
    }
    match clearance.decision {
        crate::Decision::Allow => {
            if determination.state != crate::AdmissibilityState::Admissible {
                return VerificationResult::reject(REASON_CLEARANCE_ALLOW_STATE_MISMATCH, "ALLOW requires ADMISSIBLE");
            }
            if clearance.constraints.is_some() {
                return VerificationResult::reject(REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS, "ALLOW must not carry constraints");
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
                    return VerificationResult::reject(REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS, "MODIFY requires constraints")
                }
                Some(c) => {
                    if !enforceable(c) {
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

    // 5. validity window + revocation
    if clearance.revocation_registry_ref.is_empty() {
        return VerificationResult::reject(REASON_CLEARANCE_REVOKED, "empty revocation_registry_ref");
    }
    if is_expired(&clearance.valid_from, &clearance.valid_until) {
        return VerificationResult::reject(REASON_CLEARANCE_EXPIRED, "validity window expired");
    }

    // 6. optional envelope digest resolution
    if let Some(env) = action_envelope {
        let env_digest = env
            .get("payload_digest")
            .or_else(|| env.get("action_envelope_digest"))
            .and_then(|v| v.as_str());
        if let Some(d) = env_digest {
            if d != clearance.action_envelope_digest {
                return VerificationResult::reject(REASON_CLEARANCE_ENVELOPE_MISMATCH, "resolved envelope digest mismatch");
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
            let ref_ok = matches!(map.get("constraint_set_ref"), Some(Value::String(s)) if !s.is_empty());
            let digest_ok = matches!(
                map.get("constraint_set_digest"),
                Some(Value::String(s)) if s.starts_with("sha256:")
            );
            ref_ok && digest_ok
        }
        _ => false,
    }
}

fn is_expired(valid_from: &str, valid_until: &str) -> bool {
    if valid_until.is_empty() {
        return false;
    }
    // Parse ISO-8601 (accept trailing Z). Best-effort; unparseable => not expired.
    let norm = valid_until.replace('Z', "+00:00");
    let until = match chrono::DateTime::parse_from_rfc3339(&norm) {
        Ok(d) => d,
        Err(_) => return false,
    };
    until < chrono::Utc::now()
}
