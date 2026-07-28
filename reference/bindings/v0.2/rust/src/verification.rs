//! RACS v0.2 runtime conformance — Port B cross-artifact verification.

use crate::boundary_crossing::BoundaryCrossingAssessment;
use crate::boundary_validation::{
    verify_boundary_chain, REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
};
use crate::validation::{
    REASON_ACCEPT, REASON_CLEARANCE_ACTION_MISMATCH,
    REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS,
    REASON_CLEARANCE_ALLOW_STATE_MISMATCH,
    REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
    REASON_CLEARANCE_ENVELOPE_MISMATCH, REASON_CLEARANCE_EXPIRED,
    REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS,
    REASON_CLEARANCE_MODIFY_STATE_MISMATCH, REASON_CLEARANCE_NEGATIVE_STATE,
    REASON_CLEARANCE_REVOKED, REASON_EVALUATION_BINDING_DIGEST_MISMATCH,
    REASON_EVALUATION_BINDING_REF_MISMATCH,
};
use crate::{
    AdmissibilityDetermination, GovernanceClearance, GovernanceEvaluation,
};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub decision: String,
    pub reason_code: String,
    pub detail: Option<String>,
}

impl VerificationResult {
    pub fn accept() -> Self {
        Self {
            decision: "ACCEPT".into(),
            reason_code: REASON_ACCEPT.into(),
            detail: None,
        }
    }

    pub fn reject(reason: &str, detail: impl Into<String>) -> Self {
        Self {
            decision: "REJECT".into(),
            reason_code: reason.into(),
            detail: Some(detail.into()),
        }
    }
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
        Ok(value) => value,
        Err(error) => {
            return VerificationResult::reject(
                REASON_EVALUATION_BINDING_DIGEST_MISMATCH,
                error.to_string(),
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
            format!("no binding references {}", evaluation.evaluation_id),
        );
    }
    for binding in &determination.evaluation_bindings {
        if binding.evaluation_digest != expected {
            return VerificationResult::reject(
                REASON_EVALUATION_BINDING_DIGEST_MISMATCH,
                format!("binding {}: digest mismatch", binding.evaluation_ref),
            );
        }
    }
    VerificationResult::accept()
}

/// Backward-compatible entrypoint. Boundary material is now mandatory, so callers
/// using this legacy signature fail closed.
pub fn verify_clearance_binding(
    clearance: &GovernanceClearance,
    determination: &AdmissibilityDetermination,
    action_envelope: Option<&Value>,
) -> VerificationResult {
    verify_clearance_binding_at(clearance, determination, action_envelope, None)
}

/// Backward-compatible timed entrypoint. It intentionally fails closed because
/// GovernanceEvaluation and BoundaryCrossingAssessment are unresolved.
pub fn verify_clearance_binding_at(
    clearance: &GovernanceClearance,
    determination: &AdmissibilityDetermination,
    action_envelope: Option<&Value>,
    verification_time: Option<&str>,
) -> VerificationResult {
    verify_clearance_binding_with_boundary_at(
        clearance,
        determination,
        action_envelope,
        verification_time,
        None,
        None,
    )
}

pub fn verify_clearance_binding_with_boundary_at(
    clearance: &GovernanceClearance,
    determination: &AdmissibilityDetermination,
    action_envelope: Option<&Value>,
    verification_time: Option<&str>,
    governance_evaluation: Option<&GovernanceEvaluation>,
    boundary_assessment: Option<&BoundaryCrossingAssessment>,
) -> VerificationResult {
    if clearance.admissibility_determination_ref != determination.determination_id {
        return VerificationResult::reject(
            REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
            "determination_ref mismatch",
        );
    }
    let determination_digest = match determination.digest() {
        Ok(value) => value,
        Err(error) => {
            return VerificationResult::reject(
                REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH,
                error.to_string(),
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

    let digest_pairs = [
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
                format!("{name} mismatch"),
            );
        }
    }

    if matches!(
        determination.state,
        crate::AdmissibilityState::NotAdmissible
            | crate::AdmissibilityState::Indeterminate
            | crate::AdmissibilityState::Stale
            | crate::AdmissibilityState::Revoked
            | crate::AdmissibilityState::Halted
            | crate::AdmissibilityState::RequiresStepUp
    ) {
        return VerificationResult::reject(
            REASON_CLEARANCE_NEGATIVE_STATE,
            "determination state is not clearable",
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
            if determination.state
                != crate::AdmissibilityState::ConditionallyAdmissible
            {
                return VerificationResult::reject(
                    REASON_CLEARANCE_MODIFY_STATE_MISMATCH,
                    "MODIFY requires CONDITIONALLY_ADMISSIBLE",
                );
            }
            let constraints = match &clearance.constraints {
                Some(value) => value,
                None => {
                    return VerificationResult::reject(
                        REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS,
                        "MODIFY requires constraints",
                    )
                }
            };
            if !enforceable(constraints) {
                return VerificationResult::reject(
                    REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS,
                    "constraints present but not enforceable",
                );
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
    if is_expired(&clearance.valid_until, verification_time) {
        return VerificationResult::reject(
            REASON_CLEARANCE_EXPIRED,
            "validity window expired",
        );
    }

    let (action_envelope, governance_evaluation, boundary_assessment) =
        match (action_envelope, governance_evaluation, boundary_assessment) {
            (Some(envelope), Some(evaluation), Some(assessment)) => {
                (envelope, evaluation, assessment)
            }
            _ => {
                return VerificationResult::reject(
                    REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
                    "clearance verification requires envelope, evaluation and assessment",
                )
            }
        };

    let boundary = verify_boundary_chain(
        action_envelope,
        Some(boundary_assessment),
        governance_evaluation,
        determination,
        verification_time,
    );
    if boundary.decision != "ACCEPT" {
        return VerificationResult {
            decision: boundary.decision,
            reason_code: boundary.reason_code,
            detail: boundary.detail,
        };
    }
    VerificationResult::accept()
}

fn enforceable(constraints: &Value) -> bool {
    match constraints {
        Value::Object(values) => {
            if matches!(values.get("rules"), Some(Value::Array(rules)) if !rules.is_empty()) {
                return true;
            }
            matches!(values.get("constraint_set_ref"), Some(Value::String(value)) if !value.is_empty())
                && matches!(
                    values.get("constraint_set_digest"),
                    Some(Value::String(value)) if value.starts_with("sha256:")
                )
        }
        _ => false,
    }
}

fn is_expired(valid_until: &str, verification_time: Option<&str>) -> bool {
    let until = match chrono::DateTime::parse_from_rfc3339(
        &valid_until.replace('Z', "+00:00"),
    ) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let at = match verification_time {
        Some(raw) => match chrono::DateTime::parse_from_rfc3339(
            &raw.replace('Z', "+00:00"),
        ) {
            Ok(value) => value,
            Err(_) => return false,
        },
        None => chrono::Utc::now().fixed_offset(),
    };
    until < at
}
