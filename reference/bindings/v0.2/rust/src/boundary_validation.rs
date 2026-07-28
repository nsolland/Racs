use chrono::{DateTime, FixedOffset, Utc};
use serde_json::Value;
use std::collections::HashSet;

use crate::boundary_crossing::{
    response_floor_satisfied, BoundaryCrossingAssessment, BoundaryState,
};
use crate::{sha256_digest, AdmissibilityDetermination, GovernanceEvaluation};

pub const REASON_BOUNDARY_ACCEPT: &str = "BOUNDARY_ACCEPT";
pub const REASON_BOUNDARY_REQUIRED_MISSING: &str = "BOUNDARY_REQUIRED_MISSING";
pub const REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH: &str =
    "BOUNDARY_ASSESSMENT_REF_MISMATCH";
pub const REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH: &str =
    "BOUNDARY_ASSESSMENT_DIGEST_MISMATCH";
pub const REASON_BOUNDARY_ACTION_MISMATCH: &str = "BOUNDARY_ACTION_MISMATCH";
pub const REASON_BOUNDARY_ENVELOPE_MISMATCH: &str = "BOUNDARY_ENVELOPE_MISMATCH";
pub const REASON_BOUNDARY_TENANT_MISMATCH: &str = "BOUNDARY_TENANT_MISMATCH";
pub const REASON_BOUNDARY_POLICY_MISMATCH: &str = "BOUNDARY_POLICY_MISMATCH";
pub const REASON_BOUNDARY_TYPE_MISSING: &str = "BOUNDARY_TYPE_MISSING";
pub const REASON_BOUNDARY_RESPONSE_FLOOR_VIOLATION: &str =
    "BOUNDARY_RESPONSE_FLOOR_VIOLATION";
pub const REASON_BOUNDARY_ASSESSMENT_EXPIRED: &str =
    "BOUNDARY_ASSESSMENT_EXPIRED";
pub const REASON_BOUNDARY_ASSESSMENT_REVOKED: &str =
    "BOUNDARY_ASSESSMENT_REVOKED";
pub const REASON_BOUNDARY_BINDING_DROPPED: &str = "BOUNDARY_BINDING_DROPPED";
pub const REASON_BOUNDARY_BINDING_INJECTED: &str = "BOUNDARY_BINDING_INJECTED";
pub const REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH: &str =
    "BOUNDARY_CLEARABLE_STATE_MISMATCH";
pub const REASON_BOUNDARY_ASSESSMENT_UNRESOLVED: &str =
    "BOUNDARY_ASSESSMENT_UNRESOLVED";
pub const REASON_BOUNDARY_TIME_INVALID: &str = "BOUNDARY_TIME_INVALID";
pub const REASON_BOUNDARY_LIFETIME_MISMATCH: &str =
    "BOUNDARY_LIFETIME_MISMATCH";

#[derive(Debug, Clone)]
pub struct BoundaryVerificationResult {
    pub decision: String,
    pub reason_code: String,
    pub detail: Option<String>,
}

impl BoundaryVerificationResult {
    fn accept() -> Self {
        Self {
            decision: "ACCEPT".into(),
            reason_code: REASON_BOUNDARY_ACCEPT.into(),
            detail: None,
        }
    }

    fn reject(reason: &'static str, detail: Option<String>) -> Self {
        Self {
            decision: "REJECT".into(),
            reason_code: reason.into(),
            detail,
        }
    }
}

fn instant(value: Option<&str>) -> Result<DateTime<FixedOffset>, String> {
    match value {
        Some(raw) => DateTime::parse_from_rfc3339(&raw.replace('Z', "+00:00"))
            .map_err(|_| "timestamp must include timezone".into()),
        None => Ok(Utc::now().fixed_offset()),
    }
}

fn non_clearable(state: BoundaryState) -> bool {
    matches!(
        state,
        BoundaryState::Unauthorized
            | BoundaryState::Indeterminate
            | BoundaryState::Stale
            | BoundaryState::Revoked
    )
}

pub fn verify_evaluation_boundary_binding(
    action_envelope: &Value,
    assessment: Option<&BoundaryCrossingAssessment>,
    evaluation: &GovernanceEvaluation,
    verification_time: Option<&str>,
) -> BoundaryVerificationResult {
    let requirements = match action_envelope
        .get("boundary_requirements")
        .and_then(Value::as_object)
    {
        Some(value) => value,
        None => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_REQUIRED_MISSING,
                Some("ActionEnvelope must declare fail-closed boundary requirements".into()),
            )
        }
    };
    let assessment = match assessment {
        Some(value) => value,
        None => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
                Some("evaluation binding cannot be resolved".into()),
            )
        }
    };

    if evaluation.boundary_assessment_binding.assessment_ref != assessment.assessment_id {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH,
            None,
        );
    }
    let assessment_digest = match assessment.digest() {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH,
                Some(error.to_string()),
            )
        }
    };
    if evaluation.boundary_assessment_binding.assessment_digest != assessment_digest {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH,
            None,
        );
    }
    if assessment.action_id != evaluation.action_id {
        return BoundaryVerificationResult::reject(REASON_BOUNDARY_ACTION_MISMATCH, None);
    }
    if assessment.tenant_id != evaluation.tenant_id {
        return BoundaryVerificationResult::reject(REASON_BOUNDARY_TENANT_MISMATCH, None);
    }

    let envelope_digest = match sha256_digest(action_envelope) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_ENVELOPE_MISMATCH,
                Some(error.to_string()),
            )
        }
    };
    if action_envelope.get("action_id").and_then(Value::as_str)
        != Some(assessment.action_id.as_str())
    {
        return BoundaryVerificationResult::reject(REASON_BOUNDARY_ACTION_MISMATCH, None);
    }
    if action_envelope.get("tenant_id").and_then(Value::as_str)
        != Some(assessment.tenant_id.as_str())
    {
        return BoundaryVerificationResult::reject(REASON_BOUNDARY_TENANT_MISMATCH, None);
    }
    if assessment.action_envelope_digest != envelope_digest
        || evaluation.action_envelope_digest != envelope_digest
    {
        return BoundaryVerificationResult::reject(REASON_BOUNDARY_ENVELOPE_MISMATCH, None);
    }

    if requirements.get("policy_ref").and_then(Value::as_str)
        != Some(assessment.requirement_policy_ref.as_str())
        || requirements.get("policy_digest").and_then(Value::as_str)
            != Some(assessment.requirement_policy_digest.as_str())
    {
        return BoundaryVerificationResult::reject(REASON_BOUNDARY_POLICY_MISMATCH, None);
    }

    let required_types: HashSet<&str> = requirements
        .get("required_types")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let present_types: HashSet<&str> = assessment
        .crossings
        .iter()
        .map(|item| match item.boundary_type {
            crate::BoundaryType::Execution => "EXECUTION",
            crate::BoundaryType::Disclosure => "DISCLOSURE",
            crate::BoundaryType::Mandate => "MANDATE",
            crate::BoundaryType::Resource => "RESOURCE",
            crate::BoundaryType::Evaluation => "EVALUATION",
        })
        .collect();
    let mut missing: Vec<&str> = required_types
        .difference(&present_types)
        .copied()
        .collect();
    missing.sort();
    if !missing.is_empty() {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_TYPE_MISSING,
            Some(missing.join(",")),
        );
    }

    let at = match instant(verification_time) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };
    let assessed_at = match instant(Some(&assessment.assessed_at)) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };
    let assessment_until = match instant(Some(&assessment.valid_until)) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };
    let evaluated_at = match instant(Some(&evaluation.evaluated_at)) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };
    let evaluation_until = match instant(Some(&evaluation.valid_until)) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };

    if assessed_at > evaluated_at {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_LIFETIME_MISMATCH,
            Some("evaluation predates assessment".into()),
        );
    }
    if evaluation_until > assessment_until {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_LIFETIME_MISMATCH,
            Some("evaluation outlives assessment".into()),
        );
    }
    if at >= assessment_until {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_ASSESSMENT_EXPIRED,
            None,
        );
    }
    if assessment.aggregate_state == BoundaryState::Revoked {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_ASSESSMENT_REVOKED,
            None,
        );
    }
    if !response_floor_satisfied(assessment.required_response_floor, evaluation.decision) {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_RESPONSE_FLOOR_VIOLATION,
            Some(format!(
                "{:?}>{:?}",
                assessment.required_response_floor, evaluation.decision
            )),
        );
    }
    BoundaryVerificationResult::accept()
}

pub fn verify_determination_boundary_binding(
    assessment: Option<&BoundaryCrossingAssessment>,
    evaluation: &GovernanceEvaluation,
    determination: &AdmissibilityDetermination,
) -> BoundaryVerificationResult {
    let assessment = match assessment {
        Some(value) => value,
        None => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
                None,
            )
        }
    };

    if evaluation.boundary_assessment_binding != determination.boundary_assessment_binding {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH,
            None,
        );
    }
    if determination.boundary_assessment_binding.assessment_ref != assessment.assessment_id {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH,
            None,
        );
    }
    let digest = match assessment.digest() {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH,
                Some(error.to_string()),
            )
        }
    };
    if determination.boundary_assessment_binding.assessment_digest != digest {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH,
            None,
        );
    }
    if determination.action_id != assessment.action_id
        || determination.action_id != evaluation.action_id
    {
        return BoundaryVerificationResult::reject(REASON_BOUNDARY_ACTION_MISMATCH, None);
    }
    if determination.tenant_id != assessment.tenant_id {
        return BoundaryVerificationResult::reject(REASON_BOUNDARY_TENANT_MISMATCH, None);
    }
    if determination.action_envelope_digest != assessment.action_envelope_digest
        || determination.action_envelope_digest != evaluation.action_envelope_digest
    {
        return BoundaryVerificationResult::reject(REASON_BOUNDARY_ENVELOPE_MISMATCH, None);
    }

    let evaluated_at = match instant(Some(&evaluation.evaluated_at)) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };
    let evaluation_until = match instant(Some(&evaluation.valid_until)) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };
    let determined_at = match instant(Some(&determination.determined_at)) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };
    let determination_until = match instant(Some(&determination.valid_until)) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };
    let assessment_until = match instant(Some(&assessment.valid_until)) {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_TIME_INVALID,
                Some(error),
            )
        }
    };

    if determined_at < evaluated_at {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_LIFETIME_MISMATCH,
            Some("determination predates evaluation".into()),
        );
    }
    if determination_until > evaluation_until || determination_until > assessment_until {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_LIFETIME_MISMATCH,
            Some("determination outlives bound evidence".into()),
        );
    }

    if non_clearable(assessment.aggregate_state)
        && matches!(
            determination.state,
            crate::AdmissibilityState::Admissible
                | crate::AdmissibilityState::ConditionallyAdmissible
        )
    {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH,
            Some(format!(
                "{:?}->{:?}",
                assessment.aggregate_state, determination.state
            )),
        );
    }
    if assessment.aggregate_state == BoundaryState::ConditionallyAuthorized
        && determination.state == crate::AdmissibilityState::Admissible
    {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH,
            Some("conditional assessment cannot become ADMISSIBLE".into()),
        );
    }
    BoundaryVerificationResult::accept()
}

pub fn verify_clearance_boundary_resolution(
    determination: &AdmissibilityDetermination,
    assessment: Option<&BoundaryCrossingAssessment>,
) -> BoundaryVerificationResult {
    let assessment = match assessment {
        Some(value) => value,
        None => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_ASSESSMENT_UNRESOLVED,
                None,
            )
        }
    };
    if determination.boundary_assessment_binding.assessment_ref != assessment.assessment_id {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_ASSESSMENT_REF_MISMATCH,
            None,
        );
    }
    let digest = match assessment.digest() {
        Ok(value) => value,
        Err(error) => {
            return BoundaryVerificationResult::reject(
                REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH,
                Some(error.to_string()),
            )
        }
    };
    if determination.boundary_assessment_binding.assessment_digest != digest {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_ASSESSMENT_DIGEST_MISMATCH,
            None,
        );
    }
    if non_clearable(assessment.aggregate_state) {
        return BoundaryVerificationResult::reject(
            REASON_BOUNDARY_CLEARABLE_STATE_MISMATCH,
            None,
        );
    }
    BoundaryVerificationResult::accept()
}

pub fn verify_boundary_chain(
    action_envelope: &Value,
    assessment: Option<&BoundaryCrossingAssessment>,
    evaluation: &GovernanceEvaluation,
    determination: &AdmissibilityDetermination,
    verification_time: Option<&str>,
) -> BoundaryVerificationResult {
    let evaluation_result = verify_evaluation_boundary_binding(
        action_envelope,
        assessment,
        evaluation,
        verification_time,
    );
    if evaluation_result.decision != "ACCEPT" {
        return evaluation_result;
    }
    let determination_result =
        verify_determination_boundary_binding(assessment, evaluation, determination);
    if determination_result.decision != "ACCEPT" {
        return determination_result;
    }
    verify_clearance_boundary_resolution(determination, assessment)
}
