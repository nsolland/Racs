//! RACS v0.2 runtime-continuity cross-artifact verification.
//!
//! Verification produces evidence and verified outcomes. It never creates
//! execution authority or widens a clearance.

use crate::continuity::{
    ContinuityDecision, ContinuityDecisionType, ContinuityPayload,
    EnvironmentGovernanceProfile, GovernedCapabilityManifest, GovernedExecutionSession,
    SessionState,
};
use crate::{AdmissibilityState, Decision, GovernanceClearance, GovernanceEvaluation};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub const REASON_ACCEPT: &str = "ACCEPT";
pub const REASON_SESSION_TERMINAL: &str = "SESSION_TERMINAL";
pub const REASON_SESSION_ACTION_ENVELOPE_MISMATCH: &str = "SESSION_ACTION_ENVELOPE_MISMATCH";
pub const REASON_SESSION_AUTHORITY_MISMATCH: &str = "SESSION_AUTHORITY_MISMATCH";
pub const REASON_SESSION_CAPABILITY_MANIFEST_MISMATCH: &str = "SESSION_CAPABILITY_MANIFEST_MISMATCH";
pub const REASON_SESSION_ENVIRONMENT_PROFILE_MISMATCH: &str = "SESSION_ENVIRONMENT_PROFILE_MISMATCH";
pub const REASON_SESSION_EVALUATION_MISMATCH: &str = "SESSION_EVALUATION_MISMATCH";
pub const REASON_SESSION_CLEARANCE_MISMATCH: &str = "SESSION_CLEARANCE_MISMATCH";
pub const REASON_SESSION_TENANT_MISMATCH: &str = "SESSION_TENANT_MISMATCH";
pub const REASON_SESSION_EXECUTOR_NOT_ALLOWED: &str = "SESSION_EXECUTOR_NOT_ALLOWED";
pub const REASON_SESSION_CAPABILITY_NOT_PERMITTED: &str = "SESSION_CAPABILITY_NOT_PERMITTED";
pub const REASON_SESSION_CONSEQUENCE_NOT_ALLOWED: &str = "SESSION_CONSEQUENCE_NOT_ALLOWED";
pub const REASON_SESSION_PROFILE_NOT_REFERENCED: &str = "SESSION_PROFILE_NOT_REFERENCED";
pub const REASON_SESSION_CLEARANCE_NOT_EXECUTABLE: &str = "SESSION_CLEARANCE_NOT_EXECUTABLE";
pub const REASON_SESSION_ARTIFACT_NOT_CURRENT: &str = "SESSION_ARTIFACT_NOT_CURRENT";
pub const REASON_SESSION_DEADLINE_EXCEEDS_AUTHORIZATION: &str = "SESSION_DEADLINE_EXCEEDS_AUTHORIZATION";

pub const REASON_BOUNDS_NARROWED: &str = "BOUNDS_NARROWED";
pub const REASON_BOUNDS_WIDENED: &str = "BOUNDS_WIDENED";
pub const REASON_BOUNDS_UNPROVABLE: &str = "BOUNDS_UNPROVABLE";
pub const REASON_BOUNDS_NOT_NARROWER: &str = "BOUNDS_NOT_NARROWER";

pub const REASON_DECISION_SESSION_MISMATCH: &str = "DECISION_SESSION_MISMATCH";
pub const REASON_DECISION_SEQUENCE_MISMATCH: &str = "DECISION_SEQUENCE_MISMATCH";
pub const REASON_DECISION_ACTION_MISMATCH: &str = "DECISION_ACTION_MISMATCH";
pub const REASON_DECISION_CAPABILITY_MISMATCH: &str = "DECISION_CAPABILITY_MISMATCH";
pub const REASON_DECISION_ENVIRONMENT_MISMATCH: &str = "DECISION_ENVIRONMENT_MISMATCH";
pub const REASON_DECISION_AUTHORITY_MISMATCH: &str = "DECISION_AUTHORITY_MISMATCH";
pub const REASON_DECISION_EXPIRED: &str = "DECISION_EXPIRED";
pub const REASON_DECISION_OUTLIVES_SESSION: &str = "DECISION_OUTLIVES_SESSION";

#[derive(Debug, Clone, PartialEq)]
pub struct ContinuityVerificationResult {
    pub decision: String,
    pub reason_code: String,
    pub detail: Option<String>,
    pub effective_bounds: Option<Map<String, Value>>,
}

impl ContinuityVerificationResult {
    pub fn accept(reason_code: &str) -> Self {
        Self {
            decision: "ACCEPT".into(),
            reason_code: reason_code.into(),
            detail: None,
            effective_bounds: None,
        }
    }

    pub fn accept_with_bounds(reason_code: &str, effective_bounds: Map<String, Value>) -> Self {
        Self {
            decision: "ACCEPT".into(),
            reason_code: reason_code.into(),
            detail: None,
            effective_bounds: Some(effective_bounds),
        }
    }

    pub fn reject(reason_code: &str, detail: impl Into<String>) -> Self {
        Self {
            decision: "REJECT".into(),
            reason_code: reason_code.into(),
            detail: Some(detail.into()),
            effective_bounds: None,
        }
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| error.to_string())
}

fn verification_time(value: Option<&str>) -> Result<DateTime<Utc>, String> {
    match value {
        Some(value) => parse_time(value),
        None => Ok(Utc::now()),
    }
}

fn is_terminal(state: SessionState) -> bool {
    matches!(
        state,
        SessionState::Completed | SessionState::Failed | SessionState::Stopped | SessionState::Halted
    )
}

fn current(now: DateTime<Utc>, valid_from: &str, valid_until: &str) -> Result<bool, String> {
    Ok(parse_time(valid_from)? <= now && now <= parse_time(valid_until)?)
}

pub fn verify_execution_session(
    session: &GovernedExecutionSession,
    manifest: &GovernedCapabilityManifest,
    profile: &EnvironmentGovernanceProfile,
    evaluation: &GovernanceEvaluation,
    clearance: &GovernanceClearance,
    verification_time_value: Option<&str>,
) -> ContinuityVerificationResult {
    if is_terminal(session.session_state) {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_TERMINAL,
            format!("session_state={:?} is terminal", session.session_state),
        );
    }

    if session.action_envelope_digest != evaluation.action_envelope_digest
        || session.action_envelope_digest != clearance.action_envelope_digest
    {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_ACTION_ENVELOPE_MISMATCH,
            "session, evaluation and clearance must bind the same ActionEnvelope",
        );
    }
    if session.authority_digest != clearance.authority_digest {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_AUTHORITY_MISMATCH,
            "session.authority_digest != clearance.authority_digest",
        );
    }

    let manifest_digest = match manifest.digest() {
        Ok(value) => value,
        Err(error) => {
            return ContinuityVerificationResult::reject(
                REASON_SESSION_CAPABILITY_MANIFEST_MISMATCH,
                error.to_string(),
            )
        }
    };
    if session.capability_manifest_digest != manifest_digest {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_CAPABILITY_MANIFEST_MISMATCH,
            "session does not bind the supplied capability manifest",
        );
    }

    let profile_digest = match profile.digest() {
        Ok(value) => value,
        Err(error) => {
            return ContinuityVerificationResult::reject(
                REASON_SESSION_ENVIRONMENT_PROFILE_MISMATCH,
                error.to_string(),
            )
        }
    };
    if session.environment_profile_digest != profile_digest {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_ENVIRONMENT_PROFILE_MISMATCH,
            "session does not bind the supplied environment profile",
        );
    }

    let evaluation_digest = match evaluation.digest() {
        Ok(value) => value,
        Err(error) => {
            return ContinuityVerificationResult::reject(
                REASON_SESSION_EVALUATION_MISMATCH,
                error.to_string(),
            )
        }
    };
    if session.governance_evaluation_digest != evaluation_digest {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_EVALUATION_MISMATCH,
            "session does not bind the supplied GovernanceEvaluation",
        );
    }

    let clearance_digest = match clearance.digest() {
        Ok(value) => value,
        Err(error) => {
            return ContinuityVerificationResult::reject(
                REASON_SESSION_CLEARANCE_MISMATCH,
                error.to_string(),
            )
        }
    };
    if session.reht_clearance_digest != clearance_digest {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_CLEARANCE_MISMATCH,
            "session does not bind the supplied GovernanceClearance",
        );
    }

    if profile.tenant_id != evaluation.tenant_id || profile.tenant_id != clearance.tenant_id {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_TENANT_MISMATCH,
            "profile, evaluation and clearance tenant bindings differ",
        );
    }
    if !manifest
        .executor_binding
        .allowed_executor_ids
        .contains(&session.executor_id)
    {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_EXECUTOR_NOT_ALLOWED,
            "executor_id is outside the admitted executor binding",
        );
    }
    if !manifest.permissions.contains(&clearance.capability) {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_CAPABILITY_NOT_PERMITTED,
            "clearance capability is not admitted by the manifest",
        );
    }
    if !manifest.consequence_classes.contains(&clearance.consequence_class)
        || !profile
            .allowed_consequence_classes
            .contains(&clearance.consequence_class)
    {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_CONSEQUENCE_NOT_ALLOWED,
            "consequence class is outside manifest or environment admission",
        );
    }

    let versioned_profile_ref = format!("{}@{}", profile.profile_id, profile.profile_version);
    if !manifest
        .environment_profile_refs
        .iter()
        .any(|value| value == &profile.profile_id || value == &versioned_profile_ref)
    {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_PROFILE_NOT_REFERENCED,
            "manifest does not reference the bound environment profile",
        );
    }

    let executable_clearance = matches!(clearance.decision, Decision::Allow | Decision::Modify)
        && matches!(
            clearance.admissibility_state,
            AdmissibilityState::Admissible | AdmissibilityState::ConditionallyAdmissible
        )
        && matches!(evaluation.decision, Decision::Allow | Decision::Modify);
    if !executable_clearance {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_CLEARANCE_NOT_EXECUTABLE,
            "evaluation or clearance is not executable",
        );
    }

    let now = match verification_time(verification_time_value) {
        Ok(value) => value,
        Err(error) => {
            return ContinuityVerificationResult::reject(
                REASON_SESSION_ARTIFACT_NOT_CURRENT,
                error,
            )
        }
    };
    let windows = [
        (&manifest.issued_at, &manifest.expires_at),
        (&profile.valid_from, &profile.expires_at),
        (&clearance.valid_from, &clearance.valid_until),
        (&evaluation.evaluated_at, &evaluation.valid_until),
    ];
    for (valid_from, valid_until) in windows {
        match current(now, valid_from, valid_until) {
            Ok(true) => {}
            Ok(false) => {
                return ContinuityVerificationResult::reject(
                    REASON_SESSION_ARTIFACT_NOT_CURRENT,
                    "one or more bound artifacts are not current at verification time",
                )
            }
            Err(error) => {
                return ContinuityVerificationResult::reject(
                    REASON_SESSION_ARTIFACT_NOT_CURRENT,
                    error,
                )
            }
        }
    }

    let deadlines = [
        &manifest.expires_at,
        &profile.expires_at,
        &evaluation.valid_until,
        &clearance.valid_until,
    ];
    let mut authorization_deadline: Option<DateTime<Utc>> = None;
    for value in deadlines {
        let parsed = match parse_time(value) {
            Ok(value) => value,
            Err(error) => {
                return ContinuityVerificationResult::reject(
                    REASON_SESSION_ARTIFACT_NOT_CURRENT,
                    error,
                )
            }
        };
        authorization_deadline = Some(match authorization_deadline {
            Some(current) => current.min(parsed),
            None => parsed,
        });
    }
    match parse_time(&session.must_complete_by) {
        Ok(deadline) if deadline > authorization_deadline.expect("deadline exists") => {
            return ContinuityVerificationResult::reject(
                REASON_SESSION_DEADLINE_EXCEEDS_AUTHORIZATION,
                "session deadline exceeds a bound artifact validity window",
            )
        }
        Err(error) => {
            return ContinuityVerificationResult::reject(
                REASON_SESSION_DEADLINE_EXCEEDS_AUTHORIZATION,
                error,
            )
        }
        _ => {}
    }

    ContinuityVerificationResult::accept(REASON_ACCEPT)
}

#[derive(Debug)]
struct BoundsFailure {
    reason_code: &'static str,
    detail: String,
}

impl BoundsFailure {
    fn new(reason_code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            reason_code,
            detail: detail.into(),
        }
    }
}

pub fn prove_runtime_bounds_narrowing(
    current_bounds: &Map<String, Value>,
    proposed_bounds: &Map<String, Value>,
) -> ContinuityVerificationResult {
    match prove_mapping(current_bounds, proposed_bounds, "") {
        Ok(true) => ContinuityVerificationResult::accept_with_bounds(
            REASON_BOUNDS_NARROWED,
            proposed_bounds.clone(),
        ),
        Ok(false) => ContinuityVerificationResult::reject(
            REASON_BOUNDS_NOT_NARROWER,
            "MODIFY_RUNTIME_BOUNDS must make at least one bound stricter",
        ),
        Err(failure) => ContinuityVerificationResult::reject(failure.reason_code, failure.detail),
    }
}

fn prove_mapping(
    current: &Map<String, Value>,
    proposed: &Map<String, Value>,
    path: &str,
) -> Result<bool, BoundsFailure> {
    let mut changed = false;
    for (key, proposed_value) in proposed {
        let item_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        let current_value = current.get(key).ok_or_else(|| {
            BoundsFailure::new(
                REASON_BOUNDS_UNPROVABLE,
                format!("{item_path}: dimension is not present in the current bounds"),
            )
        })?;
        changed |= prove_value(key, current_value, proposed_value, &item_path)?;
    }
    Ok(changed)
}

fn prove_value(
    key: &str,
    current: &Value,
    proposed: &Value,
    path: &str,
) -> Result<bool, BoundsFailure> {
    match (current, proposed) {
        (Value::Bool(left), Value::Bool(right)) => {
            if left != right {
                Err(BoundsFailure::new(
                    REASON_BOUNDS_UNPROVABLE,
                    format!("{path}: boolean direction is not declared"),
                ))
            } else {
                Ok(false)
            }
        }
        (Value::Number(left), Value::Number(right)) => {
            let left = left.as_f64().ok_or_else(|| {
                BoundsFailure::new(
                    REASON_BOUNDS_UNPROVABLE,
                    format!("{path}: number is not comparable"),
                )
            })?;
            let right = right.as_f64().ok_or_else(|| {
                BoundsFailure::new(
                    REASON_BOUNDS_UNPROVABLE,
                    format!("{path}: number is not comparable"),
                )
            })?;
            let minimum_dimension =
                key.starts_with("min_") || key.contains("minimum") || key.contains("floor");
            if minimum_dimension {
                if right < left {
                    Err(BoundsFailure::new(
                        REASON_BOUNDS_WIDENED,
                        format!("{path}: minimum decreased"),
                    ))
                } else {
                    Ok(right > left)
                }
            } else if right > left {
                Err(BoundsFailure::new(
                    REASON_BOUNDS_WIDENED,
                    format!("{path}: upper bound increased"),
                ))
            } else {
                Ok(right < left)
            }
        }
        (Value::String(left), Value::String(right)) => {
            let time_key = matches!(
                key,
                "deadline" | "expires_at" | "valid_until" | "must_complete_by" | "end_at" | "latest_finish_at"
            ) || key.ends_with("_deadline")
                || key.ends_with("_expires_at")
                || key.ends_with("_valid_until");
            if time_key {
                let left_time = parse_time(left).map_err(|_| {
                    BoundsFailure::new(
                        REASON_BOUNDS_UNPROVABLE,
                        format!("{path}: invalid time bound"),
                    )
                })?;
                let right_time = parse_time(right).map_err(|_| {
                    BoundsFailure::new(
                        REASON_BOUNDS_UNPROVABLE,
                        format!("{path}: invalid time bound"),
                    )
                })?;
                if right_time > left_time {
                    Err(BoundsFailure::new(
                        REASON_BOUNDS_WIDENED,
                        format!("{path}: deadline moved later"),
                    ))
                } else {
                    Ok(right_time < left_time)
                }
            } else if left != right {
                Err(BoundsFailure::new(
                    REASON_BOUNDS_UNPROVABLE,
                    format!("{path}: string direction is not declared"),
                ))
            } else {
                Ok(false)
            }
        }
        (Value::Object(left), Value::Object(right)) => prove_mapping(left, right, path),
        (Value::Array(left), Value::Array(right)) => {
            let left_set = scalar_set(left).ok_or_else(|| {
                BoundsFailure::new(
                    REASON_BOUNDS_UNPROVABLE,
                    format!("{path}: complex list membership cannot be proven"),
                )
            })?;
            let right_set = scalar_set(right).ok_or_else(|| {
                BoundsFailure::new(
                    REASON_BOUNDS_UNPROVABLE,
                    format!("{path}: complex list membership cannot be proven"),
                )
            })?;
            if !right_set.is_subset(&left_set) {
                Err(BoundsFailure::new(
                    REASON_BOUNDS_WIDENED,
                    format!("{path}: allowed set expanded"),
                ))
            } else {
                Ok(right_set != left_set)
            }
        }
        (Value::Null, Value::Null) => Ok(false),
        _ if std::mem::discriminant(current) != std::mem::discriminant(proposed) => Err(
            BoundsFailure::new(REASON_BOUNDS_UNPROVABLE, format!("{path}: type changed")),
        ),
        _ if current == proposed => Ok(false),
        _ => Err(BoundsFailure::new(
            REASON_BOUNDS_UNPROVABLE,
            format!("{path}: narrowing semantics are not declared"),
        )),
    }
}

fn scalar_set(values: &[Value]) -> Option<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for value in values {
        let key = match value {
            Value::String(value) => format!("s:{value}"),
            Value::Number(value) => format!("n:{value}"),
            Value::Bool(value) => format!("b:{value}"),
            Value::Null => "null".to_string(),
            _ => return None,
        };
        result.insert(key);
    }
    Some(result)
}

pub fn verify_continuity_decision(
    session: &GovernedExecutionSession,
    decision: &ContinuityDecision,
    current_bounds: &Map<String, Value>,
    verification_time_value: Option<&str>,
) -> ContinuityVerificationResult {
    if is_terminal(session.session_state) {
        return ContinuityVerificationResult::reject(
            REASON_SESSION_TERMINAL,
            format!("session_state={:?} is terminal", session.session_state),
        );
    }
    if decision.session_id != session.session_id {
        return ContinuityVerificationResult::reject(
            REASON_DECISION_SESSION_MISMATCH,
            "decision.session_id != session.session_id",
        );
    }
    if decision.continuity_sequence != session.continuity_sequence + 1 {
        return ContinuityVerificationResult::reject(
            REASON_DECISION_SEQUENCE_MISMATCH,
            "continuity sequence must advance by exactly one",
        );
    }
    if decision.action_envelope_digest != session.action_envelope_digest {
        return ContinuityVerificationResult::reject(
            REASON_DECISION_ACTION_MISMATCH,
            "decision action binding differs from the session",
        );
    }
    if decision.capability_manifest_digest != session.capability_manifest_digest {
        return ContinuityVerificationResult::reject(
            REASON_DECISION_CAPABILITY_MISMATCH,
            "decision capability binding differs from the session",
        );
    }
    if decision.environment_profile_digest != session.environment_profile_digest {
        return ContinuityVerificationResult::reject(
            REASON_DECISION_ENVIRONMENT_MISMATCH,
            "decision environment binding differs from the session",
        );
    }
    if decision.authority_state_digest != session.authority_digest {
        return ContinuityVerificationResult::reject(
            REASON_DECISION_AUTHORITY_MISMATCH,
            "decision authority state differs from the session",
        );
    }

    let now = match verification_time(verification_time_value) {
        Ok(value) => value,
        Err(error) => return ContinuityVerificationResult::reject(REASON_DECISION_EXPIRED, error),
    };
    let valid_until = match parse_time(&decision.valid_until) {
        Ok(value) => value,
        Err(error) => return ContinuityVerificationResult::reject(REASON_DECISION_EXPIRED, error),
    };
    if valid_until < now {
        return ContinuityVerificationResult::reject(
            REASON_DECISION_EXPIRED,
            "continuity decision is expired",
        );
    }
    match parse_time(&session.must_complete_by) {
        Ok(session_deadline) if valid_until > session_deadline => {
            return ContinuityVerificationResult::reject(
                REASON_DECISION_OUTLIVES_SESSION,
                "continuity decision cannot outlive the session",
            )
        }
        Err(error) => {
            return ContinuityVerificationResult::reject(REASON_DECISION_OUTLIVES_SESSION, error)
        }
        _ => {}
    }

    if decision.decision == ContinuityDecisionType::ModifyRuntimeBounds {
        let constraints = match &decision.constraints {
            Some(Value::Object(value)) => value,
            _ => {
                return ContinuityVerificationResult::reject(
                    REASON_BOUNDS_UNPROVABLE,
                    "MODIFY_RUNTIME_BOUNDS has no object constraints",
                )
            }
        };
        return prove_runtime_bounds_narrowing(current_bounds, constraints);
    }

    ContinuityVerificationResult::accept(REASON_ACCEPT)
}
