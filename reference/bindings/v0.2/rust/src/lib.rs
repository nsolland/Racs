//! RACS v0.2 canonical contract bindings.

pub mod boundary_crossing;
pub mod boundary_validation;
pub mod continuity;
pub mod continuity_verification;
pub mod validation;
pub mod verification;

pub use boundary_crossing::*;
pub use boundary_validation::*;
pub use continuity::*;
pub use continuity_verification::*;
pub use validation::*;
pub use verification::*;

use serde::{Deserialize, Serialize};
use serde_jcs::to_string as canonicalize;
use sha2::{Digest, Sha256};
use std::error::Error;

pub fn canonical_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(canonicalize(value)?.into_bytes())
}

pub fn sha256_digest<T: Serialize + ?Sized>(value: &T) -> Result<String, Box<dyn Error>> {
    let canon = canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(&canon);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub fn canonical_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Box<dyn Error>> {
    let bytes = canonical_bytes(value)?;
    String::from_utf8(bytes)
        .map_err(|error| Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)) as Box<dyn Error>)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    Modify,
    Defer,
    Deny,
    #[serde(rename = "STEP_UP")]
    StepUp,
    Halt,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    PresentAndValid,
    PresentButInvalid,
    Missing,
    Unknown,
    Unavailable,
    Stale,
    Revoked,
    Conflicting,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissibilityState {
    Admissible,
    ConditionallyAdmissible,
    NotAdmissible,
    Indeterminate,
    Stale,
    Revoked,
    Halted,
    RequiresStepUp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConsequenceClass {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Reversibility {
    Reversible,
    Compensatable,
    Irreversible,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationBinding {
    pub evaluation_ref: String,
    pub evaluation_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceEvaluation {
    pub evaluation_id: String,
    pub action_id: String,
    pub action_envelope_digest: String,
    pub tenant_id: String,
    pub evaluator_id: String,
    pub evaluator_version: String,
    pub decision: Decision,
    pub authority_status: Status,
    pub policy_status: Status,
    pub evidence_status: Status,
    pub purpose_status: Status,
    pub state_status: Status,
    pub risk_status: Status,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,
    pub boundary_assessment_binding: BoundaryAssessmentBinding,
    pub evaluated_at: String,
    pub valid_until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdmissibilityDetermination {
    pub determination_id: String,
    pub action_id: String,
    pub action_envelope_digest: String,
    pub tenant_id: String,
    pub authority_digest: String,
    pub delegation_chain_digest: String,
    pub policy_digest: String,
    pub evidence_digest: String,
    pub purpose_digest: String,
    pub state_digest: String,
    pub evaluation_bindings: Vec<EvaluationBinding>,
    pub boundary_assessment_binding: BoundaryAssessmentBinding,
    pub state: AdmissibilityState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    pub determined_at: String,
    pub valid_until: String,
    pub revocation_registry_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceClearance {
    pub clearance_id: String,
    pub action_id: String,
    pub action_envelope_digest: String,
    pub tenant_id: String,
    pub decision: Decision,
    pub admissibility_state: AdmissibilityState,
    pub authority_digest: String,
    pub delegation_chain_digest: String,
    pub policy_digest: String,
    pub evidence_digest: String,
    pub purpose_digest: String,
    pub state_digest: String,
    pub target_digest: String,
    pub payload_digest: String,
    pub connector_id: String,
    pub capability: String,
    pub consequence_class: ConsequenceClass,
    pub reversibility: Reversibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,
    pub valid_from: String,
    pub valid_until: String,
    pub replay_nonce: String,
    pub idempotency_key: String,
    pub revocation_registry_ref: String,
    pub evaluator_refs: Vec<String>,
    pub admissibility_determination_ref: String,
    pub admissibility_determination_digest: String,
}

impl GovernanceEvaluation {
    pub fn canonical(&self) -> Result<String, Box<dyn Error>> {
        canonical_string(self)
    }

    pub fn digest(&self) -> Result<String, Box<dyn Error>> {
        sha256_digest(self)
    }
}

impl AdmissibilityDetermination {
    pub fn canonical(&self) -> Result<String, Box<dyn Error>> {
        canonical_string(self)
    }

    pub fn digest(&self) -> Result<String, Box<dyn Error>> {
        sha256_digest(self)
    }
}

impl GovernanceClearance {
    pub fn canonical(&self) -> Result<String, Box<dyn Error>> {
        canonical_string(self)
    }

    pub fn digest(&self) -> Result<String, Box<dyn Error>> {
        sha256_digest(self)
    }
}
