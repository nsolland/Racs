use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;

use crate::{canonical_string, sha256_digest};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryType {
    Execution,
    Disclosure,
    Mandate,
    Resource,
    Evaluation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryState {
    NoCrossing,
    Authorized,
    ConditionallyAuthorized,
    Unauthorized,
    Indeterminate,
    Stale,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryResponseFloor {
    None,
    Modify,
    Defer,
    StepUp,
    Deny,
    Halt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    pub r#ref: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundaryAssessmentBinding {
    pub assessment_ref: String,
    pub assessment_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundaryRequirementSet {
    pub required_types: Vec<BoundaryType>,
    pub policy_ref: String,
    pub policy_digest: String,
    pub fail_closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundaryCrossing {
    pub crossing_id: String,
    pub boundary_type: BoundaryType,
    pub crossing_detected: bool,
    pub prior_state_digest: String,
    pub proposed_state_digest: String,
    pub authority_requirement_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_binding: Option<ArtifactBinding>,
    pub policy_binding: ArtifactBinding,
    pub evidence_binding: ArtifactBinding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_reservation_binding: Option<ArtifactBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_provenance_binding: Option<ArtifactBinding>,
    pub details_digest: String,
    pub state: BoundaryState,
    pub required_response_floor: BoundaryResponseFloor,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    pub observed_at: String,
    pub valid_until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundaryCrossingAssessment {
    pub schema_version: String,
    pub assessment_id: String,
    pub action_id: String,
    pub action_envelope_digest: String,
    pub tenant_id: String,
    pub assessor_id: String,
    pub assessor_version: String,
    pub requirement_policy_ref: String,
    pub requirement_policy_digest: String,
    pub crossings: Vec<BoundaryCrossing>,
    pub aggregate_state: BoundaryState,
    pub required_response_floor: BoundaryResponseFloor,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    pub assessed_at: String,
    pub valid_until: String,
    pub revocation_registry_ref: String,
}

fn parse_time(value: &str) -> Result<DateTime<chrono::FixedOffset>, String> {
    if !(value.ends_with('Z')
        || value
            .get(value.len().saturating_sub(6)..)
            .map(|tail| {
                let bytes = tail.as_bytes();
                tail.len() == 6
                    && (bytes[0] == b'+' || bytes[0] == b'-')
                    && bytes[3] == b':'
            })
            .unwrap_or(false))
    {
        return Err("timestamp must include timezone".into());
    }
    DateTime::parse_from_rfc3339(&value.replace('Z', "+00:00"))
        .map_err(|_| "timestamp must include timezone".into())
}

fn boundary_rank(value: BoundaryType) -> u8 {
    match value {
        BoundaryType::Execution => 0,
        BoundaryType::Disclosure => 1,
        BoundaryType::Mandate => 2,
        BoundaryType::Resource => 3,
        BoundaryType::Evaluation => 4,
    }
}

fn state_rank(value: BoundaryState) -> u8 {
    match value {
        BoundaryState::NoCrossing => 0,
        BoundaryState::Authorized => 1,
        BoundaryState::ConditionallyAuthorized => 2,
        BoundaryState::Indeterminate => 3,
        BoundaryState::Unauthorized => 4,
        BoundaryState::Stale => 5,
        BoundaryState::Revoked => 6,
    }
}

fn response_rank(value: BoundaryResponseFloor) -> u8 {
    match value {
        BoundaryResponseFloor::None => 0,
        BoundaryResponseFloor::Modify => 1,
        BoundaryResponseFloor::Defer => 2,
        BoundaryResponseFloor::StepUp => 3,
        BoundaryResponseFloor::Deny => 4,
        BoundaryResponseFloor::Halt => 5,
    }
}

fn sorted_unique(values: &[String]) -> bool {
    let unique: HashSet<&String> = values.iter().collect();
    unique.len() == values.len() && values.windows(2).all(|pair| pair[0] <= pair[1])
}

impl BoundaryRequirementSet {
    pub fn validate_semantics(&self) -> Result<(), String> {
        if self.required_types.is_empty() {
            return Err("required_types must not be empty".into());
        }
        let unique: HashSet<BoundaryType> = self.required_types.iter().copied().collect();
        if unique.len() != self.required_types.len() {
            return Err("required_types must be unique".into());
        }
        if !self
            .required_types
            .windows(2)
            .all(|pair| boundary_rank(pair[0]) <= boundary_rank(pair[1]))
        {
            return Err("required_types must use canonical boundary order".into());
        }
        if !self.required_types.contains(&BoundaryType::Execution) {
            return Err("EXECUTION boundary is mandatory for every ActionEnvelope".into());
        }
        if !self.fail_closed {
            return Err("boundary requirements must be fail_closed".into());
        }
        Ok(())
    }
}

impl BoundaryCrossing {
    pub fn validate_semantics(&self) -> Result<(), String> {
        let observed = parse_time(&self.observed_at)?;
        let valid_until = parse_time(&self.valid_until)?;
        if valid_until <= observed {
            return Err("crossing valid_until must be after observed_at".into());
        }
        if !sorted_unique(&self.reason_codes) {
            return Err("reason_codes must be unique and sorted".into());
        }

        let changed = self.prior_state_digest != self.proposed_state_digest;
        if self.crossing_detected != changed {
            return Err("crossing_detected must equal state-digest change".into());
        }
        if !self.crossing_detected {
            if self.state != BoundaryState::NoCrossing {
                return Err("non-crossing must use NO_CROSSING".into());
            }
            if self.required_response_floor != BoundaryResponseFloor::None {
                return Err("non-crossing must use NONE response".into());
            }
            if !self.reason_codes.is_empty() {
                return Err("non-crossing cannot carry reason codes".into());
            }
            return Ok(());
        }

        if self.state == BoundaryState::NoCrossing {
            return Err("detected crossing cannot use NO_CROSSING".into());
        }
        if matches!(
            self.state,
            BoundaryState::Authorized | BoundaryState::ConditionallyAuthorized
        ) && self.authority_binding.is_none()
        {
            return Err("authorized crossing requires authority_binding".into());
        }

        let minimum = match self.state {
            BoundaryState::Authorized => BoundaryResponseFloor::None,
            BoundaryState::ConditionallyAuthorized => BoundaryResponseFloor::Modify,
            BoundaryState::Indeterminate => BoundaryResponseFloor::Defer,
            BoundaryState::Unauthorized => BoundaryResponseFloor::Deny,
            BoundaryState::Stale => BoundaryResponseFloor::Defer,
            BoundaryState::Revoked => BoundaryResponseFloor::Deny,
            BoundaryState::NoCrossing => BoundaryResponseFloor::None,
        };
        if response_rank(self.required_response_floor) < response_rank(minimum) {
            return Err("boundary response is weaker than required state minimum".into());
        }
        if self.state == BoundaryState::Authorized
            && self.required_response_floor != BoundaryResponseFloor::None
        {
            return Err("AUTHORIZED crossing must use NONE response".into());
        }
        if self.state == BoundaryState::ConditionallyAuthorized
            && self.required_response_floor != BoundaryResponseFloor::Modify
        {
            return Err("CONDITIONALLY_AUTHORIZED crossing must use MODIFY response".into());
        }

        let reasons: HashSet<&str> = self.reason_codes.iter().map(String::as_str).collect();
        if reasons.contains("TECHNICAL_ACCESS_ONLY") {
            if self.state != BoundaryState::Unauthorized {
                return Err("technical access alone cannot authorize execution".into());
            }
            if !matches!(
                self.required_response_floor,
                BoundaryResponseFloor::Deny | BoundaryResponseFloor::Halt
            ) {
                return Err("technical access alone requires DENY or HALT".into());
            }
        }
        if reasons.contains("UNAUTHORIZED_DISCOVERABILITY")
            && self.state != BoundaryState::Unauthorized
        {
            return Err("unauthorized discoverability must be UNAUTHORIZED".into());
        }
        if reasons.contains("RESOURCE_LIMIT_EXCEEDED")
            && self.state != BoundaryState::Unauthorized
        {
            return Err("resource limit exceeded must be UNAUTHORIZED".into());
        }
        if self.boundary_type == BoundaryType::Resource
            && matches!(
                self.state,
                BoundaryState::Authorized | BoundaryState::ConditionallyAuthorized
            )
            && self.resource_reservation_binding.is_none()
        {
            return Err("authorized resource crossing requires reservation binding".into());
        }
        if self.boundary_type == BoundaryType::Evaluation
            && self.evaluation_provenance_binding.is_none()
        {
            return Err("evaluation crossing requires provenance binding".into());
        }
        Ok(())
    }
}

impl BoundaryCrossingAssessment {
    pub fn canonical(&self) -> Result<String, Box<dyn Error>> {
        canonical_string(self)
    }

    pub fn digest(&self) -> Result<String, Box<dyn Error>> {
        sha256_digest(self)
    }

    pub fn validate_semantics(&self) -> Result<(), String> {
        if self.schema_version != "racs.boundary-crossing-assessment.v0.2" {
            return Err("invalid boundary assessment schema_version".into());
        }
        let assessed = parse_time(&self.assessed_at)?;
        let valid_until = parse_time(&self.valid_until)?;
        if valid_until <= assessed {
            return Err("assessment valid_until must be after assessed_at".into());
        }
        if self.crossings.is_empty() {
            return Err("assessment must include at least one crossing".into());
        }

        let types: Vec<BoundaryType> =
            self.crossings.iter().map(|item| item.boundary_type).collect();
        let unique_types: HashSet<BoundaryType> = types.iter().copied().collect();
        if unique_types.len() != types.len() {
            return Err("assessment cannot repeat boundary types".into());
        }
        if !types
            .windows(2)
            .all(|pair| boundary_rank(pair[0]) <= boundary_rank(pair[1]))
        {
            return Err("crossings must use canonical boundary order".into());
        }
        if !types.contains(&BoundaryType::Execution) {
            return Err("assessment must include EXECUTION boundary".into());
        }

        let ids: HashSet<&String> = self.crossings.iter().map(|item| &item.crossing_id).collect();
        if ids.len() != self.crossings.len() {
            return Err("crossing_id values must be unique".into());
        }

        for crossing in &self.crossings {
            crossing.validate_semantics()?;
            if crossing.policy_binding.r#ref != self.requirement_policy_ref {
                return Err("crossing policy ref must match requirement policy".into());
            }
            if crossing.policy_binding.digest != self.requirement_policy_digest {
                return Err("crossing policy digest must match requirement policy".into());
            }
            if parse_time(&crossing.observed_at)? > assessed {
                return Err("crossing cannot be observed after assessment".into());
            }
            if parse_time(&crossing.valid_until)? < valid_until {
                return Err("assessment cannot outlive crossing evidence".into());
            }
        }

        let expected_state = self
            .crossings
            .iter()
            .max_by_key(|item| state_rank(item.state))
            .map(|item| item.state)
            .ok_or_else(|| "assessment must include at least one crossing".to_string())?;
        let expected_response = self
            .crossings
            .iter()
            .max_by_key(|item| response_rank(item.required_response_floor))
            .map(|item| item.required_response_floor)
            .ok_or_else(|| "assessment must include at least one crossing".to_string())?;
        let mut expected_reasons: Vec<String> = self
            .crossings
            .iter()
            .flat_map(|item| item.reason_codes.iter().cloned())
            .collect::<HashSet<String>>()
            .into_iter()
            .collect();
        expected_reasons.sort();

        if self.aggregate_state != expected_state {
            return Err("aggregate_state does not match crossings".into());
        }
        if self.required_response_floor != expected_response {
            return Err("required_response_floor does not match crossings".into());
        }
        if self.reason_codes != expected_reasons {
            return Err("assessment reason_codes must equal sorted crossing union".into());
        }
        Ok(())
    }
}

pub fn response_floor_satisfied(
    response_floor: BoundaryResponseFloor,
    decision: crate::Decision,
) -> bool {
    match response_floor {
        BoundaryResponseFloor::None => true,
        BoundaryResponseFloor::Modify => !matches!(decision, crate::Decision::Allow),
        BoundaryResponseFloor::Defer => matches!(
            decision,
            crate::Decision::Defer
                | crate::Decision::StepUp
                | crate::Decision::Deny
                | crate::Decision::Halt
        ),
        BoundaryResponseFloor::StepUp => matches!(
            decision,
            crate::Decision::StepUp | crate::Decision::Deny | crate::Decision::Halt
        ),
        BoundaryResponseFloor::Deny => {
            matches!(decision, crate::Decision::Deny | crate::Decision::Halt)
        }
        BoundaryResponseFloor::Halt => matches!(decision, crate::Decision::Halt),
    }
}
