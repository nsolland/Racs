//! RACS v0.2 runtime conformance — Port A schema and typed validation.

use crate::{
    canonical_string, sha256_digest, AdmissibilityDetermination,
    BoundaryCrossingAssessment, GovernanceClearance, GovernanceEvaluation,
};
use jsonschema::JSONSchema;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;

pub const REASON_ACCEPT: &str = "ACCEPT";
pub const REASON_SCHEMA_INVALID: &str = "SCHEMA_INVALID";
pub const REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS: &str =
    "CLEARANCE_ALLOW_HAS_CONSTRAINTS";
pub const REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS: &str =
    "CLEARANCE_MODIFY_MISSING_CONSTRAINTS";
pub const REASON_CLEARANCE_ALLOW_STATE_MISMATCH: &str =
    "CLEARANCE_ALLOW_STATE_MISMATCH";
pub const REASON_CLEARANCE_MODIFY_STATE_MISMATCH: &str =
    "CLEARANCE_MODIFY_STATE_MISMATCH";
pub const REASON_EVALUATION_BINDING_DIGEST_MISMATCH: &str =
    "EVALUATION_BINDING_DIGEST_MISMATCH";
pub const REASON_EVALUATION_BINDING_REF_MISMATCH: &str =
    "EVALUATION_BINDING_REF_MISMATCH";
pub const REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH: &str =
    "CLEARANCE_DETERMINATION_DIGEST_MISMATCH";
pub const REASON_CLEARANCE_ACTION_MISMATCH: &str = "CLEARANCE_ACTION_MISMATCH";
pub const REASON_CLEARANCE_ENVELOPE_MISMATCH: &str =
    "CLEARANCE_ENVELOPE_MISMATCH";
pub const REASON_CLEARANCE_NEGATIVE_STATE: &str = "CLEARANCE_NEGATIVE_STATE";
pub const REASON_CLEARANCE_EXPIRED: &str = "CLEARANCE_EXPIRED";
pub const REASON_CLEARANCE_REVOKED: &str = "CLEARANCE_REVOKED";

pub struct ArtifactType {
    pub schema_file: &'static str,
}

pub fn artifact_types() -> HashMap<&'static str, ArtifactType> {
    HashMap::from([
        (
            "GovernanceEvaluation",
            ArtifactType {
                schema_file: "governance-evaluation-v0.2.schema.json",
            },
        ),
        (
            "AdmissibilityDetermination",
            ArtifactType {
                schema_file: "admissibility-determination-v0.2.schema.json",
            },
        ),
        (
            "GovernanceClearance",
            ArtifactType {
                schema_file: "governance-clearance.schema.json",
            },
        ),
        (
            "BoundaryCrossingAssessment",
            ArtifactType {
                schema_file: "boundary-crossing-assessment-v0.2.schema.json",
            },
        ),
    ])
}

pub struct Raw<T> {
    pub data: Value,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Raw<T> {
    pub fn new(data: Value) -> Self {
        Self {
            data,
            _marker: std::marker::PhantomData,
        }
    }
}

pub struct Validated<T> {
    pub artifact_type: String,
    pub model: T,
    pub payload: Value,
}

pub struct Verified<T> {
    pub artifact_type: String,
    pub model: T,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub decision: String,
    pub reason_code: String,
    pub canonical: Option<String>,
    pub payload_digest: Option<String>,
    pub error_path: Option<String>,
}

impl ValidationResult {
    pub fn to_json(&self) -> Result<String, Box<dyn Error>> {
        let mut output = serde_json::Map::new();
        output.insert("decision".into(), Value::String(self.decision.clone()));
        output.insert("reason_code".into(), Value::String(self.reason_code.clone()));
        if let Some(value) = &self.canonical {
            output.insert("canonical".into(), Value::String(value.clone()));
        }
        if let Some(value) = &self.payload_digest {
            output.insert("payload_digest".into(), Value::String(value.clone()));
        }
        if let Some(value) = &self.error_path {
            output.insert("error_path".into(), Value::String(value.clone()));
        }
        serde_json::to_string(&Value::Object(output)).map_err(|error| error.into())
    }
}

#[derive(Debug)]
pub struct SchemaValidationError {
    pub message: String,
    pub path: String,
}

impl std::fmt::Display for SchemaValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let location = if self.path.is_empty() {
            "<root>"
        } else {
            &self.path
        };
        write!(formatter, "{} (at {})", self.message, location)
    }
}

impl Error for SchemaValidationError {}

fn repo_root() -> PathBuf {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in
        std::iter::once(start.clone()).chain(start.ancestors().map(|path| path.to_path_buf()))
    {
        if candidate
            .join("spec")
            .join("governance-clearance.schema.json")
            .exists()
        {
            return candidate;
        }
    }
    panic!("could not locate RACS spec/ directory");
}

fn validator(artifact_type: &str) -> Result<JSONSchema, Box<dyn Error>> {
    let types = artifact_types();
    let entry = types
        .get(artifact_type)
        .ok_or_else(|| format!("unknown artifact_type: {artifact_type}"))?;
    let text = std::fs::read_to_string(repo_root().join("spec").join(entry.schema_file))?;
    let schema: Value = serde_json::from_str(&text)?;
    JSONSchema::compile(&schema)
        .map_err(|error| error.to_string().into())
}

pub fn schema_sha256(artifact_type: &str) -> Result<String, Box<dyn Error>> {
    let types = artifact_types();
    let entry = types
        .get(artifact_type)
        .ok_or_else(|| format!("unknown artifact_type: {artifact_type}"))?;
    let raw = std::fs::read(repo_root().join("spec").join(entry.schema_file))?;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(raw);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub fn validate(
    artifact_type: &str,
    raw: &Value,
) -> Result<Validated<Value>, SchemaValidationError> {
    let validator = validator(artifact_type).map_err(|error| SchemaValidationError {
        message: error.to_string(),
        path: String::new(),
    })?;
    if let Err(mut errors) = validator.validate(raw) {
        let (message, path) = errors
            .next()
            .map(|error| (error.to_string(), error.instance_path.to_string()))
            .unwrap_or_else(|| ("validation failed".into(), String::new()));
        return Err(SchemaValidationError { message, path });
    }

    if artifact_type == "BoundaryCrossingAssessment" {
        let assessment: BoundaryCrossingAssessment =
            serde_json::from_value(raw.clone()).map_err(|error| SchemaValidationError {
                message: error.to_string(),
                path: String::new(),
            })?;
        assessment
            .validate_semantics()
            .map_err(|message| SchemaValidationError {
                message,
                path: String::new(),
            })?;
    }

    Ok(Validated {
        artifact_type: artifact_type.to_string(),
        model: raw.clone(),
        payload: raw.clone(),
    })
}

pub fn check(artifact_type: &str, raw: &Value) -> ValidationResult {
    let validated = match validate(artifact_type, raw) {
        Ok(value) => value,
        Err(error) => {
            return ValidationResult {
                decision: "REJECT".into(),
                reason_code: REASON_SCHEMA_INVALID.into(),
                canonical: None,
                payload_digest: None,
                error_path: Some(error.path),
            }
        }
    };

    let (canonical, digest) = match typed_digest(artifact_type, &validated.model) {
        Ok(value) => value,
        Err(error) => {
            return ValidationResult {
                decision: "REJECT".into(),
                reason_code: REASON_SCHEMA_INVALID.into(),
                canonical: None,
                payload_digest: None,
                error_path: Some(error.to_string()),
            }
        }
    };

    if artifact_type == "GovernanceClearance" {
        if let Ok(model) = serde_json::from_value::<GovernanceClearance>(validated.model.clone()) {
            if let Some(reason) = clearance_intra_check(&model) {
                return ValidationResult {
                    decision: "REJECT".into(),
                    reason_code: reason,
                    canonical: None,
                    payload_digest: None,
                    error_path: None,
                };
            }
        }
    }

    ValidationResult {
        decision: "ACCEPT".into(),
        reason_code: REASON_ACCEPT.into(),
        canonical: Some(canonical),
        payload_digest: Some(digest),
        error_path: None,
    }
}

fn typed_digest(artifact_type: &str, raw: &Value) -> Result<(String, String), Box<dyn Error>> {
    match artifact_type {
        "GovernanceEvaluation" => {
            let model: GovernanceEvaluation = serde_json::from_value(raw.clone())?;
            Ok((canonical_string(&model)?, sha256_digest(&model)?))
        }
        "AdmissibilityDetermination" => {
            let model: AdmissibilityDetermination = serde_json::from_value(raw.clone())?;
            Ok((canonical_string(&model)?, sha256_digest(&model)?))
        }
        "GovernanceClearance" => {
            let model: GovernanceClearance = serde_json::from_value(raw.clone())?;
            Ok((canonical_string(&model)?, sha256_digest(&model)?))
        }
        "BoundaryCrossingAssessment" => {
            let model: BoundaryCrossingAssessment = serde_json::from_value(raw.clone())?;
            Ok((canonical_string(&model)?, sha256_digest(&model)?))
        }
        _ => Err(format!("unknown artifact_type: {artifact_type}").into()),
    }
}

fn clearance_intra_check(model: &GovernanceClearance) -> Option<String> {
    match model.decision {
        crate::Decision::Allow => {
            if model.admissibility_state != crate::AdmissibilityState::Admissible {
                return Some(REASON_CLEARANCE_ALLOW_STATE_MISMATCH.into());
            }
            if model.constraints.is_some() {
                return Some(REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS.into());
            }
        }
        crate::Decision::Modify => {
            if model.admissibility_state
                != crate::AdmissibilityState::ConditionallyAdmissible
            {
                return Some(REASON_CLEARANCE_MODIFY_STATE_MISMATCH.into());
            }
            if model
                .constraints
                .as_ref()
                .map(enforceable)
                .unwrap_or(false)
                == false
            {
                return Some(REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS.into());
            }
        }
        _ => {}
    }
    None
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
