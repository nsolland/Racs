//! RACS v0.2 runtime conformance — Stage 3C, Port A (schema validation).
//!
//! Turns the pure typed models from Stage 3B into governed types:
//!
//! * `Raw<T>`      — JSON parsed, NOT yet schema-conformant.
//! * `Validated<T>` — proven schema-conformant (Draft 2020-12) for its artifact type.
//! * `Verified<T>`  — schema-conformant AND all external cross-artifact bindings
//!                    resolved and checked (Stage 3C, Port B).
//!
//! The normative contract is the schema files under `spec/*.schema.json`. Nothing
//! may be promoted to `Validated` without passing the jsonschema validator, and
//! nothing may be promoted to `Verified` without passing the cross-artifact
//! verifier in [`crate::verification`].
//!
//! All three bindings (Python/Rust/TypeScript) MUST emit byte-identical:
//! * accept/reject decision
//! * normalized reason code
//! * canonical bytes (for accepted objects)
//! * payload digest (for accepted objects)

use crate::{
    canonical_string, sha256_digest, AdmissibilityDetermination, GovernanceClearance,
    GovernanceEvaluation,
};
use jsonschema::JSONSchema;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;

// --- normalized reason codes (language-agnostic) -----------------------------

pub const REASON_ACCEPT: &str = "ACCEPT";
pub const REASON_SCHEMA_INVALID: &str = "SCHEMA_INVALID";
pub const REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS: &str = "CLEARANCE_ALLOW_HAS_CONSTRAINTS";
pub const REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS: &str =
    "CLEARANCE_MODIFY_MISSING_CONSTRAINTS";
pub const REASON_CLEARANCE_ALLOW_STATE_MISMATCH: &str = "CLEARANCE_ALLOW_STATE_MISMATCH";
pub const REASON_CLEARANCE_MODIFY_STATE_MISMATCH: &str = "CLEARANCE_MODIFY_STATE_MISMATCH";
pub const REASON_EVALUATION_BINDING_DIGEST_MISMATCH: &str =
    "EVALUATION_BINDING_DIGEST_MISMATCH";
pub const REASON_EVALUATION_BINDING_REF_MISMATCH: &str = "EVALUATION_BINDING_REF_MISMATCH";
pub const REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH: &str =
    "CLEARANCE_DETERMINATION_DIGEST_MISMATCH";
pub const REASON_CLEARANCE_ACTION_MISMATCH: &str = "CLEARANCE_ACTION_MISMATCH";
pub const REASON_CLEARANCE_ENVELOPE_MISMATCH: &str = "CLEARANCE_ENVELOPE_MISMATCH";
pub const REASON_CLEARANCE_NEGATIVE_STATE: &str = "CLEARANCE_NEGATIVE_STATE";
pub const REASON_CLEARANCE_EXPIRED: &str = "CLEARANCE_EXPIRED";
pub const REASON_CLEARANCE_REVOKED: &str = "CLEARANCE_REVOKED";

// --- artifact type registry --------------------------------------------------

pub struct ArtifactType {
    pub schema_file: &'static str,
}

pub fn artifact_types() -> HashMap<&'static str, ArtifactType> {
    let mut m = HashMap::new();
    m.insert(
        "GovernanceEvaluation",
        ArtifactType {
            schema_file: "governance-evaluation-v0.2.schema.json",
        },
    );
    m.insert(
        "AdmissibilityDetermination",
        ArtifactType {
            schema_file: "admissibility-determination-v0.2.schema.json",
        },
    );
    m.insert(
        "GovernanceClearance",
        ArtifactType {
            schema_file: "governance-clearance.schema.json",
        },
    );
    m
}

// --- wrapper types -----------------------------------------------------------

pub struct Raw<T> {
    pub data: Value,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Raw<T> {
    pub fn new(data: Value) -> Self {
        Raw {
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
        let mut out = serde_json::Map::new();
        out.insert("decision".into(), Value::String(self.decision.clone()));
        out.insert("reason_code".into(), Value::String(self.reason_code.clone()));
        if let Some(c) = &self.canonical {
            out.insert("canonical".into(), Value::String(c.clone()));
        }
        if let Some(d) = &self.payload_digest {
            out.insert("payload_digest".into(), Value::String(d.clone()));
        }
        if let Some(p) = &self.error_path {
            out.insert("error_path".into(), Value::String(p.clone()));
        }
        serde_json::to_string(&Value::Object(out)).map_err(|e| e.into())
    }
}

#[derive(Debug)]
pub struct SchemaValidationError {
    pub message: String,
    pub path: String,
}

impl std::fmt::Display for SchemaValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let loc = if self.path.is_empty() { "<root>" } else { &self.path };
        write!(f, "{} (at {})", self.message, loc)
    }
}

impl Error for SchemaValidationError {}

// --- schema loading ----------------------------------------------------------

fn repo_root() -> PathBuf {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for cand in std::iter::once(start.clone()).chain(start.ancestors().map(|p| p.to_path_buf())) {
        if cand.join("spec").join("governance-clearance.schema.json").exists() {
            return cand;
        }
    }
    panic!("could not locate RACS spec/ directory");
}

fn get_validator(artifact_type: &str) -> Result<JSONSchema, Box<dyn Error>> {
    let types = artifact_types();
    let entry = types
        .get(artifact_type)
        .ok_or_else(|| format!("unknown artifact_type: {artifact_type}"))?;
    let path = repo_root().join("spec").join(entry.schema_file);
    let text = std::fs::read_to_string(&path)?;
    let schema: Value = serde_json::from_str(&text)?;
    let validator = JSONSchema::compile(&schema).map_err(|e| e.to_string())?;
    Ok(validator)
}

pub fn schema_sha256(artifact_type: &str) -> Result<String, Box<dyn Error>> {
    let types = artifact_types();
    let entry = types
        .get(artifact_type)
        .ok_or_else(|| format!("unknown artifact_type: {artifact_type}"))?;
    let path = repo_root().join("spec").join(entry.schema_file);
    let raw = std::fs::read(&path)?;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&raw);
    Ok(format!("sha256:{:x}", h.finalize()))
}

// --- core validate entrypoint -----------------------------------------------

/// Validate raw JSON against the exact v0.2 schema and deserialize to the typed
/// 3B model. Returns [`SchemaValidationError`] on any violation.
pub fn validate(
    artifact_type: &str,
    raw: &Value,
) -> Result<Validated<Value>, SchemaValidationError> {
    let validator = get_validator(artifact_type).map_err(|e| SchemaValidationError {
        message: e.to_string(),
        path: String::new(),
    })?;
    if let Err(mut errors) = validator.validate(raw) {
        let (msg, path) = match errors.next() {
            Some(e) => (e.to_string(), e.instance_path.to_string()),
            None => ("validation failed".to_string(), String::new()),
        };
        return Err(SchemaValidationError {
            message: msg,
            path,
        });
    }
    Ok(Validated {
        artifact_type: artifact_type.to_string(),
        model: raw.clone(),
        payload: raw.clone(),
    })
}

/// Non-raising variant: returns an ACCEPT/REJECT [`ValidationResult`] with a
/// normalized reason code. For ACCEPT, canonical bytes + digest are attached.
pub fn check(artifact_type: &str, raw: &Value) -> ValidationResult {
    let validated = match validate(artifact_type, raw) {
        Ok(v) => v,
        Err(e) => {
            return ValidationResult {
                decision: "REJECT".into(),
                reason_code: REASON_SCHEMA_INVALID.into(),
                canonical: None,
                payload_digest: None,
                error_path: Some(e.path),
            };
        }
    };

    let (canonical, digest) = match typed_digest(artifact_type, &validated.model) {
        Ok(pair) => pair,
        Err(e) => {
            return ValidationResult {
                decision: "REJECT".into(),
                reason_code: REASON_SCHEMA_INVALID.into(),
                canonical: None,
                payload_digest: None,
                error_path: Some(e.to_string()),
            };
        }
    };

    if artifact_type == "GovernanceClearance" {
        if let Ok(model) = serde_json::from_value::<GovernanceClearance>(validated.model.clone()) {
            if let Some(sem) = clearance_intra_check(&model) {
                return ValidationResult {
                    decision: "REJECT".into(),
                    reason_code: sem,
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

/// Deserialize the typed model and compute canonical + digest via the 3B kernel.
fn typed_digest(artifact_type: &str, raw: &Value) -> Result<(String, String), Box<dyn Error>> {
    match artifact_type {
        "GovernanceEvaluation" => {
            let m: GovernanceEvaluation = serde_json::from_value(raw.clone())?;
            Ok((canonical_string(&m)?, sha256_digest(&m)?))
        }
        "AdmissibilityDetermination" => {
            let m: AdmissibilityDetermination = serde_json::from_value(raw.clone())?;
            Ok((canonical_string(&m)?, sha256_digest(&m)?))
        }
        "GovernanceClearance" => {
            let m: GovernanceClearance = serde_json::from_value(raw.clone())?;
            Ok((canonical_string(&m)?, sha256_digest(&m)?))
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
            if model.admissibility_state != crate::AdmissibilityState::ConditionallyAdmissible {
                return Some(REASON_CLEARANCE_MODIFY_STATE_MISMATCH.into());
            }
            match &model.constraints {
                None => return Some(REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS.into()),
                Some(c) => {
                    if !enforceable(c) {
                        return Some(REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS.into());
                    }
                }
            }
        }
        _ => {}
    }
    None
}

fn enforceable(constraints: &Value) -> bool {
    match constraints {
        Value::Object(map) => {
            if let Some(Value::Array(rules)) = map.get("rules") {
                if !rules.is_empty() {
                    return true;
                }
            }
            let ref_ok =
                matches!(map.get("constraint_set_ref"), Some(Value::String(s)) if !s.is_empty());
            let digest_ok = matches!(
                map.get("constraint_set_digest"),
                Some(Value::String(s)) if s.starts_with("sha256:")
            );
            ref_ok && digest_ok
        }
        _ => false,
    }
}
