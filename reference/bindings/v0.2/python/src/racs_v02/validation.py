"""RACS v0.2 schema validation and typed conformance."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Generic, Optional, TypeVar

from jsonschema import Draft202012Validator
from pydantic import ValidationError as PydanticValidationError

from .boundary_crossing import BoundaryCrossingAssessment
from .models import (
    AdmissibilityDetermination,
    GovernanceClearance,
    GovernanceEvaluation,
)

ARTIFACT_TYPES = {
    "GovernanceEvaluation": (
        "governance-evaluation-v0.2.schema.json",
        GovernanceEvaluation,
    ),
    "AdmissibilityDetermination": (
        "admissibility-determination-v0.2.schema.json",
        AdmissibilityDetermination,
    ),
    "GovernanceClearance": (
        "governance-clearance.schema.json",
        GovernanceClearance,
    ),
    "BoundaryCrossingAssessment": (
        "boundary-crossing-assessment-v0.2.schema.json",
        BoundaryCrossingAssessment,
    ),
}

REASON_ACCEPT = "ACCEPT"
REASON_SCHEMA_INVALID = "SCHEMA_INVALID"
REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS = "CLEARANCE_ALLOW_HAS_CONSTRAINTS"
REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS = "CLEARANCE_MODIFY_MISSING_CONSTRAINTS"
REASON_CLEARANCE_ALLOW_STATE_MISMATCH = "CLEARANCE_ALLOW_STATE_MISMATCH"
REASON_CLEARANCE_MODIFY_STATE_MISMATCH = "CLEARANCE_MODIFY_STATE_MISMATCH"
REASON_EVALUATION_BINDING_DIGEST_MISMATCH = "EVALUATION_BINDING_DIGEST_MISMATCH"
REASON_EVALUATION_BINDING_REF_MISMATCH = "EVALUATION_BINDING_REF_MISMATCH"
REASON_CLEARANCE_DETERMINATION_DIGEST_MISMATCH = (
    "CLEARANCE_DETERMINATION_DIGEST_MISMATCH"
)
REASON_CLEARANCE_ACTION_MISMATCH = "CLEARANCE_ACTION_MISMATCH"
REASON_CLEARANCE_ENVELOPE_MISMATCH = "CLEARANCE_ENVELOPE_MISMATCH"
REASON_CLEARANCE_NEGATIVE_STATE = "CLEARANCE_NEGATIVE_STATE"
REASON_CLEARANCE_EXPIRED = "CLEARANCE_EXPIRED"
REASON_CLEARANCE_REVOKED = "CLEARANCE_REVOKED"

EXPECTED_VALUES = {"ACCEPT", "REJECT"}

T = TypeVar("T")


@dataclass
class Raw(Generic[T]):
    data: Dict[str, Any]

    def into_validated(self, artifact_type: str) -> "Validated[T]":
        return validate(artifact_type, self.data)


@dataclass
class Validated(Generic[T]):
    artifact_type: str
    model: T
    payload: Dict[str, Any]


@dataclass
class Verified(Generic[T]):
    artifact_type: str
    model: T
    payload: Dict[str, Any]


@dataclass
class ValidationResult:
    decision: str
    reason_code: str
    canonical_bytes: Optional[bytes] = None
    payload_digest: Optional[str] = None
    error_path: Optional[str] = None

    def to_json(self) -> str:
        out: Dict[str, Any] = {
            "decision": self.decision,
            "reason_code": self.reason_code,
        }
        if self.canonical_bytes is not None:
            out["canonical"] = self.canonical_bytes.decode("utf-8")
        if self.payload_digest is not None:
            out["payload_digest"] = self.payload_digest
        if self.error_path is not None:
            out["error_path"] = self.error_path
        return json.dumps(out, sort_keys=True, separators=(",", ":"))


_SCHEMA_CACHE: Dict[str, Draft202012Validator] = {}
_ROOT_HINT = Path(__file__).resolve().parents[5]


def _repo_root() -> Path:
    for candidate in [_ROOT_HINT, *_ROOT_HINT.parents]:
        if (candidate / "spec" / "governance-clearance.schema.json").exists():
            return candidate
    raise FileNotFoundError("could not locate RACS spec/ directory")


def _validator(artifact_type: str) -> Draft202012Validator:
    if artifact_type not in _SCHEMA_CACHE:
        if artifact_type not in ARTIFACT_TYPES:
            raise KeyError(f"unknown artifact_type: {artifact_type}")
        filename, _ = ARTIFACT_TYPES[artifact_type]
        schema = json.loads(
            (_repo_root() / "spec" / filename).read_text(encoding="utf-8")
        )
        _SCHEMA_CACHE[artifact_type] = Draft202012Validator(schema)
    return _SCHEMA_CACHE[artifact_type]


def schema_sha256(artifact_type: str) -> str:
    import hashlib

    filename, _ = ARTIFACT_TYPES[artifact_type]
    raw = (_repo_root() / "spec" / filename).read_bytes()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class SchemaValidationError(ValueError):
    def __init__(self, message: str, path: str = ""):
        self.message = message
        self.path = path
        super().__init__(f"{message} (at {path or '<root>'})")


def validate(artifact_type: str, raw: Dict[str, Any]) -> Validated:
    validator = _validator(artifact_type)
    errors = sorted(
        validator.iter_errors(raw),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        path = "/".join(str(item) for item in first.absolute_path)
        raise SchemaValidationError(first.message, path)

    model_class = ARTIFACT_TYPES[artifact_type][1]
    try:
        model = model_class.model_validate(raw)
    except PydanticValidationError as exc:
        first = exc.errors()[0]
        path = "/".join(str(item) for item in first.get("loc", ()))
        raise SchemaValidationError(
            first.get("msg", "semantic validation failed"),
            path,
        ) from exc
    return Validated(artifact_type=artifact_type, model=model, payload=raw)


def check(artifact_type: str, raw: Dict[str, Any]) -> ValidationResult:
    try:
        validated = validate(artifact_type, raw)
    except SchemaValidationError as exc:
        return ValidationResult(
            decision="REJECT",
            reason_code=REASON_SCHEMA_INVALID,
            error_path=exc.path,
        )

    model = validated.model
    canonical = model.model_canonical()
    digest = model.model_digest()

    if artifact_type == "GovernanceClearance":
        semantic_reason = _clearance_intra_check(model)
        if semantic_reason is not None:
            return ValidationResult(decision="REJECT", reason_code=semantic_reason)

    return ValidationResult(
        decision="ACCEPT",
        reason_code=REASON_ACCEPT,
        canonical_bytes=canonical,
        payload_digest=digest,
    )


def _clearance_intra_check(model: GovernanceClearance) -> Optional[str]:
    if model.decision.value == "ALLOW":
        if model.admissibility_state.value != "ADMISSIBLE":
            return REASON_CLEARANCE_ALLOW_STATE_MISMATCH
        if model.constraints is not None:
            return REASON_CLEARANCE_ALLOW_HAS_CONSTRAINTS
    elif model.decision.value == "MODIFY":
        if model.admissibility_state.value != "CONDITIONALLY_ADMISSIBLE":
            return REASON_CLEARANCE_MODIFY_STATE_MISMATCH
        if model.constraints is None or not _enforceable(model.constraints):
            return REASON_CLEARANCE_MODIFY_MISSING_CONSTRAINTS
    return None


def _enforceable(constraints: Dict[str, Any]) -> bool:
    if not isinstance(constraints, dict):
        return False
    rules = constraints.get("rules")
    if isinstance(rules, list) and len(rules) >= 1:
        return True
    reference = constraints.get("constraint_set_ref")
    digest = constraints.get("constraint_set_digest")
    return (
        isinstance(reference, str)
        and bool(reference)
        and isinstance(digest, str)
        and digest.startswith("sha256:")
    )
