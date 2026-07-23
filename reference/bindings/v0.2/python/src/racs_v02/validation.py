"""RACS v0.2 runtime conformance — Stage 3C, Port A (schema validation).

This module turns the *pure* typed models from Stage 3B into *governed* types:

    Raw[T]        — JSON parsed, NOT yet schema-conformant.
    Validated[T]  — proven schema-conformant (Draft 2020-12) for its artifact type.
    Verified[T]   — schema-conformant AND all external cross-artifact bindings
                    resolved and checked (Stage 3C, Port B).

The normative contract is the schema files under ``spec/*.schema.json``. Nothing
may be promoted to ``Validated`` without passing ``Draft202012Validator``, and
nothing may be promoted to ``Verified`` without passing the cross-artifact
verifier in :mod:`racs_v02.verification`.

All three bindings (Python/Rust/TypeScript) MUST emit byte-identical:

    * accept/reject decision
    * normalized reason code
    * canonical bytes (for accepted objects)
    * payload digest (for accepted objects)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generic, Optional, TypeVar

from jsonschema import Draft202012Validator

from .models import (
    AdmissibilityDetermination,
    GovernanceClearance,
    GovernanceEvaluation,
)

# --- artifact type registry --------------------------------------------------

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
}

# --- normalized reason codes (language-agnostic) -----------------------------

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


# --- wrapper types ----------------------------------------------------------

T = TypeVar("T")


@dataclass
class Raw(Generic[T]):
    """Ingested JSON. Not yet proven schema-conformant."""

    data: Dict[str, Any]

    def into_validated(self, artifact_type: str) -> "Validated[T]":
        return validate(artifact_type, self.data)


@dataclass
class Validated(Generic[T]):
    """Schema-conformant (Draft 2020-12) typed model."""

    artifact_type: str
    model: T
    payload: Dict[str, Any]


@dataclass
class Verified(Generic[T]):
    """Schema-conformant AND cross-artifact bindings verified."""

    artifact_type: str
    model: T
    payload: Dict[str, Any]


@dataclass
class ValidationResult:
    decision: str  # "ACCEPT" | "REJECT"
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


# --- schema loading ---------------------------------------------------------

_SCHEMA_CACHE: Dict[str, Draft202012Validator] = {}
_ROOT_HINT = Path(__file__).resolve().parents[5]  # reference/bindings/v0.2/python


def _repo_root() -> Path:
    # candidates: from this file up to the dir that contains spec/
    for cand in [_ROOT_HINT, *_ROOT_HINT.parents]:
        if (cand / "spec" / "governance-clearance.schema.json").exists():
            return cand
    raise FileNotFoundError("could not locate RACS spec/ directory")


def _validator(artifact_type: str) -> Draft202012Validator:
    if artifact_type not in _SCHEMA_CACHE:
        if artifact_type not in ARTIFACT_TYPES:
            raise KeyError(f"unknown artifact_type: {artifact_type}")
        fname, _ = ARTIFACT_TYPES[artifact_type]
        path = _repo_root() / "spec" / fname
        schema = json.loads(path.read_text(encoding="utf-8"))
        _SCHEMA_CACHE[artifact_type] = Draft202012Validator(schema)
    return _SCHEMA_CACHE[artifact_type]


def schema_sha256(artifact_type: str) -> str:
    """SHA-256 over the raw bytes of the normative schema file (manifest pin)."""
    import hashlib

    fname, _ = ARTIFACT_TYPES[artifact_type]
    path = _repo_root() / "spec" / fname
    raw = path.read_text(encoding="utf-8").encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# --- core validate entrypoint -----------------------------------------------

def validate(artifact_type: str, raw: Dict[str, Any]) -> Validated:
    """Validate raw JSON against the exact v0.2 schema and deserialize to the
    typed 3B model. Raises :class:`SchemaValidationError` on any violation."""
    validator = _validator(artifact_type)
    errors = sorted(validator.iter_errors(raw), key=lambda e: list(e.absolute_path))
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.absolute_path)
        raise SchemaValidationError(first.message, path)
    model_cls = ARTIFACT_TYPES[artifact_type][1]
    model = model_cls.model_validate(raw)
    return Validated(artifact_type=artifact_type, model=model, payload=raw)


class SchemaValidationError(ValueError):
    def __init__(self, message: str, path: str = ""):
        self.message = message
        self.path = path
        super().__init__(f"{message} (at {path or '<root>'})")


def check(artifact_type: str, raw: Dict[str, Any]) -> ValidationResult:
    """Non-raising variant: returns an ACCEPT/REJECT :class:`ValidationResult`
    with a normalized reason code. For ACCEPT, canonical bytes + digest are
    attached (using the 3B model canonicalization)."""
    try:
        validated = validate(artifact_type, raw)
    except SchemaValidationError as exc:
        return ValidationResult(
            decision="REJECT",
            reason_code=REASON_SCHEMA_INVALID,
            error_path=exc.path,
        )
    # Re-derive canonical + digest from the typed model (3B model_canonical()).
    model = validated.model
    canonical = model.model_canonical()
    digest = model.model_digest()

    # For clearances, schema-ACCEPT is necessary but not sufficient: the
    # intra-payload ALLOW/MODIFY <-> state/constraints rules must also hold.
    # (Cross-artifact digest bindings are verified separately via
    # verify_clearance_binding once the referenced artifacts are resolved.)
    if artifact_type == "GovernanceClearance":
        sem = _clearance_intra_check(model)
        if sem is not None:
            return ValidationResult(decision="REJECT", reason_code=sem)

    return ValidationResult(
        decision="ACCEPT",
        reason_code=REASON_ACCEPT,
        canonical_bytes=canonical,
        payload_digest=digest,
    )


def _clearance_intra_check(model: "GovernanceClearance") -> "Optional[str]":
    """Intra-payload semantic rules for a schema-valid clearance.
    Returns a normalized reason code if the clearance must be REJECTED, else None."""
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
    ref = constraints.get("constraint_set_ref")
    digest = constraints.get("constraint_set_digest")
    if isinstance(ref, str) and ref and isinstance(digest, str) and digest.startswith("sha256:"):
        return True
    return False
