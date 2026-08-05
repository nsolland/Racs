#!/usr/bin/env python3
"""
RACS Action Envelope Validator

Validates an action envelope (YAML or JSON) against the RACS specification.
This is a specification-first validator: it checks required fields,
types, and structural constraints per the JSON schema + SPECIFICATION.md.

Usage:
    python validators/envelope_validator.py path/to/envelope.yaml
    python validators/envelope_validator.py path/to/envelope.json

Exit codes:
    0   Valid envelope
    1   Invalid envelope (validation error)
    2   File not found or unreadable
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

# Allow `python validators/envelope_validator.py` to import sibling validators
# via the package namespace (`validators.authority_validator`, ...).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


# ---- Schema constants (from schemas/action-envelope.schema.json + SPEC) ----

REQUIRED_FIELDS = [
    "racs_version",
    "action_id",
    "action_type",
    "actor",
    "target",
    "requested_effect",
    "authority_context",
    "policy_context",
    "evidence_package",
    "environment_state",
    "created_at",
]

OPTIONAL_FIELDS = ["risk_context", "expires_at"]

ALLOWED_TOP_LEVEL = set(REQUIRED_FIELDS + OPTIONAL_FIELDS)

# Envelope versions known to this validator. Unknown versions fail closed in
# governance-complete mode.
VALID_RACS_VERSIONS = {"0.1", "0.2"}

# ISO 8601 datetime regex (basic validation)
DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)

# All-zero SHA-256 placeholder digest (e.g. "sha256:0000...0").
_ZERO_SHA256_RE = re.compile(r"^sha256:0{64}$")


# ---- Validation helpers ----


def _load_document(path: str) -> dict[str, Any]:
    """Load a YAML or JSON document from *path*."""
    if not os.path.isfile(path):
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(2)

    with open(path, "r") as fh:
        content = fh.read()

    # Try JSON first, then YAML
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    if yaml is not None:
        try:
            loaded = yaml.safe_load(content)
            if not isinstance(loaded, dict):
                print(
                    f"ERROR: envelope must be a mapping (got {type(loaded).__name__})",
                    file=sys.stderr,
                )
                sys.exit(1)
            return loaded
        except yaml.YAMLError as exc:
            print(f"ERROR: invalid YAML: {exc}", file=sys.stderr)
            sys.exit(1)

    print("ERROR: PyYAML not installed; cannot parse YAML files", file=sys.stderr)
    sys.exit(1)


def _validate_string(value: Any, field_name: str) -> list[str]:
    """Validate that *value* is a non-empty string."""
    errors: list[str] = []
    if not isinstance(value, str):
        errors.append(f"{field_name}: must be a string, got {type(value).__name__}")
    elif len(value) == 0:
        errors.append(f"{field_name}: must not be empty")
    return errors


def _validate_datetime(value: Any, field_name: str) -> list[str]:
    """Validate that *value* is an ISO 8601 datetime string."""
    errors: list[str] = []
    if not isinstance(value, str):
        errors.append(
            f"{field_name}: must be a datetime string, got {type(value).__name__}"
        )
    elif not DATETIME_RE.match(value):
        errors.append(f"{field_name}: not a valid ISO 8601 datetime: {value!r}")
    return errors


def _validate_object(value: Any, field_name: str) -> list[str]:
    """Validate that *value* is a dict."""
    errors: list[str] = []
    if value is None:
        errors.append(f"{field_name}: is required")
    elif not isinstance(value, dict):
        errors.append(
            f"{field_name}: must be an object, got {type(value).__name__}"
        )
    return errors


def _validate_actor(value: Any) -> list[str]:
    """Validate actor object (must have id and role)."""
    errors: list[str] = []
    if not isinstance(value, dict):
        errors.append(f"actor: must be an object, got {type(value).__name__}")
        return errors
    for req in ("id", "role"):
        if req not in value:
            errors.append(f"actor.{req}: is required")
        elif not isinstance(value[req], str) or len(value[req]) == 0:
            errors.append(f"actor.{req}: must be a non-empty string")
    return errors


def _validate_target(value: Any) -> list[str]:
    """Validate target object (must have id and type)."""
    errors: list[str] = []
    if not isinstance(value, dict):
        errors.append(f"target: must be an object, got {type(value).__name__}")
        return errors
    for req in ("id", "type"):
        if req not in value:
            errors.append(f"target.{req}: is required")
        elif not isinstance(value[req], str) or len(value[req]) == 0:
            errors.append(f"target.{req}: must be a non-empty string")
    return errors


def _validate_requested_effect(value: Any) -> list[str]:
    """Validate requested_effect (must have description)."""
    errors: list[str] = []
    if not isinstance(value, dict):
        errors.append(
            f"requested_effect: must be an object, got {type(value).__name__}"
        )
        return errors
    if "description" not in value:
        errors.append("requested_effect.description: is required")
    elif not isinstance(value["description"], str) or len(value["description"]) == 0:
        errors.append("requested_effect.description: must be a non-empty string")
    return errors


def _validate_risk_context(value: Any) -> list[str]:
    """Validate risk_context if present."""
    errors: list[str] = []
    if value is None:
        return errors
    if not isinstance(value, dict):
        errors.append(
            f"risk_context: must be an object, got {type(value).__name__}"
        )
        return errors
    if "level" in value and value["level"] not in ("low", "medium", "high", "critical"):
        errors.append(
            f"risk_context.level: must be one of low, medium, high, critical"
        )
    return errors


def _validate_field(value: Any, field_name: str) -> list[str]:
    """Route validation by field name."""
    if field_name == "actor":
        return _validate_actor(value)
    elif field_name == "target":
        return _validate_target(value)
    elif field_name == "requested_effect":
        return _validate_requested_effect(value)
    elif field_name == "risk_context":
        return _validate_risk_context(value)
    elif field_name == "created_at":
        return _validate_datetime(value, field_name)
    elif field_name == "expires_at":
        if value is not None:
            return _validate_datetime(value, field_name)
        return []
    elif field_name == "racs_version":
        return _validate_string(value, field_name)
    elif field_name in ("action_id", "action_type"):
        return _validate_string(value, field_name)
    elif field_name in (
        "authority_context",
        "policy_context",
        "evidence_package",
        "environment_state",
    ):
        return _validate_object(value, field_name)
    return []


def _validate_governed_context(value: Any, field_name: str) -> list[str]:
    """Validate a governance context (authority/policy/evidence).

    Structural validation only: the context must be a non-empty object AND must
    pass its dedicated validator. This rejects empty ``{}`` contexts, which the
    envelope-level ``_validate_object`` alone would accept.

    Signature/cryptographic verification is NOT performed here — a passing
    structural check must never be presented as proof of signature validity.
    """
    errors: list[str] = []

    if value is None:
        errors.append(f"{field_name}: is required")
        return errors
    if not isinstance(value, dict):
        errors.append(f"{field_name}: must be an object, got {type(value).__name__}")
        return errors
    if len(value) == 0:
        errors.append(
            f"{field_name}: must not be empty; an explicit {field_name} is required"
        )
        return errors

    if field_name == "authority_context":
        from validators.authority_validator import validate_authority_context

        errors.extend(validate_authority_context(value))
    elif field_name == "policy_context":
        from validators.policy_validator import validate_policy_context

        errors.extend(validate_policy_context(value))
    elif field_name == "evidence_package":
        from validators.evidence_validator import validate_evidence_package

        errors.extend(validate_evidence_package(value))

    return errors


# ---- Public API ----


def validate_envelope(
    data: dict[str, Any],
    *,
    strict: bool = True,
    governance_complete: bool = True,
) -> list[str]:
    """Validate an action envelope dict.

    Returns a list of error messages (empty = valid).

    Two validation levels are exposed so callers can distinguish structural
    parsing from governance completeness:

    * ``governance_complete=True`` (default): the governance contexts
      (authority_context, policy_context, evidence_package) are recursively
      validated and MUST be present, non-empty, and well-formed. An envelope
      that passes at this level is structurally AND governance-ready, but this
      does NOT imply signature/cryptographic verification was performed.
    * ``governance_complete=False``: only the envelope shell is validated
      (required fields present and well-typed). Governance contexts are checked
      for type only, not completeness. Use this for pure structural parsing;
      never treat its success as admissibility readiness.
    """
    errors: list[str] = []

    # 1. Check required fields
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None:
            errors.append(f"{field}: is required and must not be null")
            continue
        if (
            governance_complete
            and field in ("authority_context", "policy_context", "evidence_package")
        ):
            errors.extend(_validate_governed_context(data[field], field))
        else:
            errors.extend(_validate_field(data[field], field))

    # 1a. Governance-complete version vocabulary (deterministic).
    if governance_complete and data.get("racs_version"):
        if data["racs_version"] not in VALID_RACS_VERSIONS:
            errors.append(
                f"racs_version: must be one of "
                f"{', '.join(sorted(VALID_RACS_VERSIONS))}, "
                f"got {data['racs_version']!r}"
            )

    # 1b. Governance-complete digest re-verify: placeholder (all-zero) digest
    #     fields are never acceptable — a real digest must bind content.
    if governance_complete:
        for key, value in data.items():
            if (
                key.endswith("_digest")
                and isinstance(value, str)
                and _ZERO_SHA256_RE.match(value)
            ):
                errors.append(
                    f"{key}: placeholder (all-zero) digest is not acceptable "
                    "in governance-complete mode"
                )

    # 1b. Validate optional fields when present
    for field in OPTIONAL_FIELDS:
        if field in data and data[field] is not None:
            errors.extend(_validate_field(data[field], field))

    # 2. Check for unknown top-level fields
    if strict:
        for key in data:
            if key not in ALLOWED_TOP_LEVEL:
                errors.append(f"extra field not allowed: {key}")

    return errors


def check_admissibility_expiry(data: dict[str, Any], now: datetime) -> list[str]:
    """Expiry check for the admissibility layer (caller passes wall time).

    ``validate_envelope`` stays deterministic and does not consult a wall clock;
    admissibility code passes ``now`` here. Returns errors; an expired envelope
    yields an ``expires_at`` error. Structural ``expires_at`` validation is the
    responsibility of ``validate_envelope``.
    """
    expires_at = data.get("expires_at")
    if not isinstance(expires_at, str):
        return []
    try:
        parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return []
    if parsed <= now:
        return [f"expires_at: envelope expired at {expires_at}"]
    return []


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python validators/envelope_validator.py <path>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    data = _load_document(path)
    errors = validate_envelope(data)

    if errors:
        print("VALIDATION FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    print("VALID: Action envelope conforms to the RACS specification.")
    sys.exit(0)


if __name__ == "__main__":
    main()
