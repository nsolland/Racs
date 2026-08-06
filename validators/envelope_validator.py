#!/usr/bin/env python3
"""
RACS Action Envelope Validator

Validates an action envelope (YAML or JSON) against the canonical RACS v0.2
contract: ``spec/action-envelope-v0.2.schema.json``. This is a
specification-first, schema-driven validator — it must never drift from the
normative schema, so validation is delegated to ``jsonschema`` over the spec
file itself (the same pattern as ``execution_receipt_validator``).

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
from datetime import datetime
from pathlib import Path
from typing import Any

import jsonschema

# Allow `python validators/envelope_validator.py` to import sibling validators
# via the package namespace (`validators.authority_validator`, ...).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

# Canonical source of truth — the normative v0.2 contract. Loading the schema
# at call time means any change to spec/ is picked up without touching this
# file (no duplicated field lists to drift).
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "spec" / "action-envelope-v0.2.schema.json"

# All-zero SHA-256 placeholder digest (e.g. "sha256:0000...0").
_ZERO_SHA256_RE = re.compile(r"^sha256:0{64}$")

_VALIDATOR: jsonschema.Draft202012Validator | None = None


def _validator() -> jsonschema.Draft202012Validator:
    global _VALIDATOR
    if _VALIDATOR is None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        _VALIDATOR = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )
    return _VALIDATOR


def _load_document(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")) and yaml is not None:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("document root must be a JSON/YAML object")
    return data


def _is_iso8601(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _schema_errors(data: dict[str, Any]) -> list[str]:
    return [
        (
            ".".join(str(p) for p in error.path)
            or error.validator
            or "root"
        ) + f": {error.message}"
        for error in sorted(
            _validator().iter_errors(data),
            key=lambda e: (str(e.path), str(e.schema_path)),
        )
    ]


def validate_envelope(
    data: dict[str, Any],
    *,
    strict: bool = True,
    governance_complete: bool = True,
) -> list[str]:
    """Validate an action envelope dict against the canonical v0.2 schema.

    Returns a list of error messages (empty = valid).

    * ``strict=True`` (default): the schema has ``additionalProperties: false``,
      so unknown top-level fields are rejected by ``jsonschema`` itself.
    * ``governance_complete=True`` (default): placeholder (all-zero) digests
      are rejected — a real digest must bind content. Structural validity is
      always schema-driven.
    """
    errors: list[str] = []

    # 1. Schema-driven structural validation (the authoritative check).
    errors.extend(_schema_errors(data))

    # 2. ISO 8601 timestamps must be real. jsonschema's ``date-time`` format
    #    check is not reliably enforced across versions, so the envelope's own
    #    timestamps are verified explicitly — the same way the zero-digest rule
    #    is enforced below.
    for field_name in ("created_at", "expires_at"):
        value = data.get(field_name)
        if isinstance(value, str) and not _is_iso8601(value):
            errors.append(f"{field_name}: must be a valid ISO 8601 timestamp")

    # 3. Governance-complete digest re-verify: placeholder (all-zero) digest
    #    fields are never acceptable — a real digest must bind content.
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

    print("VALID: Action envelope conforms to the RACS v0.2 specification.")
    sys.exit(0)


if __name__ == "__main__":
    main()
