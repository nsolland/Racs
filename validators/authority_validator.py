#!/usr/bin/env python3
"""
RACS Authority Grant Validator

Validates an authority grant against the canonical RACS v0.2 contract:
``spec/authority-grant-v0.2.schema.json``. Schema-driven (never hand-maintained
field lists), so it cannot drift from the normative contract — the same pattern
as ``execution_receipt_validator``.

Usage:
    python validators/authority_validator.py path/to/grant.yaml
    python validators/authority_validator.py path/to/grant.json

Exit codes:
    0   Valid authority grant
    1   Invalid authority grant (validation error)
    2   File not found or unreadable
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import jsonschema

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

# Canonical source of truth — the normative v0.2 authority-grant contract.
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "spec" / "authority-grant-v0.2.schema.json"

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
    if not os.path.isfile(path):
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(2)

    with open(path, "r") as fh:
        content = fh.read()

    try:
        loaded = json.loads(content)
    except json.JSONDecodeError:
        if yaml is not None:
            try:
                loaded = yaml.safe_load(content)
            except yaml.YAMLError as exc:
                print(f"ERROR: invalid YAML: {exc}", file=sys.stderr)
                sys.exit(1)
        else:
            print("ERROR: PyYAML not installed", file=sys.stderr)
            sys.exit(1)

    if not isinstance(loaded, dict):
        print("ERROR: authority grant must be a mapping", file=sys.stderr)
        sys.exit(1)
    return loaded


def validate_authority_context(data: Any) -> list[str]:
    """Validate an authority grant against the canonical v0.2 schema.

    Returns a list of error messages (empty = valid). A non-dict or empty
    object is rejected: authority must always be explicit.

    NOTE: structural validation only. Signature/cryptographic verification is
    the responsibility of the downstream verification layer and is NOT performed
    here.
    """
    if data is None:
        return ["authority_grant: is required"]
    if not isinstance(data, dict):
        return [
            f"authority_grant: must be an object, got {type(data).__name__}"
        ]
    if len(data) == 0:
        return [
            "authority_grant: must not be empty; explicit authority is required"
        ]
    return [
        ".".join(str(p) for p in error.path)
        or error.validator
        or "root" + f": {error.message}"
        for error in sorted(
            _validator().iter_errors(data),
            key=lambda e: (str(e.path), str(e.schema_path)),
        )
    ]


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python validators/authority_validator.py <path>", file=sys.stderr)
        sys.exit(1)

    data = _load_document(sys.argv[1])
    errors = validate_authority_context(data)

    if errors:
        print("AUTHORITY VALIDATION FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    print("VALID: Authority grant conforms to the RACS v0.2 specification.")
    sys.exit(0)


if __name__ == "__main__":
    main()
