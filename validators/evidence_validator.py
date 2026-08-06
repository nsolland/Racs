#!/usr/bin/env python3
"""
RACS Evidence Validator

Schema-driven against the canonical contract in
``spec/evidence-package.yaml`` — never hand-maintained field lists, so the
validator cannot drift from the normative evidence contract (same pattern as
``execution_receipt_validator``).

Checks integrity metadata structure but does NOT verify signatures.

Usage:
    python validators/evidence_validator.py path/to/evidence-package.yaml

Exit codes:
    0   Valid evidence package
    1   Invalid evidence package
    2   File error
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import jsonschema

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

# Canonical contract — the evidence_package subtree of the normative YAML.
CONTRACT_PATH = Path(__file__).resolve().parent.parent / "spec" / "evidence-package.yaml"

_VALIDATOR: jsonschema.Draft202012Validator | None = None


def _contract_schema() -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load the evidence contract")
    with open(CONTRACT_PATH, encoding="utf-8") as fh:
        contract = yaml.safe_load(fh)
    return contract["evidence_package"]


def _validator() -> jsonschema.Draft202012Validator:
    global _VALIDATOR
    if _VALIDATOR is None:
        _VALIDATOR = jsonschema.Draft202012Validator(
            _contract_schema(),
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
        print("ERROR: evidence package must be a mapping", file=sys.stderr)
        sys.exit(1)
    return loaded


def validate_evidence_package(data: dict[str, Any]) -> list[str]:
    """Validate an evidence package against the canonical YAML contract.

    Returns list of errors (empty = valid). Structural rules (required fields,
    package types, producer/items/integrity shapes, confidence range) are all
    enforced by the schema.
    """
    return [
        (
            ".".join(str(p) for p in error.path) or "root"
        ) + f": {error.message}"
        for error in sorted(
            _validator().iter_errors(data),
            key=lambda e: (str(e.path), str(e.schema_path)),
        )
    ]


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python validators/evidence_validator.py <path>", file=sys.stderr)
        sys.exit(1)

    data = _load_document(sys.argv[1])
    errors = validate_evidence_package(data)

    if errors:
        print("EVIDENCE VALIDATION FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    print("VALID: Evidence package conforms to the RACS specification.")
    sys.exit(0)


if __name__ == "__main__":
    main()
