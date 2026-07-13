#!/usr/bin/env python3
"""
RACS Evidence Validator

Checks that an evidence package conforms to the RACS specification.
Evidence packages are immutable in transmission — this validator
checks integrity metadata structure (but does not verify signatures).

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
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

REQUIRED_FIELDS = [
    "evidence_id",
    "package_type",
    "producer",
    "items",
    "integrity",
    "created_at",
]

VALID_PACKAGE_TYPES = {"observation", "inference", "measurement", "report", "composite"}


def _load_document(path: str) -> dict[str, Any]:
    if not os.path.isfile(path):
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(2)

    with open(path, "r") as fh:
        content = fh.read()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    if yaml is not None:
        try:
            loaded = yaml.safe_load(content)
            if not isinstance(loaded, dict):
                print(f"ERROR: evidence package must be a mapping", file=sys.stderr)
                sys.exit(1)
            return loaded
        except yaml.YAMLError as exc:
            print(f"ERROR: invalid YAML: {exc}", file=sys.stderr)
            sys.exit(1)

    print("ERROR: PyYAML not installed", file=sys.stderr)
    sys.exit(1)


def validate_evidence_package(data: dict[str, Any]) -> list[str]:
    """Validate an evidence package dict. Returns list of errors (empty = valid)."""
    errors: list[str] = []

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None:
            errors.append(f"{field}: is required")

    # Package type
    if "package_type" in data and data["package_type"] not in VALID_PACKAGE_TYPES:
        errors.append(
            f"package_type: must be one of {', '.join(sorted(VALID_PACKAGE_TYPES))}, got {data['package_type']!r}"
        )

    # Producer object
    if "producer" in data and isinstance(data["producer"], dict):
        producer = data["producer"]
        for req in ("id", "system"):
            if req not in producer:
                errors.append(f"producer.{req}: is required")

    # Items list
    if "items" in data:
        if not isinstance(data["items"], list):
            errors.append("items: must be a list")
        elif len(data["items"]) == 0:
            errors.append("items: must have at least one item")
        else:
            for i, item in enumerate(data["items"]):
                if not isinstance(item, dict):
                    errors.append(f"items[{i}]: must be an object")
                    continue
                for req in ("item_id", "fact_type", "value"):
                    if req not in item:
                        errors.append(f"items[{i}].{req}: is required")
                if "confidence" in item:
                    c = item["confidence"]
                    if not isinstance(c, (int, float)) or c < 0 or c > 1:
                        errors.append(
                            f"items[{i}].confidence: must be a number between 0 and 1"
                        )

    # Integrity object
    if "integrity" in data and isinstance(data["integrity"], dict):
        integrity = data["integrity"]
        for req in ("signed_digest", "algorithm"):
            if req not in integrity:
                errors.append(f"integrity.{req}: is required")

    return errors


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
