#!/usr/bin/env python3
"""
RACS Policy Validator

Checks that a policy context conforms to the RACS specification.
Policy is data, not code — this validator checks structure only,
never evaluates policy content.

Usage:
    python validators/policy_validator.py path/to/policy-context.yaml

Exit codes:
    0   Valid policy context
    1   Invalid policy context
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
    "policy_id",
    "policy_set_ref",
    "policy_set_version",
    "evaluation_mode",
    "valid_from",
]

VALID_EVALUATION_MODES = {"strict", "advisory", "audit_only"}
VALID_EFFECTS = {"ALLOW", "DENY", "REQUIRE_ELEVATION", "REQUIRE_REVIEW", "LOG"}


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
                print(
                    f"ERROR: policy context must be a mapping",
                    file=sys.stderr,
                )
                sys.exit(1)
            return loaded
        except yaml.YAMLError as exc:
            print(f"ERROR: invalid YAML: {exc}", file=sys.stderr)
            sys.exit(1)

    print("ERROR: PyYAML not installed", file=sys.stderr)
    sys.exit(1)


def validate_policy_context(data: dict[str, Any]) -> list[str]:
    """Validate a policy context dict. Returns list of errors (empty = valid)."""
    errors: list[str] = []

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None:
            errors.append(f"{field}: is required")
        elif not isinstance(data[field], str):
            errors.append(f"{field}: must be a string")

    # Validate evaluation_mode
    if "evaluation_mode" in data:
        mode = data["evaluation_mode"]
        if mode not in VALID_EVALUATION_MODES:
            errors.append(
                f"evaluation_mode: must be one of {', '.join(sorted(VALID_EVALUATION_MODES))}, got {mode!r}"
            )

    # Validate rules if present
    if "rules" in data:
        if not isinstance(data["rules"], list):
            errors.append("rules: must be a list")
        else:
            for i, rule in enumerate(data["rules"]):
                if not isinstance(rule, dict):
                    errors.append(f"rules[{i}]: must be an object")
                    continue
                if "rule_id" not in rule:
                    errors.append(f"rules[{i}]: rule_id is required")
                if "effect" in rule:
                    if rule["effect"] not in VALID_EFFECTS:
                        errors.append(
                            f"rules[{i}].effect: must be one of {', '.join(sorted(VALID_EFFECTS))}, got {rule['effect']!r}"
                        )

    return errors


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python validators/policy_validator.py <path>", file=sys.stderr)
        sys.exit(1)

    data = _load_document(sys.argv[1])
    errors = validate_policy_context(data)

    if errors:
        print("POLICY VALIDATION FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    print("VALID: Policy context conforms to the RACS specification.")
    sys.exit(0)


if __name__ == "__main__":
    main()
