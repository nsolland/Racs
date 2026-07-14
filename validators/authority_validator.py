#!/usr/bin/env python3
"""
RACS Authority Context Validator

Validates the authority_context of a RACS Action Envelope. An authority context
MUST be explicit: it names who is authorized, the authorizing entity, and — for
delegated authority — a traceable delegation chain. Empty or missing authority
is never admissible.

This validator checks structure only; it does NOT perform cryptographic
signature verification. Callers must not treat a passing structural validation
as proof of signature validity.

Usage:
    python validators/authority_validator.py path/to/authority-context.yaml

Exit codes:
    0   Valid authority context
    1   Invalid authority context
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
    "authority_id",
    "authorizing_entity",
    "authority_type",
]

VALID_AUTHORITY_TYPES = {"direct", "delegated", "self", "system"}


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
                    "ERROR: authority context must be a mapping",
                    file=sys.stderr,
                )
                sys.exit(1)
            return loaded
        except yaml.YAMLError as exc:
            print(f"ERROR: invalid YAML: {exc}", file=sys.stderr)
            sys.exit(1)

    print("ERROR: PyYAML not installed", file=sys.stderr)
    sys.exit(1)


def validate_authority_context(data: Any) -> list[str]:
    """Validate an authority context dict.

    Returns a list of error messages (empty = valid). A non-dict or empty
    object is rejected: authority must always be explicit.

    NOTE: structural validation only. Signature/cryptographic verification is
    the responsibility of the downstream verification layer and is NOT performed
    here.
    """
    errors: list[str] = []

    if data is None:
        errors.append("authority_context: is required")
        return errors
    if not isinstance(data, dict):
        errors.append(
            f"authority_context: must be an object, got {type(data).__name__}"
        )
        return errors
    if len(data) == 0:
        errors.append(
            "authority_context: must not be empty; explicit authority is required"
        )
        return errors

    # Required fields (string-valued). `authorizing_entity` is a structured
    # object and is validated separately below, so it is excluded here.
    for field in REQUIRED_FIELDS:
        if field == "authorizing_entity":
            continue
        if field not in data or data[field] is None:
            errors.append(f"authority_context.{field}: is required")
        elif not isinstance(data[field], str) or len(data[field]) == 0:
            errors.append(f"authority_context.{field}: must be a non-empty string")

    # authority_type must be a known value
    if "authority_type" in data and data["authority_type"] not in VALID_AUTHORITY_TYPES:
        errors.append(
            f"authority_context.authority_type: must be one of "
            f"{', '.join(sorted(VALID_AUTHORITY_TYPES))}, "
            f"got {data['authority_type']!r}"
        )

    # authorizing_entity must be a structured object with id + role
    if "authorizing_entity" in data:
        ent = data["authorizing_entity"]
        if not isinstance(ent, dict):
            errors.append("authority_context.authorizing_entity: must be an object")
        else:
            for req in ("id", "role"):
                if req not in ent or not isinstance(ent[req], str) or len(ent[req]) == 0:
                    errors.append(
                        f"authority_context.authorizing_entity.{req}: "
                        "must be a non-empty string"
                    )

    # Delegated authority requires a traceable delegation chain
    if data.get("authority_type") == "delegated":
        chain = data.get("delegation_chain")
        if not isinstance(chain, list) or len(chain) == 0:
            errors.append(
                "authority_context.delegation_chain: is required for delegated "
                "authority and must be a non-empty list"
            )
        else:
            for i, link in enumerate(chain):
                if not isinstance(link, dict):
                    errors.append(f"authority_context.delegation_chain[{i}]: must be an object")
                    continue
                for req in ("delegator_id", "delegate_id", "scope"):
                    if req not in link or not isinstance(link[req], str) or len(link[req]) == 0:
                        errors.append(
                            f"authority_context.delegation_chain[{i}].{req}: "
                            "must be a non-empty string"
                        )

    return errors


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

    print("VALID: Authority context conforms to the RACS specification.")
    sys.exit(0)


if __name__ == "__main__":
    main()
