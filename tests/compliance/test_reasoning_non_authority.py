"""Conformance tests for the chain-of-thought non-authority invariant."""
import json
from pathlib import Path

from jsonschema import Draft202012Validator


REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "spec" / "governance-evaluation-v0.2.schema.json"
VECTORS = REPO / "test-vectors" / "0.2" / "reasoning-non-authority.json"


def test_reasoning_non_authority_vectors_match_schema_expectations():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]

    for vector in vectors:
        errors = list(validator.iter_errors(vector["payload"]))
        assert (not errors) is vector["schema_valid"], (
            vector["id"],
            [error.message for error in errors],
        )


def test_missing_authority_never_issues_clearance():
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]

    for vector in vectors:
        payload = vector["payload"]
        if payload["authority_status"] == "MISSING":
            assert vector["clearance_issued"] is False
            if vector["schema_valid"]:
                assert payload["decision"] in {"DENY", "HALT"}


def test_reasoning_observability_is_not_required_for_valid_authority():
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]
    vector = next(
        item
        for item in vectors
        if item["id"] == "valid_authority_without_reasoning_trace"
    )

    assert "reasoning_trace_binding" not in vector["payload"]
    assert vector["payload"]["authority_status"] == "PRESENT_AND_VALID"
    assert vector["payload"]["decision"] == "ALLOW"
    assert vector["schema_valid"] is True
