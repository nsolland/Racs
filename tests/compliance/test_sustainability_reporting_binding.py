"""Tests for CSRD/ESRS RACS binding extensions (#1492, Slice 8).

Validates the additive extension schemas with an independent validator
(jsonschema if available, else stdlib deny-unknown structural check).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

try:
    import jsonschema

    HAS_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    HAS_JSONSCHEMA = False


def _load(name: str) -> dict:
    with open(Path("spec/extensions") / name) as f:
        return json.load(f)


def _valid_action_binding() -> dict:
    return {
        "schema": "sustainability-reporting-action-binding.v1",
        "binding_id": "b-1",
        "action_envelope_ref": "env-1",
        "action_envelope_digest": "d-env-1",
        "reporting_entity_ref": "entity-1",
        "reporting_entity_digest": "d-entity-1",
        "reporting_period_ref": "p-2026",
        "standard_profile_ref": "EU_ESRS_2023_IN_FORCE",
        "standard_profile_digest": "d-profile-1",
        "target_artifact_ref": "dp-1",
        "target_artifact_digest": "d-dp-1",
        "source_evidence_refs": ["src-1"],
        "materiality_decision_ref": "dec-1",
        "reht_clearance_ref": "reht-1",
        "expected_receipt_type": "REPORT_FREEZE_RECEIPT",
    }


def _valid_receipt_binding() -> dict:
    return {
        "schema": "sustainability-reporting-receipt-binding.v1",
        "receipt_binding_id": "rb-1",
        "action_binding_ref": "b-1",
        "expected_receipt_type": "REPORT_FREEZE_RECEIPT",
        "issued_receipt_ref": "r-1",
        "issued_receipt_digest": "d-r-1",
        "receipt_chain_ref": "chain-1",
    }


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_action_binding_schema_validates_good_document():
    schema = _load("sustainability-reporting-action-binding-v1.schema.json")
    jsonschema.validate(_valid_action_binding(), schema)


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_action_binding_rejects_unknown_field():
    schema = _load("sustainability-reporting-action-binding-v1.schema.json")
    bad = _valid_action_binding()
    bad["datapoint_value"] = 120  # must be rejected (deny-unknown)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)


def test_action_binding_deny_unknown_structure():
    schema = _load("sustainability-reporting-action-binding-v1.schema.json")
    assert schema.get("additionalProperties") is False
    assert "datapoint_value" not in schema["properties"]


def test_receipt_binding_deny_unknown():
    schema = _load("sustainability-reporting-receipt-binding-v1.schema.json")
    assert schema.get("additionalProperties") is False


def test_binding_does_not_copy_domain_logic():
    """RACS binds refs/digests only — no datapoint values or ESRS text."""
    schema = _load("sustainability-reporting-action-binding-v1.schema.json")
    props = " ".join(schema["properties"].keys())
    assert "datapoint_value" not in props
    assert "esrs_text" not in props
    assert "materiality_score" not in props


def test_binding_requires_essential_refs():
    schema = _load("sustainability-reporting-action-binding-v1.schema.json")
    required = schema["required"]
    for field in ("reporting_entity_ref", "reporting_period_ref",
                  "standard_profile_ref", "target_artifact_ref", "expected_receipt_type"):
        assert field in required
