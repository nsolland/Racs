"""Conformance tests for role-contract-v1 and role-integrity-evaluation-v1 canonical wire schemas."""

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator


def load_schema(filename: str) -> dict:
    schema_path = Path(__file__).parent.parent.parent / "spec" / filename
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def role_contract_validator():
    schema = load_schema("role-contract-v1.schema.json")
    return Draft202012Validator(schema)


@pytest.fixture
def role_integrity_validator():
    schema = load_schema("role-integrity-evaluation-v1.schema.json")
    return Draft202012Validator(schema)


def valid_role_contract_payload() -> dict:
    return {
        "module_role_id": "role-collector-v1",
        "role_contract_version": "1.0",
        "allowed_operations": ["FETCH_SOURCE", "PARSE_DOCUMENT"],
        "forbidden_operations": ["PUBLISH_DECISION", "MUTATE_POLICY"],
        "required_input_types": ["SourceQuery"],
        "required_evidence_types": ["SourceArtifactDigest"],
        "allowed_output_types": ["RawDocumentPayload"],
        "forbidden_output_fields": ["editorial_verdict"],
        "next_owner_roles": ["role-analyzer-v1"],
        "authority_ceiling": "READ_ONLY",
        "may_transform": False,
        "may_repair": False,
        "may_authorize": False,
        "may_execute": False,
    }


def valid_role_integrity_payload() -> dict:
    return {
        "module_role_id": "role-collector-v1",
        "role_contract_version": "1.0",
        "role_contract_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "role_fidelity_probe": "probe-collector-01",
        "evidence_dependency": ["ev-source-digest-001"],
        "cross_role_computation_detected": False,
        "role_drift_detected": False,
        "drift_type": "none",
        "violated_constraints": [],
        "evidence_refs": ["ev-ref-1"],
        "evaluation_timestamp_ns": "1719280000000000000",
        "decision": "ALLOW",
    }


def test_role_contract_valid_payload_passes(role_contract_validator):
    payload = valid_role_contract_payload()
    role_contract_validator.validate(payload)


def test_role_contract_missing_required_fields_fails(role_contract_validator):
    required_fields = [
        "module_role_id",
        "role_contract_version",
        "allowed_operations",
        "forbidden_operations",
        "required_input_types",
        "required_evidence_types",
        "allowed_output_types",
        "forbidden_output_fields",
        "next_owner_roles",
        "authority_ceiling",
        "may_transform",
        "may_repair",
        "may_authorize",
        "may_execute",
    ]
    for field in required_fields:
        payload = valid_role_contract_payload()
        del payload[field]
        errors = list(role_contract_validator.iter_errors(payload))
        assert len(errors) > 0, f"Expected validation failure when missing required field: {field}"


def test_role_contract_unknown_fields_denied(role_contract_validator):
    payload = valid_role_contract_payload()
    payload["unknown_extra_field"] = "illegal"
    errors = list(role_contract_validator.iter_errors(payload))
    assert len(errors) > 0, "Expected validation failure for unknown field"


def test_role_integrity_valid_payload_passes(role_integrity_validator):
    payload = valid_role_integrity_payload()
    role_integrity_validator.validate(payload)


def test_role_integrity_all_drift_enum_values_accepted(role_integrity_validator):
    drift_types = [
        "none",
        "answer_leakage",
        "evidence_bypass",
        "analysis_by_collector",
        "authorization_by_evaluator",
        "repair_by_verifier",
        "execution_by_planner",
        "policy_invention",
        "authority_expansion",
        "downstream_role_absorption",
    ]
    for dt in drift_types:
        payload = valid_role_integrity_payload()
        payload["drift_type"] = dt
        role_integrity_validator.validate(payload)


def test_role_integrity_invalid_drift_type_fails(role_integrity_validator):
    payload = valid_role_integrity_payload()
    payload["drift_type"] = "invalid_drift_enum"
    errors = list(role_integrity_validator.iter_errors(payload))
    assert len(errors) > 0


def test_role_integrity_invalid_decision_fails(role_integrity_validator):
    payload = valid_role_integrity_payload()
    payload["decision"] = "INVALID_DECISION"
    errors = list(role_integrity_validator.iter_errors(payload))
    assert len(errors) > 0


def test_role_integrity_unknown_fields_denied(role_integrity_validator):
    payload = valid_role_integrity_payload()
    payload["extra_property"] = "disallowed"
    errors = list(role_integrity_validator.iter_errors(payload))
    assert len(errors) > 0
