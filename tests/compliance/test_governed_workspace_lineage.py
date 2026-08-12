"""Compliance tests for the additive Governed Workspace lineage contract."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


REPO = Path(__file__).resolve().parents[2]
SPEC = REPO / "spec"
DIGEST = "sha256:" + "a" * 64
WORKSPACE_DIGEST = "sha256:" + "b" * 64
KERNEL_CONTEXT_DIGEST = "sha256:" + "c" * 64


def _schema(name: str) -> dict:
    return json.loads((SPEC / name).read_text(encoding="utf-8"))


LINEAGE_SCHEMA = _schema("governed-workspace-lineage-v0.2.schema.json")
REGISTRY = Registry().with_resource(
    LINEAGE_SCHEMA["$id"], Resource.from_contents(LINEAGE_SCHEMA)
)
FORMAT_CHECKER = FormatChecker()


def _validator(name: str) -> Draft202012Validator:
    schema = _schema(name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        registry=REGISTRY,
        format_checker=FORMAT_CHECKER,
    )


def _lineage() -> dict:
    return {
        "tenant_id": "tenant-1",
        "work_unit_id": "work-1",
        "workspace_id": "workspace-1",
        "workspace_digest": DIGEST,
        "workspace_expires_at": "2026-08-12T12:15:00Z",
        "program_ref": "program://workspace-1/function-1",
        "program_digest": DIGEST,
        "invocation_id": "invocation-1",
        "candidate_id": "candidate-1",
        "candidate_digest": DIGEST,
        "proposed_action_digest": DIGEST,
        "conformance_report_id": "conformance-1",
        "conformance_digest": DIGEST,
        "source_state_digest": DIGEST,
        "conformed_state_digest": DIGEST,
        "source_event_position": 42,
        "conformed_at": "2026-08-12T12:00:00Z",
        "dependency_digest": DIGEST,
        "workspace_binding_digest": WORKSPACE_DIGEST,
        "kernel_context_digest": KERNEL_CONTEXT_DIGEST,
    }


def _action_envelope() -> dict:
    return {
        "action_id": "action-1",
        "tenant_id": "tenant-1",
        "action_type": "CONNECTOR_CALL",
        "actor_ref": "agent://worker-1",
        "target_ref": "system://target-1",
        "target_digest": DIGEST,
        "payload_digest": DIGEST,
        "authority_grant_ref": "authority://grant-1",
        "delegation_chain_ref": "delegation://chain-1",
        "policy_ref": "policy://execution-1",
        "evidence_package_ref": "evidence://package-1",
        "purpose_ref": "purpose://work-1",
        "environment_state_ref": "state://kernel/42",
        "risk_context_ref": "risk://context-1",
        "connector_id": "connector-1",
        "capability": "write",
        "consequence_class": "HIGH",
        "reversibility": "COMPENSATABLE",
        "created_at": "2026-08-12T12:00:00Z",
        "expires_at": "2026-08-12T12:10:00Z",
        "replay_nonce": "0123456789abcdef",
        "idempotency_key": "idem-001",
        "boundary_requirements": {
            "required_types": ["EXECUTION"],
            "policy_ref": "policy://execution-1",
            "policy_digest": DIGEST,
            "fail_closed": True,
        },
    }


def _determination() -> dict:
    return {
        "determination_id": "determination-1",
        "action_id": "action-1",
        "action_envelope_digest": DIGEST,
        "tenant_id": "tenant-1",
        "authority_digest": DIGEST,
        "delegation_chain_digest": DIGEST,
        "policy_digest": DIGEST,
        "evidence_digest": DIGEST,
        "purpose_digest": DIGEST,
        "state_digest": DIGEST,
        "evaluation_bindings": [
            {"evaluation_ref": "evaluation-1", "evaluation_digest": DIGEST}
        ],
        "boundary_assessment_binding": {
            "assessment_ref": "assessment-1",
            "assessment_digest": DIGEST,
        },
        "state": "ADMISSIBLE",
        "reason_codes": ["WORKSPACE_CONFORMANT"],
        "determined_at": "2026-08-12T12:01:00Z",
        "valid_until": "2026-08-12T12:10:00Z",
        "revocation_registry_ref": "revocation://registry-1",
    }


def _clearance() -> dict:
    return {
        "clearance_id": "clearance-1",
        "action_id": "action-1",
        "action_envelope_digest": DIGEST,
        "tenant_id": "tenant-1",
        "decision": "ALLOW",
        "admissibility_state": "ADMISSIBLE",
        "authority_digest": DIGEST,
        "delegation_chain_digest": DIGEST,
        "policy_digest": DIGEST,
        "evidence_digest": DIGEST,
        "purpose_digest": DIGEST,
        "state_digest": DIGEST,
        "target_digest": DIGEST,
        "payload_digest": DIGEST,
        "connector_id": "connector-1",
        "capability": "write",
        "consequence_class": "HIGH",
        "reversibility": "COMPENSATABLE",
        "valid_from": "2026-08-12T12:02:00Z",
        "valid_until": "2026-08-12T12:07:00Z",
        "replay_nonce": "0123456789abcdef",
        "idempotency_key": "idem-001",
        "revocation_registry_ref": "revocation://registry-1",
        "evaluator_refs": ["evaluation-1"],
        "admissibility_determination_ref": "determination-1",
        "admissibility_determination_digest": DIGEST,
    }


def _permit() -> dict:
    return {
        "execution_id": "execution-1",
        "action_id": "action-1",
        "tenant_id": "tenant-1",
        "clearance_id": "clearance-1",
        "clearance_digest": DIGEST,
        "racs_decision_id": "decision-1",
        "racs_decision_digest": DIGEST,
        "decision": "ALLOW",
        "action_envelope_digest": DIGEST,
        "connector_id": "connector-1",
        "capability": "write",
        "target_digest": DIGEST,
        "payload_digest": DIGEST,
        "purpose_digest": DIGEST,
        "authority_digest": DIGEST,
        "policy_digest": DIGEST,
        "evidence_digest": DIGEST,
        "state_digest": DIGEST,
        "valid_from": "2026-08-12T12:02:00Z",
        "valid_until": "2026-08-12T12:07:00Z",
        "replay_nonce": "0123456789abcdef",
        "idempotency_key": "idem-001",
        "reservation_id": "reservation-1",
    }


def _execution_receipt() -> dict:
    return {
        "execution_receipt_id": "execution-receipt-1",
        "execution_id": "execution-1",
        "tenant_id": "tenant-1",
        "action_id": "action-1",
        "action_envelope_digest": DIGEST,
        "clearance_id": "clearance-1",
        "clearance_digest": DIGEST,
        "commit_token_id": "commit-token-1",
        "commit_token_digest": DIGEST,
        "connector_id": "connector-1",
        "capability": "write",
        "target_digest": DIGEST,
        "payload_digest": DIGEST,
        "started_at": "2026-08-12T12:03:00Z",
        "completed_at": "2026-08-12T12:03:01Z",
        "technical_outcome": "SUCCEEDED",
        "provider_reference": "provider://operation-1",
        "response_digest": DIGEST,
        "reversal_status": "NOT_REVERSED",
        "previous_receipt_hash": DIGEST,
    }


def _outcome_receipt() -> dict:
    return {
        "outcome_receipt_id": "outcome-receipt-1",
        "execution_receipt_id": "execution-receipt-1",
        "execution_receipt_digest": DIGEST,
        "tenant_id": "tenant-1",
        "observation_window": {"from": "2026-08-12T12:03:00Z"},
        "expected_effect": {"status": "updated"},
        "observed_effect": {"status": "updated"},
        "evidence_refs": ["evidence://observation-1"],
        "measurement_method": "provider response plus state observation",
        "baseline_ref": "baseline://state-42",
        "attribution_score": 1.0,
        "confidence": 0.99,
        "dispute_state": "UNDISPUTED",
        "observed_at": "2026-08-12T12:04:00Z",
        "previous_receipt_hash": DIGEST,
    }


def test_complete_lineage_and_workspace_bound_action_are_valid():
    lineage_validator = _validator("governed-workspace-lineage-v0.2.schema.json")
    assert lineage_validator.is_valid(_lineage())

    action = _action_envelope()
    assert _validator("action-envelope-v0.2.schema.json").is_valid(action)
    action["workspace_binding"] = _lineage()
    assert _validator("action-envelope-v0.2.schema.json").is_valid(action)


@pytest.mark.parametrize("required_field", LINEAGE_SCHEMA["required"])
def test_lineage_is_fail_closed_when_any_binding_is_missing(required_field: str):
    lineage = _lineage()
    del lineage[required_field]
    assert not _validator("governed-workspace-lineage-v0.2.schema.json").is_valid(
        lineage
    )


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("workspace_digest", "not-a-digest"),
        ("source_event_position", -1),
    ],
)
def test_lineage_rejects_invalid_values(field: str, invalid_value: object):
    lineage = _lineage()
    lineage[field] = invalid_value
    assert not _validator("governed-workspace-lineage-v0.2.schema.json").is_valid(
        lineage
    )


def test_lineage_time_fields_are_declared_as_date_time():
    assert LINEAGE_SCHEMA["properties"]["workspace_expires_at"]["format"] == "date-time"
    assert LINEAGE_SCHEMA["properties"]["conformed_at"]["format"] == "date-time"


@pytest.mark.parametrize(
    "authority_or_execution_field",
    [
        "decision",
        "authority_digest",
        "authority_grant_ref",
        "clearance_id",
        "execution_id",
        "technical_outcome",
        "authorized",
        "is_true",
    ],
)
def test_lineage_cannot_carry_authority_truth_or_execution_fields(
    authority_or_execution_field: str,
):
    lineage = _lineage()
    lineage[authority_or_execution_field] = True
    assert not _validator("governed-workspace-lineage-v0.2.schema.json").is_valid(
        lineage
    )


CHAIN_PAYLOADS = [
    ("admissibility-determination-v0.2.schema.json", _determination),
    ("governance-clearance.schema.json", _clearance),
    ("core-execution-permit.schema.json", _permit),
    ("execution-receipt-v0.2.schema.json", _execution_receipt),
    ("outcome-receipt-v0.2.schema.json", _outcome_receipt),
]


@pytest.mark.parametrize(("schema_name", "payload_factory"), CHAIN_PAYLOADS)
def test_chain_binding_is_optional_for_legacy_payloads_and_atomic_when_present(
    schema_name: str,
    payload_factory,
):
    validator = _validator(schema_name)
    legacy = payload_factory()
    assert validator.is_valid(legacy), list(validator.iter_errors(legacy))

    bound = deepcopy(legacy)
    bound["workspace_binding_digest"] = WORKSPACE_DIGEST
    bound["kernel_context_digest"] = KERNEL_CONTEXT_DIGEST
    assert validator.is_valid(bound), list(validator.iter_errors(bound))

    for missing in ("workspace_binding_digest", "kernel_context_digest"):
        partial = deepcopy(bound)
        del partial[missing]
        assert not validator.is_valid(partial)


def test_manifest_records_additive_revision_without_superseding_v02():
    manifest = _schema("version-manifest.json")
    assert manifest["base_version"] == "0.2"
    assert manifest["base_revision"] == "0.2.1"
    assert manifest["base_contract_count"] == 139
    assert "Legacy payloads remain valid" in manifest["note"]
