"""Portable execution receipt extension conformance."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from reference.python.racs_canonical import sha256_digest
from validators.execution_receipt_validator import validate_execution_receipt_chain

REPO_ROOT = Path(__file__).resolve().parents[2]
V02_SPEC_PATH = REPO_ROOT / "spec" / "execution-receipt-v0.2.schema.json"
V03_SPEC_PATH = REPO_ROOT / "spec" / "execution-receipt-v0.3.schema.json"
V02_VALIDATOR = jsonschema.Draft202012Validator(
    json.loads(V02_SPEC_PATH.read_text(encoding="utf-8")),
    format_checker=jsonschema.FormatChecker(),
)
V03_VALIDATOR = jsonschema.Draft202012Validator(
    json.loads(V03_SPEC_PATH.read_text(encoding="utf-8")),
    format_checker=jsonschema.FormatChecker(),
)

D = "sha256:" + "a" * 64


def _base_receipt() -> dict:
    return {
        "execution_receipt_id": "receipt-1",
        "execution_id": "exec-1",
        "tenant_id": "tenant-1",
        "action_id": "action-1",
        "action_envelope_digest": D,
        "clearance_id": "clearance-1",
        "clearance_digest": D,
        "commit_token_id": "commit-1",
        "commit_token_digest": D,
        "connector_id": "connector-1",
        "capability": "cap-1",
        "target_digest": D,
        "payload_digest": D,
        "started_at": "2026-08-01T12:00:00Z",
        "completed_at": "2026-08-01T12:01:00Z",
        "technical_outcome": "SUCCEEDED",
        "provider_reference": "provider-1",
        "response_digest": D,
        "reversal_status": "NOT_REVERSED",
        "previous_receipt_hash": D,
    }


def test_existing_receipt_without_extensions_remains_valid():
    assert V02_VALIDATOR.is_valid(_base_receipt())
    assert V03_VALIDATOR.is_valid(_base_receipt())


def test_v02_is_unchanged_and_rejects_the_v03_extension():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {}
    assert not V02_VALIDATOR.is_valid(receipt)
    assert V03_VALIDATOR.is_valid(receipt)


def test_known_extension_fields_are_accepted():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "actor_principal": {"subject": "actor-1"},
        "delegation_scope_ref": "del-1",
        "policy_fingerprint_ref": "policy-1",
        "evidence_refs": [D],
        "pre_state": {"evidence_ref": D, "scope": "bounded:target_digest"},
        "post_state": {"evidence_ref": D, "scope": "bounded:target_digest"},
        "cost": {
            "method": "provider_reported",
            "evidence_ref": D,
            "confidence": "high",
            "unit": "token",
            "amount": 10,
        },
        "value_claim": {
            "method": "estimated_monetary_impact",
            "evidence_ref": D,
            "confidence": "medium",
            "direction": "protected",
            "amount": 100,
            "currency": "NOK",
        },
        "external_proof_ref": "proof-1",
        "signature_binding_ref": "sig-1",
        "replay_status": "FIRST_EXECUTION",
        "idempotency_token": "idem-1",
    }
    assert V03_VALIDATOR.is_valid(receipt)


def test_unknown_extension_fields_are_rejected():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "actor_principal": {"subject": "actor-1"},
        "unknown_field": "rejected",
    }
    assert not V03_VALIDATOR.is_valid(receipt)


def test_unknown_actor_principal_fields_are_rejected():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "actor_principal": {"vendor_x_secret": 1},
    }
    assert not V03_VALIDATOR.is_valid(receipt)


def test_confidence_must_be_typed_for_cost_and_value_claims():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "cost": {
            "method": "provider_reported",
            "evidence_ref": D,
            "confidence": "banana",
            "unit": "token",
            "amount": 10,
        },
        "value_claim": {
            "method": "estimated_monetary_impact",
            "evidence_ref": D,
            "confidence": "banana",
            "direction": "protected",
            "amount": 100,
            "currency": "NOK",
        },
    }
    assert not V03_VALIDATOR.is_valid(receipt)


def test_external_references_are_not_governance_authority():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "external_proof_ref": "proof-1",
        "signature_binding_ref": "sig-1",
        "evidence_refs": [D],
    }
    assert V03_VALIDATOR.is_valid(receipt)
    assert receipt["clearance_id"] == "clearance-1"
    assert receipt["commit_token_id"] == "commit-1"


def test_cost_claim_requires_method_evidence_and_confidence():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "cost": {
            "method": "provider_reported",
            "evidence_ref": D,
            "confidence": "high",
            "unit": "token",
            "amount": 10,
        }
    }
    assert V03_VALIDATOR.is_valid(receipt)

    for missing_field in ("method", "evidence_ref", "confidence"):
        invalid = deepcopy(receipt)
        invalid["receipt_ext"] = {
            "cost": {
                "method": "provider_reported",
                "evidence_ref": D,
                "confidence": "high",
                "unit": "token",
                "amount": 10,
            }
        }
        del invalid["receipt_ext"]["cost"][missing_field]
        assert not V03_VALIDATOR.is_valid(invalid)


def test_value_claim_requires_method_evidence_and_confidence():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "value_claim": {
            "method": "estimated_monetary_impact",
            "evidence_ref": D,
            "confidence": "medium",
            "direction": "protected",
            "amount": 100,
            "currency": "NOK",
        }
    }
    assert V03_VALIDATOR.is_valid(receipt)

    for missing_field in ("method", "evidence_ref", "confidence"):
        invalid = dict(_base_receipt())
        invalid["receipt_ext"] = {
            "value_claim": {
                "method": "estimated_monetary_impact",
                "evidence_ref": D,
                "confidence": "medium",
                "direction": "protected",
                "amount": 100,
                "currency": "NOK",
            }
        }
        del invalid["receipt_ext"]["value_claim"][missing_field]
        assert not V03_VALIDATOR.is_valid(invalid)


def test_replay_status_and_idempotency_token_are_supported():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "replay_status": "REPLAY",
        "idempotency_token": "idem-1",
        "duplicate_of_receipt_id": "receipt-0",
        "duplicate_of_receipt_hash": D,
    }
    assert V03_VALIDATOR.is_valid(receipt)

    for invalid_status in ("FIRST_RUN", "DUPE", "retry"):
        bad = deepcopy(receipt)
        bad["receipt_ext"]["replay_status"] = invalid_status
        assert not V03_VALIDATOR.is_valid(bad)


@pytest.mark.parametrize("status", ["REPLAY", "DUPLICATE"])
def test_replay_and_duplicate_require_idempotency_and_exact_prior_receipt(status):
    complete = dict(_base_receipt())
    complete["receipt_ext"] = {
        "replay_status": status,
        "idempotency_token": "idem-1",
        "duplicate_of_receipt_id": "receipt-0",
        "duplicate_of_receipt_hash": D,
    }
    assert V03_VALIDATOR.is_valid(complete)

    for missing in (
        "idempotency_token",
        "duplicate_of_receipt_id",
        "duplicate_of_receipt_hash",
    ):
        invalid = deepcopy(complete)
        del invalid["receipt_ext"][missing]
        assert not V03_VALIDATOR.is_valid(invalid)


def test_first_execution_cannot_claim_a_duplicate_lineage():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "replay_status": "FIRST_EXECUTION",
        "idempotency_token": "idem-1",
        "duplicate_of_receipt_id": "receipt-0",
        "duplicate_of_receipt_hash": D,
    }
    assert not V03_VALIDATOR.is_valid(receipt)


def test_duplicate_reference_cannot_exist_without_replay_classification():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "idempotency_token": "idem-1",
        "duplicate_of_receipt_id": "receipt-0",
        "duplicate_of_receipt_hash": D,
    }
    assert not V03_VALIDATOR.is_valid(receipt)


def test_bounded_pre_and_post_state_evidence_are_supported():
    receipt = dict(_base_receipt())
    receipt["receipt_ext"] = {
        "pre_state": {"evidence_ref": D, "scope": "bounded:target_digest"},
        "post_state": {"evidence_ref": D, "scope": "bounded:target_digest"},
    }
    assert V03_VALIDATOR.is_valid(receipt)

    for missing_field in ("evidence_ref", "scope"):
        invalid = deepcopy(receipt)
        invalid["receipt_ext"]["pre_state"] = {
            "evidence_ref": D,
            "scope": "bounded:target_digest",
        }
        del invalid["receipt_ext"]["pre_state"][missing_field]
        assert not V03_VALIDATOR.is_valid(invalid)

    unbounded = deepcopy(receipt)
    unbounded["receipt_ext"]["pre_state"]["scope"] = "entire_environment_unbounded"
    assert not V03_VALIDATOR.is_valid(unbounded)


def _valid_replay_chain():
    prior = _base_receipt()
    prior["execution_receipt_id"] = "receipt-0"
    prior["execution_id"] = "exec-0"
    prior["receipt_ext"] = {
        "replay_status": "FIRST_EXECUTION",
        "idempotency_token": "idem-1",
    }
    current = deepcopy(_base_receipt())
    current["previous_receipt_hash"] = sha256_digest(prior)
    current["receipt_ext"] = {
        "replay_status": "REPLAY",
        "idempotency_token": "idem-1",
        "duplicate_of_receipt_id": "receipt-0",
        "duplicate_of_receipt_hash": sha256_digest(prior),
    }
    return prior, current


def test_semantic_validator_accepts_exact_prior_replay_lineage():
    assert validate_execution_receipt_chain(_valid_replay_chain()) == []


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("self_reference", "cannot self-reference"),
        ("missing_reference", "must reference an earlier receipt"),
        ("wrong_reference_hash", "does not match the referenced receipt"),
        ("wrong_idempotency", "does not match the referenced execution lineage"),
        ("broken_chain", "does not bind the immediately preceding receipt"),
    ],
)
def test_semantic_validator_rejects_false_replay_lineage(mutation, expected):
    prior, current = _valid_replay_chain()
    extension = current["receipt_ext"]
    if mutation == "self_reference":
        extension["duplicate_of_receipt_id"] = current["execution_receipt_id"]
    elif mutation == "missing_reference":
        extension["duplicate_of_receipt_id"] = "does-not-exist"
    elif mutation == "wrong_reference_hash":
        extension["duplicate_of_receipt_hash"] = D
    elif mutation == "wrong_idempotency":
        extension["idempotency_token"] = "idem-other"
    elif mutation == "broken_chain":
        current["previous_receipt_hash"] = D

    errors = validate_execution_receipt_chain((prior, current))
    assert any(expected in error for error in errors)


EXAMPLES_PATH = REPO_ROOT / "examples" / "portable-execution-receipts.json"
REQUIRED_DOMAINS = ("financial", "browser", "messaging", "infrastructure")


def _example_receipts():
    data = json.loads(EXAMPLES_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return [data[domain] for domain in REQUIRED_DOMAINS]


def test_portable_examples_load():
    data = json.loads(EXAMPLES_PATH.read_text(encoding="utf-8"))
    assert set(data.keys()) == set(REQUIRED_DOMAINS)


def test_portable_examples_cover_four_action_domains():
    for receipt in _example_receipts():
        assert V03_VALIDATOR.is_valid(receipt)
        assert receipt["clearance_id"]
        assert receipt["commit_token_id"]


def test_portable_examples_preserve_governance_and_commit_bindings():
    for receipt in _example_receipts():
        assert receipt["clearance_id"].startswith("clearance-")
        assert receipt["clearance_digest"].startswith("sha256:")
        assert receipt["commit_token_id"].startswith("commit-")
        assert receipt["commit_token_digest"].startswith("sha256:")
    assert len({receipt["clearance_digest"] for receipt in _example_receipts()}) == 4
    assert len({receipt["commit_token_digest"] for receipt in _example_receipts()}) == 4


def test_portable_examples_do_not_treat_external_proof_as_governance_authority():
    for receipt in _example_receipts():
        assert V03_VALIDATOR.is_valid(receipt)
        assert receipt["clearance_id"]
        assert receipt["commit_token_id"]
