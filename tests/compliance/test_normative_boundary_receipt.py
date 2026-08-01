from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "spec" / "boundary-decision-receipt-v0.2.schema.json"
BINDINGS_SRC = REPO_ROOT / "reference" / "bindings" / "v0.2" / "python" / "src"
sys.path.insert(0, str(BINDINGS_SRC))

from racs_v02.normative_receipt import (  # noqa: E402
    BoundaryAdmissibilityState,
    BoundaryDecision,
    BoundaryDecisionReceiptV02,
)


D = "sha256:" + "a" * 64


def payload(decision="DEFER", **overrides):
    value = {
        "boundary_receipt_id": "boundary-receipt-1",
        "tenant_id": "tenant-1",
        "action_id": "action-1",
        "action_envelope_digest": D,
        "decision": decision,
        "admissibility_state": (
            "INDETERMINATE" if decision == "DEFER" else "REQUIRES_STEP_UP"
        ),
        "execution_occurred": False,
        "clearance_issued": False,
        "commit_token_issued": False,
        "research_report_ref": "research:report:1",
        "research_report_digest": "sha256:" + "1" * 64,
        "model_power_shadow_profile_digest": "sha256:" + "2" * 64,
        "counterposition_bundle_digest": "sha256:" + "3" * 64,
        "adversarial_evaluation_digest": "sha256:" + "4" * 64,
        "normative_scorecard_digest": "sha256:" + "5" * 64,
        "normative_influence_profile_digests": ["sha256:" + "6" * 64],
        "vaig_evaluation_report_ref": "vaig:evaluation:1",
        "vaig_evaluation_report_digest": "sha256:" + "7" * 64,
        "vaig_normative_handoff_ref": "vaig:normative:1",
        "vaig_normative_handoff_digest": "sha256:" + "8" * 64,
        "reht_determination_ref": "reht:determination:1",
        "reht_determination_digest": "sha256:" + "9" * 64,
        "reason_codes": [
            "NORMATIVE_SCORECARD_DEFERRED"
            if decision == "DEFER"
            else "UNRESOLVED_NORMATIVE_CONFLICT"
        ],
        "recorded_at": "2026-08-01T12:00:00Z",
        "previous_receipt_hash": "sha256:" + "b" * 64,
    }
    if decision == "STEP_UP":
        value["required_authority_class"] = "HUMAN_ACCOUNTABLE_OWNER"
    value.update(overrides)
    return value


def validator():
    return jsonschema.Draft202012Validator(
        json.loads(SPEC_PATH.read_text(encoding="utf-8")),
        format_checker=jsonschema.FormatChecker(),
    )


def test_defer_receipt_validates_and_records_non_execution():
    item = payload("DEFER")
    validator().validate(item)

    assert item["execution_occurred"] is False
    assert item["clearance_issued"] is False
    assert item["commit_token_issued"] is False


def test_step_up_receipt_validates_with_authority_class():
    validator().validate(payload("STEP_UP"))


def test_defer_state_pair_is_enforced():
    item = payload("DEFER", admissibility_state="REQUIRES_STEP_UP")
    assert not validator().is_valid(item)


def test_step_up_state_pair_is_enforced():
    item = payload("STEP_UP", admissibility_state="INDETERMINATE")
    assert not validator().is_valid(item)


def test_step_up_requires_authority_class():
    item = payload("STEP_UP")
    del item["required_authority_class"]
    assert not validator().is_valid(item)


def test_defer_rejects_authority_class():
    item = payload("DEFER", required_authority_class="HUMAN_OWNER")
    assert not validator().is_valid(item)


def test_receipt_cannot_claim_clearance_commit_or_execution():
    for field in ("execution_occurred", "clearance_issued", "commit_token_issued"):
        item = payload("DEFER", **{field: True})
        assert not validator().is_valid(item)


def test_exact_cross_layer_digests_are_required():
    item = payload("DEFER", vaig_normative_handoff_digest="bad")
    assert not validator().is_valid(item)

    item = payload("DEFER")
    del item["reht_determination_digest"]
    assert not validator().is_valid(item)


def test_typed_binding_matches_schema_and_canonical_digest_is_content_bound():
    first = BoundaryDecisionReceiptV02(**payload("DEFER"))
    second = BoundaryDecisionReceiptV02(**payload("DEFER"))
    changed = BoundaryDecisionReceiptV02(
        **payload("DEFER", reason_codes=["INDEPENDENT_EVALUATOR_MISSING"])
    )

    validator().validate(first.model_dump(mode="json", exclude_none=True))
    assert first.decision is BoundaryDecision.DEFER
    assert first.admissibility_state is BoundaryAdmissibilityState.INDETERMINATE
    assert first.model_digest() == second.model_digest()
    assert first.model_digest() != changed.model_digest()


def test_typed_binding_fails_closed_on_invalid_pairs_and_authority():
    with pytest.raises(ValidationError, match="mismatch"):
        BoundaryDecisionReceiptV02(
            **payload("DEFER", admissibility_state="REQUIRES_STEP_UP")
        )

    with pytest.raises(ValidationError, match="requires required_authority_class"):
        item = payload("STEP_UP")
        del item["required_authority_class"]
        BoundaryDecisionReceiptV02(**item)
