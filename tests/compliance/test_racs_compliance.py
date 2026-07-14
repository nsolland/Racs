"""
RACS Compliance Test Suite

Tests that:
1. Valid example envelopes PASS validation
2. Invalid envelopes FAIL with appropriate errors
3. Validators handle edge cases (missing fields, wrong types, etc.)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure validators/ is on path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from validators import envelope_validator as ev
from validators import policy_validator as pv
from validators import evidence_validator as eidv


# ---- Fixtures ----


EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples"


@pytest.fixture
def valid_energy_grid() -> dict:
    """Load the energy-grid example as a dict."""
    import yaml
    with open(EXAMPLES_DIR / "energy-grid.yaml") as fh:
        return yaml.safe_load(fh)


@pytest.fixture
def valid_financial() -> dict:
    """Load the financial example as a dict."""
    import yaml
    with open(EXAMPLES_DIR / "financial.yaml") as fh:
        return yaml.safe_load(fh)


@pytest.fixture
def valid_medical() -> dict:
    """Load the medical example as a dict."""
    import yaml
    with open(EXAMPLES_DIR / "medical.yaml") as fh:
        return yaml.safe_load(fh)


def make_envelope(**overrides) -> dict:
    """Create a minimal valid envelope dict, with optional overrides.

    The base envelope is governance-complete: authority, policy and evidence
    contexts are present, non-empty and well-formed. Override any context with
    ``{}`` (or other shapes) to test rejection.
    """
    base = {
        "racs_version": "0.1",
        "action_id": "test-ae-001",
        "action_type": "test_action",
        "actor": {"id": "actor:test", "role": "test_agent"},
        "target": {"id": "target:test", "type": "test_resource"},
        "requested_effect": {"description": "Test effect"},
        "authority_context": {
            "authority_id": "auth:test-001",
            "authorizing_entity": {"id": "org:test", "role": "operator"},
            "authority_type": "direct",
        },
        "policy_context": {
            "policy_id": "pol-001",
            "policy_set_ref": "racs.policy.test",
            "policy_set_version": "1.0.0",
            "evaluation_mode": "strict",
            "valid_from": "2026-01-01T00:00:00Z",
        },
        "evidence_package": {
            "evidence_id": "ev-001",
            "package_type": "observation",
            "producer": {"id": "comp:test", "system": "BARO"},
            "items": [
                {"item_id": "item-001", "fact_type": "observation", "value": {"result": "ok"}}
            ],
            "integrity": {"signed_digest": "abc123", "algorithm": "sha256"},
            "created_at": "2026-07-13T12:00:00Z",
        },
        "environment_state": {"snapshot_id": "test-snap-001"},
        "created_at": "2026-07-13T12:00:00Z",
    }
    base.update(overrides)
    return base


# ---- Envelope Validator Tests ----


class TestEnvelopeValidator:
    """Tests for envelope_validator.validate_envelope()."""

    def test_valid_minimal(self):
        """Minimal valid envelope passes."""
        env = make_envelope()
        errors = ev.validate_envelope(env)
        assert errors == [], f"Expected no errors, got: {errors}"

    # ---- Audit #4 regression: empty governance contexts must be rejected ----

    def test_empty_authority_context_rejected(self):
        """Empty authority_context must fail (audit #4, regression #1)."""
        env = make_envelope(authority_context={})
        errors = ev.validate_envelope(env)
        assert any("authority_context" in e for e in errors), (
            f"Expected authority_context error, got: {errors}"
        )

    def test_empty_policy_context_rejected(self):
        """Empty policy_context must fail (audit #4, regression #2)."""
        env = make_envelope(policy_context={})
        errors = ev.validate_envelope(env)
        assert any("policy_context" in e for e in errors), (
            f"Expected policy_context error, got: {errors}"
        )

    def test_empty_evidence_package_rejected(self):
        """Empty evidence_package must fail (audit #4, regression #3)."""
        env = make_envelope(evidence_package={})
        errors = ev.validate_envelope(env)
        assert any("evidence_package" in e for e in errors), (
            f"Expected evidence_package error, got: {errors}"
        )

    def test_missing_policy_id_rejected(self):
        """Policy context missing policy_id must fail (audit #4, regression #5)."""
        env = make_envelope(policy_context={"evaluation_mode": "strict"})
        errors = ev.validate_envelope(env)
        assert any("policy_id" in e for e in errors), (
            f"Expected policy_id error, got: {errors}"
        )

    def test_missing_evidence_items_rejected(self):
        """Evidence package with empty items must fail (audit #4, regression #6)."""
        env = make_envelope(
            evidence_package={
                "evidence_id": "ev-001",
                "package_type": "observation",
                "producer": {"id": "comp:test", "system": "BARO"},
                "items": [],
                "integrity": {"signed_digest": "abc", "algorithm": "sha256"},
                "created_at": "2026-07-13T12:00:00Z",
            }
        )
        errors = ev.validate_envelope(env)
        assert any("items" in e for e in errors), (
            f"Expected items error, got: {errors}"
        )

    def test_unknown_racs_version_rejected(self):
        """Non-string/empty racs_version must fail (audit #4, regression #7)."""
        env = make_envelope(racs_version="")
        errors = ev.validate_envelope(env)
        assert any("racs_version" in e for e in errors), (
            f"Expected racs_version error, got: {errors}"
        )

    def test_structural_only_accepts_empty_contexts(self):
        """governance_complete=False parses structure without requiring contexts.

        Distinct from governance-complete validation: callers must not treat
        this as admissibility readiness (audit #4).
        """
        env = make_envelope(authority_context={}, policy_context={}, evidence_package={})
        errors = ev.validate_envelope(env, governance_complete=False)
        assert errors == [], f"Expected no structural errors, got: {errors}"

    def test_valid_with_optional_fields(self):
        """Envelope with all optional fields passes."""
        env = make_envelope(
            risk_context={"level": "low", "assessment": {}},
            expires_at="2026-07-13T13:00:00Z",
        )
        errors = ev.validate_envelope(env)
        assert errors == [], f"Expected no errors, got: {errors}"

    def test_missing_required_field(self):
        """Missing required field produces error."""
        env = make_envelope()
        del env["action_id"]
        errors = ev.validate_envelope(env)
        assert any("action_id" in e for e in errors), f"Expected action_id error, got: {errors}"

    def test_null_required_field(self):
        """Null value for required field produces error."""
        env = make_envelope(action_id=None)  # type: ignore[arg-type]
        errors = ev.validate_envelope(env)
        assert any("action_id" in e for e in errors), f"Expected action_id error, got: {errors}"

    def test_empty_string_field(self):
        """Empty string for action_id produces error."""
        env = make_envelope(action_id="")
        errors = ev.validate_envelope(env)
        assert any("action_id" in e for e in errors), f"Expected action_id error, got: {errors}"

    def test_wrong_type_field(self):
        """Non-string racs_version produces error."""
        env = make_envelope(racs_version=123)
        errors = ev.validate_envelope(env)
        assert any("racs_version" in e for e in errors), f"Expected racs_version error, got: {errors}"

    def test_invalid_datetime_created_at(self):
        """Invalid datetime for created_at produces error."""
        env = make_envelope(created_at="not-a-datetime")
        errors = ev.validate_envelope(env)
        assert any("created_at" in e for e in errors), f"Expected created_at error, got: {errors}"

    def test_invalid_datetime_expires_at(self):
        """Invalid datetime for expires_at produces error."""
        env = make_envelope(expires_at="bad-date")
        errors = ev.validate_envelope(env)
        assert any("expires_at" in e for e in errors), f"Expected expires_at error, got: {errors}"

    def test_null_expires_at_valid(self):
        """Null expires_at is valid (optional field)."""
        env = make_envelope(expires_at=None)
        errors = ev.validate_envelope(env)
        assert errors == [], f"Expected no errors, got: {errors}"

    def test_missing_actor_fields(self):
        """Actor missing required fields produces error."""
        env = make_envelope(actor={"id": "test"})  # missing role
        errors = ev.validate_envelope(env)
        assert any("actor.role" in e for e in errors), f"Expected actor.role error, got: {errors}"

    def test_missing_target_fields(self):
        """Target missing required fields produces error."""
        env = make_envelope(target={"id": "test"})  # missing type
        errors = ev.validate_envelope(env)
        assert any("target.type" in e for e in errors), f"Expected target.type error, got: {errors}"

    def test_missing_requested_effect_description(self):
        """Requested effect missing description produces error."""
        env = make_envelope(requested_effect={"parameters": {}})
        errors = ev.validate_envelope(env)
        assert any("requested_effect.description" in e for e in errors)

    def test_extra_fields_detected(self):
        """Unexpected top-level fields produce errors in strict mode."""
        env = make_envelope(extra_field="should not be here")
        errors = ev.validate_envelope(env, strict=True)
        assert any("extra field" in e for e in errors)

    def test_invalid_actor_type(self):
        """Non-dict actor produces error."""
        env = make_envelope(actor="not-a-dict")
        errors = ev.validate_envelope(env)
        assert any("actor" in e for e in errors)

    @pytest.mark.parametrize(
        "example_name",
        ["energy-grid.yaml", "financial.yaml", "medical.yaml"],
    )
    def test_example_files_pass(self, example_name):
        """All three example files must pass validation."""
        import yaml
        path = EXAMPLES_DIR / example_name
        with open(path) as fh:
            data = yaml.safe_load(fh)
        errors = ev.validate_envelope(data)
        assert errors == [], f"{example_name} failed: {errors}"


class TestPolicyValidator:
    """Tests for policy_validator.validate_policy_context()."""

    def test_valid_minimal(self):
        """Minimal valid policy context passes."""
        data = {
            "policy_id": "pol-001",
            "policy_set_ref": "racs.policy.test",
            "policy_set_version": "1.0.0",
            "evaluation_mode": "strict",
            "valid_from": "2026-01-01T00:00:00Z",
        }
        errors = pv.validate_policy_context(data)
        assert errors == []

    def test_missing_required(self):
        """Missing required field produces error."""
        data = {"policy_id": "pol-001"}
        errors = pv.validate_policy_context(data)
        assert len(errors) >= 1

    def test_invalid_evaluation_mode(self):
        """Invalid evaluation_mode produces error."""
        data = {
            "policy_id": "pol-001",
            "policy_set_ref": "racs.policy.test",
            "policy_set_version": "1.0.0",
            "evaluation_mode": "invalid_mode",
            "valid_from": "2026-01-01T00:00:00Z",
        }
        errors = pv.validate_policy_context(data)
        assert any("evaluation_mode" in e for e in errors)

    def test_invalid_rule_effect(self):
        """Invalid rule effect produces error."""
        data = {
            "policy_id": "pol-001",
            "policy_set_ref": "racs.policy.test",
            "policy_set_version": "1.0.0",
            "evaluation_mode": "strict",
            "valid_from": "2026-01-01T00:00:00Z",
            "rules": [{"rule_id": "r1", "effect": "INVALID_EFFECT"}],
        }
        errors = pv.validate_policy_context(data)
        assert any("effect" in e for e in errors)

    def test_rule_missing_rule_id(self):
        """Rule missing rule_id produces error."""
        data = {
            "policy_id": "pol-001",
            "policy_set_ref": "racs.policy.test",
            "policy_set_version": "1.0.0",
            "evaluation_mode": "strict",
            "valid_from": "2026-01-01T00:00:00Z",
            "rules": [{"effect": "ALLOW"}],
        }
        errors = pv.validate_policy_context(data)
        assert any("rule_id" in e for e in errors)


class TestEvidenceValidator:
    """Tests for evidence_validator.validate_evidence_package()."""

    def test_valid_minimal(self):
        """Minimal valid evidence package passes."""
        data = {
            "evidence_id": "ev-001",
            "package_type": "observation",
            "producer": {"id": "comp:test", "system": "BARO"},
            "items": [
                {
                    "item_id": "item-001",
                    "fact_type": "observation",
                    "value": {"result": "ok"},
                }
            ],
            "integrity": {
                "signed_digest": "abc123",
                "algorithm": "sha256",
            },
            "created_at": "2026-07-13T12:00:00Z",
        }
        errors = eidv.validate_evidence_package(data)
        assert errors == []

    def test_missing_required(self):
        """Missing required fields produce errors."""
        data = {"evidence_id": "ev-001"}
        errors = eidv.validate_evidence_package(data)
        assert len(errors) >= 1

    def test_invalid_package_type(self):
        """Invalid package_type produces error."""
        data = {
            "evidence_id": "ev-001",
            "package_type": "nonexistent_type",
            "producer": {"id": "comp:test", "system": "BARO"},
            "items": [{"item_id": "i1", "fact_type": "obs", "value": {}}],
            "integrity": {"signed_digest": "abc", "algorithm": "sha256"},
            "created_at": "2026-07-13T12:00:00Z",
        }
        errors = eidv.validate_evidence_package(data)
        assert any("package_type" in e for e in errors)

    def test_empty_items_list(self):
        """Empty items list produces error."""
        data = {
            "evidence_id": "ev-001",
            "package_type": "observation",
            "producer": {"id": "comp:test", "system": "BARO"},
            "items": [],
            "integrity": {"signed_digest": "abc", "algorithm": "sha256"},
            "created_at": "2026-07-13T12:00:00Z",
        }
        errors = eidv.validate_evidence_package(data)
        assert any("items" in e for e in errors)

    def test_missing_integrity_fields(self):
        """Integrity missing required signed_digest."""
        data = {
            "evidence_id": "ev-001",
            "package_type": "observation",
            "producer": {"id": "comp:test", "system": "BARO"},
            "items": [{"item_id": "i1", "fact_type": "obs", "value": {}}],
            "integrity": {"algorithm": "sha256"},
            "created_at": "2026-07-13T12:00:00Z",
        }
        errors = eidv.validate_evidence_package(data)
        assert any("signed_digest" in e for e in errors)

    def test_missing_producer_fields(self):
        """Producer missing required fields."""
        data = {
            "evidence_id": "ev-001",
            "package_type": "observation",
            "producer": {"system": "BARO"},  # missing id
            "items": [{"item_id": "i1", "fact_type": "obs", "value": {}}],
            "integrity": {"signed_digest": "abc", "algorithm": "sha256"},
            "created_at": "2026-07-13T12:00:00Z",
        }
        errors = eidv.validate_evidence_package(data)
        assert any("producer.id" in e for e in errors)

    def test_invalid_confidence(self):
        """Confidence outside 0-1 range produces error."""
        data = {
            "evidence_id": "ev-001",
            "package_type": "observation",
            "producer": {"id": "comp:test", "system": "BARO"},
            "items": [
                {
                    "item_id": "i1",
                    "fact_type": "obs",
                    "value": {},
                    "confidence": 1.5,  # invalid
                }
            ],
            "integrity": {"signed_digest": "abc", "algorithm": "sha256"},
            "created_at": "2026-07-13T12:00:00Z",
        }
        errors = eidv.validate_evidence_package(data)
        assert any("confidence" in e for e in errors)


class TestCliIntegration:
    """Integration tests for CLI invocation of validators."""

    def test_envelope_cli_valid(self, tmp_path: Path):
        """CLI exits 0 for valid envelope."""
        env = make_envelope()
        path = tmp_path / "valid.json"
        with open(path, "w") as fh:
            json.dump(env, fh)
        ret = os.system(f"{sys.executable} validators/envelope_validator.py {path}")
        assert ret == 0, "CLI should exit 0 for valid envelope"

    def test_envelope_cli_invalid(self, tmp_path: Path):
        """CLI exits non-zero for invalid envelope."""
        env = make_envelope()
        del env["action_id"]
        path = tmp_path / "invalid.json"
        with open(path, "w") as fh:
            json.dump(env, fh)
        ret = os.system(f"{sys.executable} validators/envelope_validator.py {path}")
        assert ret != 0, "CLI should exit non-zero for invalid envelope"

    def test_envelope_cli_missing_file(self):
        """CLI exits 2 for missing file."""
        ret = os.system(f"{sys.executable} validators/envelope_validator.py /nonexistent/path.yaml")
        assert ret != 0, "CLI should exit non-zero for missing file"
