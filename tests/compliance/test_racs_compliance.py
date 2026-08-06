"""RACS compliance tests — envelope, policy, evidence and CLI.

The envelope validator is schema-driven against the canonical v0.2 contract,
so these tests build **v0.2 envelopes** (refs-based, with boundary_requirements)
and preserve the audit #4 regression intent: governance contexts must be
explicit, required fields must be present and well-typed, and placeholder
digests are rejected in governance-complete mode.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Ensure validators/ is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from validators import envelope_validator as ev
from validators import policy_validator as pv
from validators import evidence_validator as eidv

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples"


def _digest(seed: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def make_envelope(**overrides) -> dict:
    """Create a minimal valid v0.2 envelope dict, with optional overrides.

    The base envelope is governance-complete: every required ref and the
    boundary requirements are present and well-formed. Override with ``None``,
    empty strings or missing fields to test rejection.
    """
    now = datetime.now(timezone.utc)
    digest = _digest("envelope:test")
    base = {
        "action_id": "test-ae-001",
        "tenant_id": "tenant:test",
        "action_type": "test_action",
        "actor_ref": "authority:actor/test",
        "target_ref": "target:test",
        "target_digest": digest,
        "payload_digest": digest,
        "authority_grant_ref": "authority-grant:test",
        "delegation_chain_ref": "delegation:test",
        "policy_ref": "policy:test",
        "evidence_package_ref": "evidence-package:test",
        "purpose_ref": "purpose:test",
        "environment_state_ref": "environment-state:test",
        "risk_context_ref": "risk-context:test",
        "connector_id": "connector:test",
        "capability": "secrets.write",
        "consequence_class": "HIGH",
        "reversibility": "COMPENSATABLE",
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "replay_nonce": "nonce-test-abcdef0123456789",
        "idempotency_key": "idem-test-xyz",
        "boundary_requirements": {
            "required_types": ["EXECUTION"],
            "policy_ref": "policy:test",
            "policy_digest": digest,
            "fail_closed": True,
        },
    }
    base.update(overrides)
    return base


# ---- Envelope Validator Tests (canonical v0.2 contract) ----


class TestEnvelopeValidator:
    """Tests for envelope_validator.validate_envelope()."""

    def test_valid_minimal(self):
        """Minimal valid v0.2 envelope passes."""
        env = make_envelope()
        errors = ev.validate_envelope(env)
        assert errors == [], f"Expected no errors, got: {errors}"

    # ---- Audit #4 regression: governance context must be explicit ----

    def test_missing_authority_grant_ref_rejected(self):
        """Missing authority_grant_ref must fail (audit #4 regression)."""
        env = make_envelope()
        del env["authority_grant_ref"]
        errors = ev.validate_envelope(env)
        assert any("authority_grant_ref" in e for e in errors), (
            f"Expected authority_grant_ref error, got: {errors}"
        )

    def test_missing_policy_ref_rejected(self):
        """Missing policy_ref must fail (audit #4 regression)."""
        env = make_envelope()
        del env["policy_ref"]
        errors = ev.validate_envelope(env)
        assert any("policy_ref" in e for e in errors), (
            f"Expected policy_ref error, got: {errors}"
        )

    def test_missing_evidence_package_ref_rejected(self):
        """Missing evidence_package_ref must fail (audit #4 regression)."""
        env = make_envelope()
        del env["evidence_package_ref"]
        errors = ev.validate_envelope(env)
        assert any("evidence_package_ref" in e for e in errors), (
            f"Expected evidence_package_ref error, got: {errors}"
        )

    def test_empty_boundary_policy_ref_rejected(self):
        """boundary_requirements.policy_ref must be present (audit #4)."""
        env = make_envelope()
        env["boundary_requirements"] = {
            "required_types": ["EXECUTION"],
            "policy_digest": _digest("policy"),
            "fail_closed": True,
        }
        errors = ev.validate_envelope(env)
        assert any("policy_ref" in e for e in errors)

    def test_fail_closed_required_in_boundary(self):
        """boundary_requirements must demand fail_closed=true (audit #4)."""
        env = make_envelope()
        env["boundary_requirements"] = {
            "required_types": ["EXECUTION"],
            "policy_ref": "policy:test",
            "policy_digest": _digest("policy"),
            "fail_closed": False,
        }
        errors = ev.validate_envelope(env)
        assert any("fail_closed" in e for e in errors)

    def test_legacy_envelope_rejected(self):
        """A pre-v0.2 envelope (racs_version/actor) must fail (drift gate)."""
        env = make_envelope()
        env["racs_version"] = "0.1"
        env["actor"] = {"id": "actor:test", "role": "test_agent"}
        errors = ev.validate_envelope(env)
        assert errors, "legacy envelope must be rejected"
        assert any("racs_version" in e or "actor" in e for e in errors)

    def test_structural_mode_still_enforces_schema(self):
        """governance_complete=False is still schema-driven (audit #4)."""
        env = make_envelope()
        del env["action_id"]
        errors = ev.validate_envelope(env, governance_complete=False)
        assert errors, "missing required field must fail even in structural mode"

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
        """Non-string action_id produces error."""
        env = make_envelope(action_id=123)  # type: ignore[arg-type]
        errors = ev.validate_envelope(env)
        assert any("action_id" in e for e in errors), f"Expected action_id error, got: {errors}"

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

    def test_null_expires_at_fails(self):
        """expires_at is required in v0.2; null must fail."""
        env = make_envelope(expires_at=None)  # type: ignore[arg-type]
        errors = ev.validate_envelope(env)
        assert any("expires_at" in e for e in errors), (
            f"Expected expires_at error, got: {errors}"
        )

    def test_empty_actor_ref_rejected(self):
        """actor_ref must be a non-empty string."""
        env = make_envelope(actor_ref="")
        errors = ev.validate_envelope(env)
        assert any("actor_ref" in e for e in errors), f"Expected actor_ref error, got: {errors}"

    def test_empty_target_ref_rejected(self):
        """target_ref must be a non-empty string."""
        env = make_envelope(target_ref="")
        errors = ev.validate_envelope(env)
        assert any("target_ref" in e for e in errors), f"Expected target_ref error, got: {errors}"

    def test_invalid_target_digest_rejected(self):
        """target_digest must be a real sha256 binding."""
        env = make_envelope(target_digest="abc123")
        errors = ev.validate_envelope(env)
        assert any("target_digest" in e for e in errors)

    def test_extra_fields_detected(self):
        """Unexpected top-level fields produce errors (additionalProperties=false)."""
        env = make_envelope(extra_field="should not be here")
        errors = ev.validate_envelope(env, strict=True)
        assert any("extra_field" in e for e in errors)

    @pytest.mark.parametrize(
        "example_name",
        ["energy-grid.yaml", "financial.yaml", "medical.yaml"],
    )
    def test_example_files_pass(self, example_name):
        """All three example files must pass validation as v0.2 envelopes."""
        if yaml is None:
            pytest.skip("PyYAML not installed")
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
        ret = os.system(f"PYTHONPATH=. {sys.executable} validators/envelope_validator.py {path}")
        assert ret == 0, "CLI should exit 0 for valid envelope"

    def test_envelope_cli_invalid(self, tmp_path: Path):
        """CLI exits non-zero for invalid envelope."""
        env = make_envelope()
        del env["action_id"]
        path = tmp_path / "invalid.json"
        with open(path, "w") as fh:
            json.dump(env, fh)
        ret = os.system(f"PYTHONPATH=. {sys.executable} validators/envelope_validator.py {path}")
        assert ret != 0, "CLI should exit non-zero for invalid envelope"

    def test_envelope_cli_missing_file(self):
        """CLI exits 2 for missing file."""
        ret = os.system(f"PYTHONPATH=. {sys.executable} validators/envelope_validator.py /nonexistent/path.yaml")
        assert ret != 0, "CLI should exit non-zero for missing file"
