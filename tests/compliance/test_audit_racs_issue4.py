"""Audit test for Racs #4 (nsolland/Racs, main @ a84b9cbd).

Confirms: an Action Envelope is accepted even when authority_context,
policy_context and evidence_package are EMPTY objects ({}). The envelope
validator only checks `isinstance(dict)` for these fields and never calls the
nested policy/evidence/authority validators, so a packet with no authority ID,
no delegation chain, no policy ID/version, no evidence content, no integrity
proof, and no purpose/mandate reference passes as "valid".

Run from repo root:
    pytest tests/compliance/test_audit_racs_issue4.py -v

NOTE: each test below asserts the DEFECT is present (the validator returns no
error for input that should be rejected). "passed" == "vulnerability reproduced".
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from validators import envelope_validator as ev  # noqa: E402


def make_envelope(**overrides) -> dict:
    base = {
        "racs_version": "0.1",
        "action_id": "test-ae-001",
        "action_type": "test_action",
        "actor": {"id": "actor:test", "role": "test_agent"},
        "target": {"id": "target:test", "type": "test_resource"},
        "requested_effect": {"description": "Test effect"},
        "authority_context": {},
        "policy_context": {},
        "evidence_package": {},
        "environment_state": {"snapshot_id": "test-snap-001"},
        "created_at": "2026-07-13T12:00:00Z",
    }
    base.update(overrides)
    return base


# --- STEP 1-3: empty context objects are accepted -------------------------

def test_step1_empty_authority_context():
    env = make_envelope(authority_context={})
    errors = ev.validate_envelope(env)
    assert errors == [], f"BUG: empty authority_context should fail, got: {errors}"


def test_step2_empty_policy_context():
    env = make_envelope(policy_context={})
    errors = ev.validate_envelope(env)
    assert errors == [], f"BUG: empty policy_context should fail, got: {errors}"


def test_step3_empty_evidence_package():
    env = make_envelope(evidence_package={})
    errors = ev.validate_envelope(env)
    assert errors == [], f"BUG: empty evidence_package should fail, got: {errors}"


# --- STEP 4-6: missing required sub-fields are NOT caught ------------------

def test_step4_missing_authority_id():
    # authority_context present but NO authority_id (and no delegation chain)
    env = make_envelope(authority_context={"role": "operator"})
    errors = ev.validate_envelope(env)
    assert errors == [], f"BUG: authority_context without authority_id should fail, got: {errors}"


def test_step5_missing_policy_id_version():
    # policy_context present but NO policy_id / policy_set_version
    env = make_envelope(policy_context={"evaluation_mode": "strict"})
    errors = ev.validate_envelope(env)
    assert errors == [], f"BUG: policy_context without policy_id/version should fail, got: {errors}"


def test_step6_empty_evidence_items():
    # evidence_package present but NO items, NO integrity proof
    env = make_envelope(evidence_package={"producer": {"id": "x", "system": "BARO"}})
    errors = ev.validate_envelope(env)
    assert errors == [], f"BUG: evidence_package without items/integrity should fail, got: {errors}"


# --- STEP 7: unknown racs_version accepted if it is text ------------------

def test_step7_unknown_racs_version():
    env = make_envelope(racs_version="not-a-real-version")
    errors = ev.validate_envelope(env)
    assert errors == [], f"BUG: unknown racs_version should fail, got: {errors}"


# --- STEP 8: expiry not checked (no governance-complete mode exists) ------

def test_step8_expired_envelope_not_rejected():
    # There is NO governance-complete / strict-expiry mode in the validator.
    # An envelope expired long ago is still accepted.
    env = make_envelope(
        created_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-02T00:00:00Z",  # long expired
    )
    errors = ev.validate_envelope(env)
    assert errors == [], f"BUG: expired envelope should fail in governance-complete mode, got: {errors}"


def test_step8_no_governance_complete_mode():
    """Document that validate_envelope has no governance-complete / expiry mode."""
    import inspect
    sig = inspect.signature(ev.validate_envelope)
    assert "governance_complete" not in sig.parameters, (
        "Unexpected: a governance_complete mode now exists"
    )
    print("[OBSERVED] validate_envelope has no governance_complete/expiry mode; "
          "expired packets pass unchallenged.")
