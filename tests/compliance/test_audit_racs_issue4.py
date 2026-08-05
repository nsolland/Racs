"""Regression tests for the governance-context fix from RACS issue #4.

These tests assert the repaired behavior.  They deliberately use an otherwise
governance-complete envelope so every failure is attributable to the field
under test rather than to unrelated empty contexts.
"""

import inspect
import sys
from pathlib import Path

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
                {
                    "item_id": "item-001",
                    "fact_type": "observation",
                    "value": {"result": "ok"},
                }
            ],
            "integrity": {"signed_digest": "abc123", "algorithm": "sha256"},
            "created_at": "2026-07-13T12:00:00Z",
        },
        "environment_state": {"snapshot_id": "test-snap-001"},
        "created_at": "2026-07-13T12:00:00Z",
    }
    base.update(overrides)
    return base


def assert_error(errors: list[str], field: str) -> None:
    assert any(field in error for error in errors), (
        f"expected an error for {field}, got: {errors}"
    )


def test_empty_authority_context_is_rejected():
    assert_error(ev.validate_envelope(make_envelope(authority_context={})), "authority_context")


def test_empty_policy_context_is_rejected():
    assert_error(ev.validate_envelope(make_envelope(policy_context={})), "policy_context")


def test_empty_evidence_package_is_rejected():
    assert_error(ev.validate_envelope(make_envelope(evidence_package={})), "evidence_package")


def test_authority_context_without_authority_id_is_rejected():
    errors = ev.validate_envelope(
        make_envelope(
            authority_context={
                "authorizing_entity": {"id": "org:test", "role": "operator"},
                "authority_type": "direct",
            }
        )
    )
    assert_error(errors, "authority_context.authority_id")


def test_policy_context_without_identity_and_version_is_rejected():
    errors = ev.validate_envelope(
        make_envelope(
            policy_context={
                "policy_set_ref": "racs.policy.test",
                "evaluation_mode": "strict",
                "valid_from": "2026-01-01T00:00:00Z",
            }
        )
    )
    assert_error(errors, "policy_id")
    assert_error(errors, "policy_set_version")


def test_evidence_package_without_items_and_integrity_is_rejected():
    errors = ev.validate_envelope(
        make_envelope(
            evidence_package={
                "evidence_id": "ev-001",
                "package_type": "observation",
                "producer": {"id": "comp:test", "system": "BARO"},
                "created_at": "2026-07-13T12:00:00Z",
            }
        )
    )
    assert_error(errors, "items")
    assert_error(errors, "integrity")


def test_empty_racs_version_is_rejected():
    assert_error(ev.validate_envelope(make_envelope(racs_version="")), "racs_version")


def test_expiry_is_structurally_validated_without_wall_clock_policy():
    errors = ev.validate_envelope(make_envelope(expires_at="not-a-datetime"))
    assert_error(errors, "expires_at")

    # This package validates the versioned document structure. Runtime
    # admissibility code, not this deterministic validator, applies wall time.
    assert ev.validate_envelope(
        make_envelope(
            created_at="2020-01-01T00:00:00Z",
            expires_at="2020-01-02T00:00:00Z",
        )
    ) == []


def test_governance_complete_mode_exists_and_defaults_on():
    parameter = inspect.signature(ev.validate_envelope).parameters["governance_complete"]
    assert parameter.default is True

    envelope = make_envelope(
        authority_context={}, policy_context={}, evidence_package={}
    )
    assert ev.validate_envelope(envelope)
    assert ev.validate_envelope(envelope, governance_complete=False) == []


def test_unknown_racs_version_rejected_in_governance_complete():
    errors = ev.validate_envelope(make_envelope(racs_version="not-a-real-version"))
    assert_error(errors, "racs_version")
    # Disabled in structural-only mode: version vocabulary is a governance rule.
    assert ev.validate_envelope(
        make_envelope(racs_version="not-a-real-version"), governance_complete=False
    ) == []


def test_admissibility_expiry_rejects_expired_envelope():
    from datetime import datetime, timezone

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    env = make_envelope(
        created_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-02T00:00:00Z",
    )
    errors = ev.check_admissibility_expiry(env, now)
    assert any("expires_at" in e for e in errors)


def test_admissibility_expiry_allows_valid_envelope():
    from datetime import datetime, timezone

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    env = make_envelope(expires_at="2026-12-31T00:00:00Z")
    assert ev.check_admissibility_expiry(env, now) == []


def test_placeholder_digest_rejected_in_governance_complete():
    zero = "sha256:" + "0" * 64
    env = make_envelope(payload_digest=zero)
    errors = ev.validate_envelope(env)
    assert any("placeholder" in e for e in errors)
    # Structural-only mode does not enforce digest authenticity.
    structural = ev.validate_envelope(env, governance_complete=False)
    assert not any("placeholder" in e for e in structural)
