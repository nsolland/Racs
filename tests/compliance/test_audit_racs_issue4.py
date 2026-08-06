"""Regression tests for the governance-context fix from RACS issue #4.

These tests assert the repaired behavior against the **canonical v0.2
contract**. They deliberately use an otherwise governance-complete envelope so
every failure is attributable to the field under test rather than to unrelated
empty contexts.
"""

import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.compliance.test_racs_compliance import make_envelope  # noqa: E402
from validators import envelope_validator as ev  # noqa: E402


def assert_error(errors: list[str], field: str) -> None:
    assert any(field in error for error in errors), (
        f"expected an error for {field}, got: {errors}"
    )


def test_missing_authority_grant_ref_is_rejected():
    env = make_envelope()
    del env["authority_grant_ref"]
    assert_error(ev.validate_envelope(env), "authority_grant_ref")


def test_missing_policy_ref_is_rejected():
    env = make_envelope()
    del env["policy_ref"]
    assert_error(ev.validate_envelope(env), "policy_ref")


def test_missing_evidence_package_ref_is_rejected():
    env = make_envelope()
    del env["evidence_package_ref"]
    assert_error(ev.validate_envelope(env), "evidence_package_ref")


def test_authority_grant_ref_without_identity_is_rejected():
    """Authority must be explicit; an empty grant ref is not authority."""
    env = make_envelope(authority_grant_ref="")
    assert_error(ev.validate_envelope(env), "authority_grant_ref")


def test_policy_ref_without_identity_and_version_is_rejected():
    """Policy must be traceable; an empty policy ref is not policy."""
    env = make_envelope(policy_ref="")
    assert_error(ev.validate_envelope(env), "policy_ref")


def test_evidence_package_ref_without_items_and_integrity_is_rejected():
    """Evidence must be bound; an empty evidence ref is not evidence."""
    env = make_envelope(evidence_package_ref="")
    assert_error(ev.validate_envelope(env), "evidence_package_ref")


def test_legacy_racs_version_field_is_rejected():
    """The canonical v0.2 envelope has no racs_version; legacy field fails."""
    env = make_envelope(racs_version="")
    assert_error(ev.validate_envelope(env), "racs_version")


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

    # Missing required fields fail in both modes (schema-driven). The mode only
    # governs the added governance rules (placeholder digests), not structure.
    env = make_envelope()
    del env["action_id"]
    assert ev.validate_envelope(env)
    assert ev.validate_envelope(env, governance_complete=False)


def test_unknown_legacy_racs_version_rejected():
    """A legacy envelope shape is rejected by the canonical v0.2 schema."""
    env = make_envelope(racs_version="not-a-real-version")
    assert_error(ev.validate_envelope(env), "racs_version")


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
