"""Canonical-contract drift detection (regression gate for RACS validators).

The shipped CLI validators must enforce the *normative* spec contracts, not a
superseded shape. These tests pin the envelope validator to the canonical v0.2
schema and fail loudly if it ever drifts again — a valid v0.2 envelope must
pass, and the legacy (pre-v0.2) shape must be rejected.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from validators import envelope_validator as ev

LEGACY_ENVELOPE = {
    "racs_version": "0.1",
    "action_id": "act-1",
    "action_type": "write",
    "actor": {"id": "actor:test", "role": "test_agent"},
    "target": {"id": "resource:test", "type": "file"},
    "requested_effect": {"type": "write", "scope": "secrets"},
    "authority_context": {
        "authority_id": "auth-1",
        "authorizing_entity": {"id": "org:test", "role": "owner"},
        "authority_type": "direct",
    },
    "policy_context": {"policy_id": "pol-1", "evaluation_mode": "strict"},
    "evidence_package": {"evidence_items": []},
    "environment_state": {"mode": "normal"},
    "created_at": "2026-01-01T00:00:00Z",
}


def _v02_envelope() -> dict:
    now = datetime.now(timezone.utc)
    digest = "sha256:" + "a" * 64
    return {
        "action_id": "act-1",
        "tenant_id": "tenant:test",
        "action_type": "write",
        "actor_ref": "authority:actor/test",
        "target_ref": "resource:test",
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
        "replay_nonce": "nonce-0001-abcdef0123456789",
        "idempotency_key": "idem-0001-xyz",
        "boundary_requirements": {
            "required_types": ["EXECUTION"],
            "policy_ref": "policy:test",
            "policy_digest": digest,
            "fail_closed": True,
        },
    }


def test_canonical_v02_envelope_passes_validator():
    envelope = _v02_envelope()
    errors = ev.validate_envelope(envelope)
    assert errors == [], f"v0.2 envelope must validate, got: {errors}"


def test_legacy_envelope_is_rejected():
    errors = ev.validate_envelope(dict(LEGACY_ENVELOPE))
    assert errors, "legacy pre-v0.2 envelope must be rejected by the validator"
    joined = "; ".join(errors)
    assert "additionalProperties" in joined or "extra field" in joined or "racs_version" in joined


def test_zero_digest_rejected_in_governance_complete():
    envelope = _v02_envelope()
    envelope["payload_digest"] = "sha256:" + "0" * 64
    errors = ev.validate_envelope(envelope)
    assert any("payload_digest" in e and "placeholder" in e for e in errors)


def test_validator_matches_golden_vector_schema():
    """The validator's schema file must be the one the golden vectors pin."""
    vectors = json.load(open("spec/golden-vectors.json"))["vectors"]
    envelope_vectors = [
        v for v in vectors.values() if "action-envelope" in v.get("schema", "")
    ]
    assert envelope_vectors, "golden-vectors.json must pin an action-envelope vector"
    pinned_schema = envelope_vectors[0]["schema"]
    assert pinned_schema.endswith("action-envelope-v0.2.schema.json"), (
        f"golden vector pins {pinned_schema}, expected the v0.2 envelope schema"
    )
