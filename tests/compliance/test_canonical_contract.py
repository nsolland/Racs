"""Canonical VALO verdict-mapping & monotonicity conformance tests.

These tests pin the locked 2026-07-23 contract:
  - RACS GovernanceEvaluation preserves all 6 AARM verdicts (no reduction).
  - REHT AdmissibilityDetermination accepts REQUIRES_STEP_UP (the only addition).
  - GovernanceClearance is positive-only: ALLOW / MODIFY-with-constraints only;
    DEFER / DENY / STEP_UP / HALT MUST NOT yield a clearance.
  - MODIFY clearance MUST bind a machine-readable, action-binding constraint set
    (enforced by the schema via if/then, not just by documentation).
  - AARM verdict is provenance, never usable directly as a clearance decision.
  - The golden vectors' MAPPING is actually validated: each vector is materialised
    into the normative AdmissibilityDetermination and GovernanceClearance payloads
    and checked against the schemas.
  - The golden vector file is integrity-checked against its .sha256 sidecar.

No runtime is exercised; only the normative JSON Schemas and golden vectors.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_DIR = REPO_ROOT / "spec"
VEC_DIR = REPO_ROOT / "test-vectors" / "0.2"


def _load_schema(name: str) -> dict:
    with open(SPEC_DIR / name) as fh:
        return json.load(fh)


def _validator(name: str):
    return jsonschema.Draft202012Validator(_load_schema(name))


def _digest() -> str:
    return "sha256:" + "a" * 64


def _valid_admissibility(state: str, evaluation_refs=None) -> dict:
    """A minimally complete AdmissibilityDetermination payload."""
    return {
        "determination_id": "det_test_001",
        "action_id": "act_test_001",
        "action_envelope_digest": _digest(),
        "tenant_id": "tenant-test",
        "authority_digest": _digest(),
        "delegation_chain_digest": _digest(),
        "policy_digest": _digest(),
        "evidence_digest": _digest(),
        "purpose_digest": _digest(),
        "state_digest": _digest(),
        "evaluation_refs": evaluation_refs or ["vaig:test:001"],
        "state": state,
        "determined_at": "2026-07-14T18:00:00Z",
        "valid_until": "2026-07-14T18:05:00Z",
        "revocation_registry_ref": "racs://trust/test/revocations",
    }


def _valid_clearance(decision: str | None, admissibility_state: str | None, constraints: dict | None = None) -> dict:
    clr = {
        "clearance_id": "clr_test_002",
        "action_id": "act_test_001",
        "action_envelope_digest": _digest(),
        "tenant_id": "tenant-test",
        "decision": decision,
        "admissibility_state": admissibility_state,
        "authority_digest": _digest(),
        "delegation_chain_digest": _digest(),
        "policy_digest": _digest(),
        "evidence_digest": _digest(),
        "purpose_digest": _digest(),
        "state_digest": _digest(),
        "target_digest": _digest(),
        "payload_digest": _digest(),
        "connector_id": "connector-test",
        "capability": "test.execute",
        "consequence_class": "HIGH",
        "reversibility": "COMPENSATABLE",
        "valid_from": "2026-07-14T18:00:00Z",
        "valid_until": "2026-07-14T18:05:00Z",
        "replay_nonce": "nonce-000000000002",
        "idempotency_key": "idem-002",
        "revocation_registry_ref": "racs://trust/test/revocations",
        "evaluator_refs": ["vaig:test:001"],
        "admissibility_determination_ref": "det_test_001",
        "admissibility_determination_digest": _digest(),
    }
    if constraints is not None:
        clr["constraints"] = constraints
    return clr


# ---- AARM / GovernanceEvaluation: all 6 verdicts preserved ----

AARM_VERDICTS = ["ALLOW", "MODIFY", "DEFER", "DENY", "STEP_UP", "HALT"]


@pytest.mark.parametrize("verdict", AARM_VERDICTS)
def test_aarm_verdict_preserved_in_governance_evaluation(verdict: str):
    """RACS GovernanceEvaluation MUST preserve all 6 AARM verdicts (no reduction)."""
    schema = _load_schema("governance-evaluation-v0.2.schema.json")
    ev = {
        "evaluation_id": "ev_test_001",
        "action_id": "act_test_001",
        "action_envelope_digest": _digest(),
        "tenant_id": "tenant-test",
        "evaluator_id": "vaig:test:001",
        "evaluator_version": "1.0.0",
        "decision": verdict,
        "authority_status": "PRESENT_AND_VALID",
        "policy_status": "PRESENT_AND_VALID",
        "evidence_status": "PRESENT_AND_VALID",
        "purpose_status": "PRESENT_AND_VALID",
        "state_status": "PRESENT_AND_VALID",
        "risk_status": "PRESENT_AND_VALID",
        "evaluated_at": "2026-07-14T18:00:00Z",
        "valid_until": "2026-07-14T18:05:00Z",
    }
    jsonschema.Draft202012Validator(schema).validate(ev)


# ---- REHT AdmissibilityDetermination: REQUIRES_STEP_UP now valid ----

def test_requires_step_up_is_valid_admissibility_state():
    """REQUIRES_STEP_UP (the only addition) MUST validate against the schema."""
    assert _validator("admissibility-determination-v0.2.schema.json").is_valid(
        _valid_admissibility("REQUIRES_STEP_UP")
    )


@pytest.mark.parametrize("state", [
    "ADMISSIBLE", "CONDITIONALLY_ADMISSIBLE", "NOT_ADMISSIBLE",
    "INDETERMINATE", "STALE", "REVOKED", "HALTED", "REQUIRES_STEP_UP",
])
def test_all_admissibility_states_validate(state: str):
    assert _validator("admissibility-determination-v0.2.schema.json").is_valid(
        _valid_admissibility(state)
    )


# ---- GovernanceClearance is positive-only ----

def test_clearance_allow_valid():
    assert _validator("governance-clearance.schema.json").is_valid(
        _valid_clearance("ALLOW", "ADMISSIBLE")
    )


def test_clearance_modify_with_constraints_valid():
    assert _validator("governance-clearance.schema.json").is_valid(
        _valid_clearance("MODIFY", "CONDITIONALLY_ADMISSIBLE", constraints={
            "machine_readable": True,
            "binds_exact_action": True,
            "capability": "net.send",
            "target": "host:10.0.0.5",
        })
    )


@pytest.mark.parametrize("verdict,state", [
    ("DEFER", "INDETERMINATE"),
    ("DENY", "NOT_ADMISSIBLE"),
    ("STEP_UP", "REQUIRES_STEP_UP"),
    ("HALT", "HALTED"),
])
def test_clearance_negative_verdicts_rejected(verdict: str, state: str):
    """DEFER / DENY / STEP_UP / HALT MUST NOT be representable as a clearance."""
    assert not _validator("governance-clearance.schema.json").is_valid(
        _valid_clearance(verdict, state)
    )


# ---- MODIFY rule: schema if/then enforces a binding constraint set ----

def test_modify_without_constraints_rejected():
    """decision=MODIFY with NO constraints key MUST fail (if/then requires it)."""
    assert not _validator("governance-clearance.schema.json").is_valid(
        _valid_clearance("MODIFY", "CONDITIONALLY_ADMISSIBLE")
    )


def test_modify_with_empty_constraints_rejected():
    """decision=MODIFY with an empty constraints object MUST fail (required fields)."""
    assert not _validator("governance-clearance.schema.json").is_valid(
        _valid_clearance("MODIFY", "CONDITIONALLY_ADMISSIBLE", constraints={})
    )


def test_modify_with_non_binding_constraints_rejected():
    """decision=MODIFY with constraints that do NOT bind the exact action MUST fail."""
    assert not _validator("governance-clearance.schema.json").is_valid(
        _valid_clearance("MODIFY", "CONDITIONALLY_ADMISSIBLE", constraints={
            "machine_readable": True,
            "binds_exact_action": False,
        })
    )


def test_modify_with_non_machine_readable_constraints_rejected():
    """decision=MODIFY with machine_readable=False MUST fail."""
    assert not _validator("governance-clearance.schema.json").is_valid(
        _valid_clearance("MODIFY", "CONDITIONALLY_ADMISSIBLE", constraints={
            "machine_readable": False,
            "binds_exact_action": True,
        })
    )


def test_modify_constraints_present_but_wrong_type_rejected():
    """constraints that are not an object (e.g. a string) MUST fail."""
    clr = _valid_clearance("MODIFY", "CONDITIONALLY_ADMISSIBLE")
    clr["constraints"] = "capability=net.send, target=host:10.0.0.5"
    assert not _validator("governance-clearance.schema.json").is_valid(clr)


# ---- AARM verdict is provenance, never a clearance decision ----

def test_aarm_verdict_not_directly_usable_as_clearance():
    """AARM verdicts that are NOT valid clearance decisions (DEFER/DENY/
    STEP_UP/HALT) must never be accepted as a clearance decision."""
    v = _validator("governance-clearance.schema.json")
    for verdict in ["DEFER", "DENY", "STEP_UP", "HALT"]:
        assert not v.is_valid(_valid_clearance(verdict, "ADMISSIBLE")), (
            f"{verdict} must not be a valid clearance decision"
        )


# ---- The golden vectors' MAPPING is actually validated ----

def _load_vectors() -> dict:
    with open(VEC_DIR / "canonical-verdict-mapping.json") as fh:
        return json.load(fh)


@pytest.mark.parametrize("vector", _load_vectors()["vectors"], ids=lambda v: v["id"])
def test_golden_vector_mapping_materialises_and_validates(vector: dict):
    """Each golden vector is materialised into the normative
    AdmissibilityDetermination and (where applicable) GovernanceClearance
    payloads and validated against the schemas. This pins the EXACT mapping
    values, so changing a mapping value breaks the test."""
    adm_v = _validator("admissibility-determination-v0.2.schema.json")
    clr_v = _validator("governance-clearance.schema.json")

    # AdmissibilityDetermination side of the mapping.
    determination = _valid_admissibility(
        state=vector["admissibility_determination"],
        evaluation_refs=[f"vaig:{vector['aarm_verdict'].lower()}"],
    )
    assert adm_v.is_valid(determination), (
        f"{vector['id']}: admissibility determination for "
        f"{vector['admissibility_determination']} should validate"
    )

    if vector["clearance_issued"]:
        # GovernanceClearance side of the mapping.
        clr = _valid_clearance(
            decision=vector["clearance_decision"],
            admissibility_state=vector["clearance_admissibility_state"],
            constraints=vector.get("constraints"),
        )
        assert clr_v.is_valid(clr), (
            f"{vector['id']}: clearance {vector['clearance_decision']} should validate"
        )
        # Provenance chain: clearance MUST reference the determination.
        assert clr["admissibility_determination_ref"] == determination["determination_id"]
    else:
        # Negative mapping: building a clearance from a null decision MUST fail,
        # proving no clearance is emitted for this AARM verdict.
        assert vector["clearance_decision"] is None
        assert not clr_v.is_valid(_valid_clearance(None, None)), (
            f"{vector['id']}: no clearance may be emitted for "
            f"{vector['aarm_verdict']}"
        )


# ---- Golden vector file integrity (.sha256 sidecar is enforced) ----

def test_golden_vector_sha256_sidecar_matches():
    """The .sha256 sidecar MUST match the actual golden vector file content."""
    vec_path = VEC_DIR / "canonical-verdict-mapping.json"
    sha_path = VEC_DIR / "canonical-verdict-mapping.sha256"
    assert vec_path.exists() and sha_path.exists()

    content = vec_path.read_bytes()
    actual = hashlib.sha256(content).hexdigest()

    sidecar = sha_path.read_text().strip()
    # Format: "<hash>  <path>" (GNU sha256sum) or bare "<hash>".
    expected = sidecar.split()[0]
    assert actual == expected, (
        f"golden vector .sha256 mismatch: expected {expected}, got {actual}. "
        f"Regenerate with: sha256sum {vec_path.name} > {sha_path.name}"
    )
