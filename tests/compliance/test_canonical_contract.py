"""Canonical verdict, boundary-binding and positive-clearance conformance."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_DIR = REPO_ROOT / "spec"
VEC_DIR = REPO_ROOT / "test-vectors" / "0.2"
DIGEST = "sha256:" + "a" * 64
BOUNDARY_BINDING = {
    "assessment_ref": "bca:test:001",
    "assessment_digest": "sha256:" + "b" * 64,
}
EXPECTED = {
    "ALLOW": ("ADMISSIBLE", "ALLOW", "ADMISSIBLE", True),
    "MODIFY": (
        "CONDITIONALLY_ADMISSIBLE",
        "MODIFY",
        "CONDITIONALLY_ADMISSIBLE",
        True,
    ),
    "DEFER": ("INDETERMINATE", None, None, False),
    "DENY": ("NOT_ADMISSIBLE", None, None, False),
    "STEP_UP": ("REQUIRES_STEP_UP", None, None, False),
    "HALT": ("HALTED", None, None, False),
}


def _load_schema(name: str) -> dict:
    return json.loads((SPEC_DIR / name).read_text(encoding="utf-8"))


def _validator(name: str):
    return jsonschema.Draft202012Validator(_load_schema(name))


def _canonicalize(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(key, ensure_ascii=False) + ":" + _canonicalize(value[key])
            for key in sorted(value)
        ) + "}"
    raise TypeError(type(value))


def _valid_evaluation(decision: str = "ALLOW") -> dict:
    return {
        "evaluation_id": "ev_test_001",
        "action_id": "act_test_001",
        "action_envelope_digest": DIGEST,
        "tenant_id": "tenant-test",
        "evaluator_id": "vaig:test:001",
        "evaluator_version": "1.0.0",
        "decision": decision,
        "authority_status": "PRESENT_AND_VALID",
        "policy_status": "PRESENT_AND_VALID",
        "evidence_status": "PRESENT_AND_VALID",
        "purpose_status": "PRESENT_AND_VALID",
        "state_status": "PRESENT_AND_VALID",
        "risk_status": "PRESENT_AND_VALID",
        "boundary_assessment_binding": dict(BOUNDARY_BINDING),
        "evaluated_at": "2026-07-14T18:00:00Z",
        "valid_until": "2026-07-14T18:05:00Z",
    }


def _valid_admissibility(
    state: str,
    evaluation_bindings=None,
    boundary_assessment_binding=None,
) -> dict:
    return {
        "determination_id": "det_test_001",
        "action_id": "act_test_001",
        "action_envelope_digest": DIGEST,
        "tenant_id": "tenant-test",
        "authority_digest": DIGEST,
        "delegation_chain_digest": DIGEST,
        "policy_digest": DIGEST,
        "evidence_digest": DIGEST,
        "purpose_digest": DIGEST,
        "state_digest": DIGEST,
        "evaluation_bindings": evaluation_bindings
        or [{"evaluation_ref": "vaig:test:001", "evaluation_digest": DIGEST}],
        "boundary_assessment_binding": boundary_assessment_binding
        or dict(BOUNDARY_BINDING),
        "state": state,
        "determined_at": "2026-07-14T18:00:00Z",
        "valid_until": "2026-07-14T18:05:00Z",
        "revocation_registry_ref": "racs://trust/test/revocations",
    }


def _valid_clearance(
    decision: str | None,
    admissibility_state: str | None,
    constraints: dict | None = None,
) -> dict:
    clearance = {
        "clearance_id": "clr_test_002",
        "action_id": "act_test_001",
        "action_envelope_digest": DIGEST,
        "tenant_id": "tenant-test",
        "decision": decision,
        "admissibility_state": admissibility_state,
        "authority_digest": DIGEST,
        "delegation_chain_digest": DIGEST,
        "policy_digest": DIGEST,
        "evidence_digest": DIGEST,
        "purpose_digest": DIGEST,
        "state_digest": DIGEST,
        "target_digest": DIGEST,
        "payload_digest": DIGEST,
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
        "admissibility_determination_digest": DIGEST,
    }
    if constraints is not None:
        clearance["constraints"] = constraints
    return clearance


@pytest.mark.parametrize("verdict", list(EXPECTED))
def test_all_aarm_verdicts_preserved(verdict):
    _validator("governance-evaluation-v0.2.schema.json").validate(
        _valid_evaluation(verdict)
    )


def test_evaluation_requires_boundary_binding():
    payload = _valid_evaluation()
    del payload["boundary_assessment_binding"]
    assert not _validator("governance-evaluation-v0.2.schema.json").is_valid(payload)


@pytest.mark.parametrize(
    "state",
    [
        "ADMISSIBLE",
        "CONDITIONALLY_ADMISSIBLE",
        "NOT_ADMISSIBLE",
        "INDETERMINATE",
        "STALE",
        "REVOKED",
        "HALTED",
        "REQUIRES_STEP_UP",
    ],
)
def test_all_admissibility_states_validate(state):
    assert _validator("admissibility-determination-v0.2.schema.json").is_valid(
        _valid_admissibility(state)
    )


def test_determination_requires_boundary_binding():
    payload = _valid_admissibility("ADMISSIBLE")
    del payload["boundary_assessment_binding"]
    assert not _validator("admissibility-determination-v0.2.schema.json").is_valid(
        payload
    )


def test_determination_requires_structured_evaluation_binding():
    payload = _valid_admissibility("ADMISSIBLE")
    payload["evaluation_bindings"] = ["vaig:test:001"]
    assert not _validator("admissibility-determination-v0.2.schema.json").is_valid(
        payload
    )


def _constraints():
    return {
        "machine_readable": True,
        "binds_exact_action": True,
        "rules": [
            {
                "id": "r1",
                "predicate": "capability_eq",
                "target": "net.send",
                "value": "net.send",
            }
        ],
    }


def test_clearance_positive_paths_only():
    validator = _validator("governance-clearance.schema.json")
    assert validator.is_valid(_valid_clearance("ALLOW", "ADMISSIBLE"))
    assert validator.is_valid(
        _valid_clearance("MODIFY", "CONDITIONALLY_ADMISSIBLE", _constraints())
    )
    for decision, state in [
        ("DEFER", "INDETERMINATE"),
        ("DENY", "NOT_ADMISSIBLE"),
        ("STEP_UP", "REQUIRES_STEP_UP"),
        ("HALT", "HALTED"),
    ]:
        assert not validator.is_valid(_valid_clearance(decision, state))


def test_clearance_cross_combinations_and_constraints_rejected():
    validator = _validator("governance-clearance.schema.json")
    assert not validator.is_valid(
        _valid_clearance("ALLOW", "CONDITIONALLY_ADMISSIBLE")
    )
    assert not validator.is_valid(
        _valid_clearance("MODIFY", "ADMISSIBLE", _constraints())
    )
    assert not validator.is_valid(
        _valid_clearance("MODIFY", "CONDITIONALLY_ADMISSIBLE")
    )
    assert not validator.is_valid(
        _valid_clearance("ALLOW", "ADMISSIBLE", _constraints())
    )


def _load_vectors() -> dict:
    return json.loads(
        (VEC_DIR / "canonical-verdict-mapping.json").read_text(encoding="utf-8")
    )


@pytest.mark.parametrize("vector", _load_vectors()["vectors"], ids=lambda v: v["id"])
def test_mapping_matches_independent_fasit_and_schemas(vector):
    expected_state, expected_decision, expected_clearance_state, issued = EXPECTED[
        vector["aarm_verdict"]
    ]
    assert vector["admissibility_determination"] == expected_state
    assert vector["clearance_decision"] == expected_decision
    assert vector["clearance_admissibility_state"] == expected_clearance_state
    assert vector["clearance_issued"] is issued

    determination = _valid_admissibility(
        expected_state,
        evaluation_bindings=vector["evaluation_bindings"],
        boundary_assessment_binding=vector["boundary_assessment_binding"],
    )
    assert _validator("admissibility-determination-v0.2.schema.json").is_valid(
        determination
    )
    if issued:
        assert _validator("governance-clearance.schema.json").is_valid(
            _valid_clearance(
                expected_decision,
                expected_clearance_state,
                vector.get("constraints"),
            )
        )


def test_mapping_covers_six_verdicts_once():
    verdicts = [item["aarm_verdict"] for item in _load_vectors()["vectors"]]
    assert set(verdicts) == set(EXPECTED)
    assert len(verdicts) == len(set(verdicts)) == 6


@pytest.mark.parametrize(
    "filename",
    ["canonical-verdict-mapping.json", "governance-evaluation-golden.json"],
)
def test_golden_sidecar(filename):
    content = (VEC_DIR / filename).read_bytes()
    expected = (VEC_DIR / filename.replace(".json", ".sha256")).read_text().split()[0]
    assert hashlib.sha256(content).hexdigest() == expected


def test_evaluation_digest_is_exact_canonical_payload_digest():
    golden = json.loads(
        (VEC_DIR / "governance-evaluation-golden.json").read_text(encoding="utf-8")
    )
    _validator("governance-evaluation-v0.2.schema.json").validate(golden["payload"])
    canonical = _canonicalize(golden["payload"])
    computed = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert canonical == golden["canonical_payload"]
    assert computed == golden["payload_digest"]
    allow = next(
        item for item in _load_vectors()["vectors"] if item["aarm_verdict"] == "ALLOW"
    )
    assert allow["evaluation_bindings"][0]["evaluation_digest"] == computed


def test_mutating_evaluation_changes_bound_digest():
    golden = json.loads(
        (VEC_DIR / "governance-evaluation-golden.json").read_text(encoding="utf-8")
    )
    mutated = dict(golden["payload"])
    mutated["decision"] = "DENY"
    changed = "sha256:" + hashlib.sha256(
        _canonicalize(mutated).encode("utf-8")
    ).hexdigest()
    assert changed != golden["payload_digest"]
