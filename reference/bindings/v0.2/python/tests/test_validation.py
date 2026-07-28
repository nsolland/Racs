"""Stage 3C Python conformance over shared boundary-aware runtime vectors."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from racs_v02 import (
    AdmissibilityDetermination,
    BoundaryCrossingAssessment,
    GovernanceClearance,
    GovernanceEvaluation,
    check,
    verify_clearance_binding,
    verify_evaluation_binding,
)

REPO = Path(__file__).resolve().parents[5]
VEC = REPO / "test-vectors" / "0.2" / "runtime-validation"
VECTOR_DIRS = [
    "governance-evaluation",
    "admissibility-determination",
    "governance-clearance",
    "cross-artifact-bindings",
]


def _load_vectors() -> list[dict]:
    vectors = []
    for directory in VECTOR_DIRS:
        for path in sorted((VEC / directory).glob("*.json")):
            if not path.name.startswith("_"):
                vectors.append(json.loads(path.read_text(encoding="utf-8")))
    return vectors


def _resolved_models(vector: dict):
    resolved = vector["resolved"]
    return (
        resolved["action_envelope"],
        BoundaryCrossingAssessment.model_validate(resolved["boundary_assessment"]),
        GovernanceEvaluation.model_validate(resolved["evaluation"]),
        AdmissibilityDetermination.model_validate(resolved["determination"]),
    )


def _verify_clearance(vector: dict, clearance: GovernanceClearance):
    action_envelope, assessment, evaluation, determination = _resolved_models(vector)
    evaluation_result = verify_evaluation_binding(
        determination,
        evaluation,
        boundary_assessment=assessment,
    )
    if evaluation_result.decision == "REJECT":
        return evaluation_result
    return verify_clearance_binding(
        clearance,
        determination,
        action_envelope=action_envelope,
        verification_time=vector.get("verification_time"),
        governance_evaluation=evaluation,
        boundary_assessment=assessment,
    )


VECTORS = _load_vectors()


def test_vectors_present():
    assert len(VECTORS) >= 18


@pytest.mark.parametrize("vector", VECTORS, ids=lambda value: value["id"])
def test_vector_decision_and_reason(vector):
    result = check(vector["artifact_type"], vector["payload"])

    if "resolved" not in vector:
        assert result.decision == vector["expected"]
        assert result.reason_code == vector["reason_code"]
        if result.decision == "ACCEPT":
            assert result.payload_digest and result.payload_digest.startswith("sha256:")
        return

    assert result.decision == "ACCEPT", result.reason_code
    clearance = GovernanceClearance.model_validate(vector["payload"])
    verified = _verify_clearance(vector, clearance)
    assert verified.decision == vector["expected"]
    assert verified.reason_code == vector["reason_code"]


@pytest.mark.parametrize(
    "filename,reason",
    [
        ("chain_accept.json", "ACCEPT"),
        (
            "chain_reject_det_digest_mismatch.json",
            "CLEARANCE_DETERMINATION_DIGEST_MISMATCH",
        ),
        (
            "chain_reject_eval_binding_mismatch.json",
            "EVALUATION_BINDING_DIGEST_MISMATCH",
        ),
        ("chain_reject_boundary_policy_mismatch.json", "BOUNDARY_POLICY_MISMATCH"),
    ],
)
def test_full_chain_vectors(filename, reason):
    vector = json.loads(
        (VEC / "cross-artifact-bindings" / filename).read_text(encoding="utf-8")
    )
    verified = _verify_clearance(
        vector, GovernanceClearance.model_validate(vector["payload"])
    )
    assert verified.reason_code == reason


def test_schema_sha256_stable():
    from racs_v02 import schema_sha256

    first = schema_sha256("BoundaryCrossingAssessment")
    assert first == schema_sha256("BoundaryCrossingAssessment")
    assert first.startswith("sha256:")
