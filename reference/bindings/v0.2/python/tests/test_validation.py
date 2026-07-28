"""Stage 3C conformance tests for the Python binding.

Reads the shared, language-agnostic runtime-validation vectors under
test-vectors/0.2/runtime-validation/ and asserts that the Python binding emits
the same ACCEPT/REJECT decision and normalized reason code as declared in each
vector. For cross-artifact vectors, it also runs the verifier with the
`resolved` artifacts and the vector's explicit verification time.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from racs_v02 import (
    AdmissibilityDetermination,
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


def _load_vectors():
    vectors = []
    for directory in VECTOR_DIRS:
        for path in sorted((VEC / directory).glob("*.json")):
            if path.name.startswith("_"):
                continue
            vectors.append(json.loads(path.read_text(encoding="utf-8")))
    return vectors


def _verify_clearance(vec, clearance, determination):
    return verify_clearance_binding(
        clearance,
        determination,
        verification_time=vec.get("verification_time"),
    )


VECTORS = _load_vectors()


def test_vectors_present():
    assert len(VECTORS) >= 15, f"expected >=15 vectors, got {len(VECTORS)}"


@pytest.mark.parametrize("vec", VECTORS, ids=lambda value: value["id"])
def test_vector_decision_and_reason(vec):
    artifact_type = vec["artifact_type"]
    expected = vec["expected"]
    reason = vec["reason_code"]
    payload = vec["payload"]

    result = check(artifact_type, payload)

    if expected == "ACCEPT" and artifact_type != "GovernanceClearance":
        assert result.decision == "ACCEPT", result.reason_code
        assert result.reason_code == "ACCEPT"
        assert result.payload_digest is not None
        assert result.payload_digest.startswith("sha256:")
        return

    if expected == "ACCEPT" and artifact_type == "GovernanceClearance":
        assert result.decision == "ACCEPT", result.reason_code
        if "resolved" in vec:
            clearance = GovernanceClearance.model_validate(payload)
            determination = AdmissibilityDetermination.model_validate(
                vec["resolved"]["determination"]
            )
            evaluation = GovernanceEvaluation.model_validate(
                vec["resolved"]["evaluation"]
            )
            evaluation_binding = verify_evaluation_binding(determination, evaluation)
            assert evaluation_binding.decision == "ACCEPT", evaluation_binding.reason_code
            clearance_binding = _verify_clearance(vec, clearance, determination)
            assert clearance_binding.decision == "ACCEPT", clearance_binding.reason_code
        return

    if "resolved" in vec:
        assert result.decision == "ACCEPT", (
            f"schema should accept, got {result.reason_code}"
        )
        return
    assert result.decision == "REJECT", (
        f"expected REJECT, got {result.decision}:{result.reason_code}"
    )
    assert result.reason_code == reason, (
        f"reason mismatch: {result.reason_code} != {reason}"
    )


@pytest.mark.parametrize("vec", VECTORS, ids=lambda value: value["id"])
def test_vector_cross_artifact(vec):
    """Verify all vectors carrying a resolved cross-artifact chain."""
    if "resolved" not in vec:
        pytest.skip("no resolved chain in vector")
    artifact_type = vec["artifact_type"]
    expected = vec["expected"]
    reason = vec["reason_code"]
    payload = vec["payload"]
    resolved = vec["resolved"]

    if artifact_type == "GovernanceClearance":
        clearance = GovernanceClearance.model_validate(payload)
        determination = AdmissibilityDetermination.model_validate(
            resolved["determination"]
        )
        evaluation = GovernanceEvaluation.model_validate(resolved["evaluation"])
        evaluation_binding = verify_evaluation_binding(determination, evaluation)
        clearance_binding = _verify_clearance(vec, clearance, determination)
        if expected == "ACCEPT":
            assert evaluation_binding.decision == "ACCEPT", evaluation_binding.reason_code
            assert clearance_binding.decision == "ACCEPT", clearance_binding.reason_code
        else:
            decided = (
                evaluation_binding
                if evaluation_binding.decision == "REJECT"
                else clearance_binding
            )
            assert decided.decision == expected, f"{decided.decision} != {expected}"
            assert decided.reason_code == reason, f"{decided.reason_code} != {reason}"
    elif artifact_type == "AdmissibilityDetermination":
        determination = AdmissibilityDetermination.model_validate(payload)
        evaluation = GovernanceEvaluation.model_validate(resolved["evaluation"])
        evaluation_binding = verify_evaluation_binding(determination, evaluation)
        assert evaluation_binding.decision == expected, (
            f"{evaluation_binding.decision} != {expected}"
        )
        assert evaluation_binding.reason_code == reason, (
            f"{evaluation_binding.reason_code} != {reason}"
        )


def test_clearance_accept_is_verified_chain():
    chain = json.loads(
        (VEC / "cross-artifact-bindings" / "chain_accept.json").read_text(
            encoding="utf-8"
        )
    )
    clearance = GovernanceClearance.model_validate(chain["payload"])
    determination = AdmissibilityDetermination.model_validate(
        chain["resolved"]["determination"]
    )
    evaluation = GovernanceEvaluation.model_validate(chain["resolved"]["evaluation"])

    evaluation_binding = verify_evaluation_binding(determination, evaluation)
    assert evaluation_binding.decision == "ACCEPT", evaluation_binding.reason_code
    clearance_binding = _verify_clearance(chain, clearance, determination)
    assert clearance_binding.decision == "ACCEPT", clearance_binding.reason_code


def test_clearance_reject_det_digest_mismatch():
    vector = json.loads(
        (
            VEC
            / "cross-artifact-bindings"
            / "chain_reject_det_digest_mismatch.json"
        ).read_text(encoding="utf-8")
    )
    clearance = GovernanceClearance.model_validate(vector["payload"])
    determination = AdmissibilityDetermination.model_validate(
        vector["resolved"]["determination"]
    )
    clearance_binding = _verify_clearance(vector, clearance, determination)
    assert clearance_binding.decision == "REJECT"
    assert (
        clearance_binding.reason_code
        == "CLEARANCE_DETERMINATION_DIGEST_MISMATCH"
    )


def test_schema_sha256_stable():
    from racs_v02 import schema_sha256

    first = schema_sha256("GovernanceClearance")
    second = schema_sha256("GovernanceClearance")
    assert first == second
    assert first.startswith("sha256:")
