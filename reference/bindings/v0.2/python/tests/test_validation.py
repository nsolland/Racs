"""Stage 3C conformance tests for the Python binding.

Reads the shared, language-agnostic runtime-validation vectors under
test-vectors/0.2/runtime-validation/ and asserts that the Python binding emits
the same ACCEPT/REJECT decision and normalized reason code as declared in each
vector. For cross-artifact vectors, it also runs the verifier with the
`resolved` artifacts.
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

REPO = Path(__file__).resolve().parents[5]  # tests -> python -> src -> racs_v02 -> v0.2 -> bindings -> reference -> Rac
VEC = REPO / "test-vectors" / "0.2" / "runtime-validation"

VECTOR_DIRS = [
    "governance-evaluation",
    "admissibility-determination",
    "governance-clearance",
    "cross-artifact-bindings",
]


def _load_vectors():
    out = []
    for d in VECTOR_DIRS:
        for p in sorted((VEC / d).glob("*.json")):
            if p.name.startswith("_"):
                continue
            out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


VECTORS = _load_vectors()


def test_vectors_present():
    assert len(VECTORS) >= 15, f"expected >=15 vectors, got {len(VECTORS)}"


@pytest.mark.parametrize("vec", VECTORS, ids=lambda v: v["id"])
def test_vector_decision_and_reason(vec):
    artifact_type = vec["artifact_type"]
    expected = vec["expected"]
    reason = vec["reason_code"]
    payload = vec["payload"]

    # Port A: schema validation
    res = check(artifact_type, payload)

    if expected == "ACCEPT" and artifact_type != "GovernanceClearance":
        # Schema ACCEPT alone suffices for evaluation/determination vectors.
        assert res.decision == "ACCEPT", res.reason_code
        assert res.reason_code == "ACCEPT"
        assert res.payload_digest is not None and res.payload_digest.startswith("sha256:")
        return

    if expected == "ACCEPT" and artifact_type == "GovernanceClearance":
        # ACCEPT clearance must ALSO pass cross-artifact verification if a
        # resolved chain is provided; otherwise schema ACCEPT is enough.
        assert res.decision == "ACCEPT", res.reason_code
        if "resolved" in vec:
            clr = GovernanceClearance.model_validate(payload)
            det = AdmissibilityDetermination.model_validate(vec["resolved"]["determination"])
            ev = GovernanceEvaluation.model_validate(vec["resolved"]["evaluation"])
            eb = verify_evaluation_binding(det, ev)
            assert eb.decision == "ACCEPT", eb.reason_code
            cb = verify_clearance_binding(clr, det)
            assert cb.decision == "ACCEPT", cb.reason_code
        return

    # REJECT case. Vectors carrying a `resolved` chain are cross-artifact
    # rejections (Port B) — schema (Port A) legitimately ACCEPTs them; their
    # rejection is asserted in test_vector_cross_artifact.
    if "resolved" in vec:
        assert res.decision == "ACCEPT", f"schema should accept, got {res.reason_code}"
        return
    assert res.decision == "REJECT", f"expected REJECT, got {res.decision}:{res.reason_code}"
    assert res.reason_code == reason, f"reason mismatch: {res.reason_code} != {reason}"


@pytest.mark.parametrize("vec", VECTORS, ids=lambda v: v["id"])
def test_vector_cross_artifact(vec):
    """Port B: cross-artifact verification for vectors carrying a `resolved`
    chain. Asserts the verifier emits the same decision + reason code."""
    if "resolved" not in vec:
        pytest.skip("no resolved chain in vector")
    artifact_type = vec["artifact_type"]
    expected = vec["expected"]
    reason = vec["reason_code"]
    payload = vec["payload"]
    resolved = vec["resolved"]

    if artifact_type == "GovernanceClearance":
        clr = GovernanceClearance.model_validate(payload)
        det = AdmissibilityDetermination.model_validate(resolved["determination"])
        ev = GovernanceEvaluation.model_validate(resolved["evaluation"])
        eb = verify_evaluation_binding(det, ev)
        cb = verify_clearance_binding(clr, det)
        # For a positive chain both bindings must ACCEPT; for a negative vector
        # the expected decision+reason must come from exactly one of them.
        if expected == "ACCEPT":
            assert eb.decision == "ACCEPT", eb.reason_code
            assert cb.decision == "ACCEPT", cb.reason_code
        else:
            decided = eb if eb.decision == "REJECT" else cb
            assert decided.decision == expected, f"{decided.decision} != {expected}"
            assert decided.reason_code == reason, f"{decided.reason_code} != {reason}"
    elif artifact_type == "AdmissibilityDetermination":
        det = AdmissibilityDetermination.model_validate(payload)
        ev = GovernanceEvaluation.model_validate(resolved["evaluation"])
        eb = verify_evaluation_binding(det, ev)
        assert eb.decision == expected, f"{eb.decision} != {expected}"
        assert eb.reason_code == reason, f"{eb.reason_code} != {reason}"


def test_clearance_accept_is_verified_chain():
    """The positive cross-artifact clearance must verify end-to-end."""
    chain = json.loads(
        (VEC / "cross-artifact-bindings" / "chain_accept.json").read_text(encoding="utf-8")
    )
    clr = GovernanceClearance.model_validate(chain["payload"])
    det = AdmissibilityDetermination.model_validate(chain["resolved"]["determination"])
    ev = GovernanceEvaluation.model_validate(chain["resolved"]["evaluation"])

    eb = verify_evaluation_binding(det, ev)
    assert eb.decision == "ACCEPT", eb.reason_code
    cb = verify_clearance_binding(clr, det)
    assert cb.decision == "ACCEPT", cb.reason_code


def test_clearance_reject_det_digest_mismatch():
    vec = json.loads(
        (VEC / "cross-artifact-bindings" / "chain_reject_det_digest_mismatch.json").read_text(
            encoding="utf-8"
        )
    )
    clr = GovernanceClearance.model_validate(vec["payload"])
    det = AdmissibilityDetermination.model_validate(vec["resolved"]["determination"])
    cb = verify_clearance_binding(clr, det)
    assert cb.decision == "REJECT"
    assert cb.reason_code == "CLEARANCE_DETERMINATION_DIGEST_MISMATCH"


def test_schema_sha256_stable():
    from racs_v02 import schema_sha256

    h1 = schema_sha256("GovernanceClearance")
    h2 = schema_sha256("GovernanceClearance")
    assert h1 == h2
    assert h1.startswith("sha256:")
