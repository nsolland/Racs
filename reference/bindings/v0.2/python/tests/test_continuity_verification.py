"""Stage 2 cross-artifact verification and monotone-bound tests."""
from __future__ import annotations

import copy
import json
import os

import pytest

from racs_v02 import (
    ContinuityDecision,
    EnvironmentGovernanceProfile,
    GovernanceClearance,
    GovernanceEvaluation,
    GovernedCapabilityManifest,
    GovernedExecutionSession,
)
from racs_v02.continuity_verification import (
    prove_runtime_bounds_narrowing,
    verify_continuity_decision,
    verify_execution_session,
)

REPO = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "..")
VECTORS = os.path.join(
    REPO,
    "test-vectors",
    "0.2",
    "runtime-continuity",
    "verification-vectors.json",
)


@pytest.fixture(scope="module")
def document():
    with open(VECTORS, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _mutate(root, mutations):
    for dotted_path, value in mutations.items():
        parts = dotted_path.split(".")
        node = root
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value


def _models(document, mutations=None):
    payloads = copy.deepcopy(document["artifacts"])
    _mutate(payloads, mutations or {})
    return {
        "manifest": GovernedCapabilityManifest(**payloads["manifest"]),
        "profile": EnvironmentGovernanceProfile(**payloads["profile"]),
        "evaluation": GovernanceEvaluation(**payloads["evaluation"]),
        "clearance": GovernanceClearance(**payloads["clearance"]),
        "session": GovernedExecutionSession(**payloads["session"]),
        "decision": ContinuityDecision(**payloads["decision"]),
    }


@pytest.mark.parametrize("case_index", range(5))
def test_session_verification_vectors(document, case_index):
    case = document["session_cases"][case_index]
    models = _models(document, case["mutations"])
    result = verify_execution_session(
        models["session"],
        models["manifest"],
        models["profile"],
        models["evaluation"],
        models["clearance"],
        verification_time=document["verification_time"],
    )
    assert result.decision == case["expected"], case["id"]
    assert result.reason_code == case["reason_code"], case["id"]


@pytest.mark.parametrize("case_index", range(5))
def test_bounds_narrowing_vectors(document, case_index):
    case = document["bounds_cases"][case_index]
    result = prove_runtime_bounds_narrowing(case["current"], case["proposed"])
    assert result.decision == case["expected"], case["id"]
    assert result.reason_code == case["reason_code"], case["id"]


@pytest.mark.parametrize("case_index", range(4))
def test_decision_verification_vectors(document, case_index):
    case = document["decision_cases"][case_index]
    models = _models(document, case["mutations"])
    result = verify_continuity_decision(
        models["session"],
        models["decision"],
        models["profile"].runtime_limits,
        verification_time=document["verification_time"],
    )
    assert result.decision == case["expected"], case["id"]
    assert result.reason_code == case["reason_code"], case["id"]
