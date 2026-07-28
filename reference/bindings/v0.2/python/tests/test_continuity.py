"""Cross-language golden-vector and fail-closed tests for runtime continuity."""
from __future__ import annotations

import json
import os

import pytest

from racs_v02 import (
    ARTIFACT_TYPES,
    check,
    ContinuityDecision,
    EnvironmentGovernanceProfile,
    GovernedCapabilityManifest,
    GovernedExecutionSession,
    InterventionReceipt,
    RecoveryPlan,
    RecoveryReceipt,
    RuntimeObservation,
)

REPO = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "..")
VECTORS = os.path.join(
    REPO, "test-vectors", "0.2", "runtime-continuity", "canonical-vectors.json"
)

MODELS = {
    "governed_capability_manifest": GovernedCapabilityManifest,
    "environment_governance_profile": EnvironmentGovernanceProfile,
    "governed_execution_session": GovernedExecutionSession,
    "runtime_observation": RuntimeObservation,
    "continuity_decision": ContinuityDecision,
    "intervention_receipt": InterventionReceipt,
    "recovery_plan": RecoveryPlan,
    "recovery_receipt": RecoveryReceipt,
}


@pytest.fixture(scope="module")
def vectors():
    with open(VECTORS, "r", encoding="utf-8") as handle:
        return json.load(handle)["vectors"]


@pytest.mark.parametrize("name", sorted(MODELS))
def test_runtime_continuity_golden_vectors(vectors, name):
    vector = next(item for item in vectors if item["name"] == name)
    model = MODELS[name](**vector["payload"])
    assert model.model_canonical().decode("utf-8") == vector["canonical"]
    assert model.model_digest() == vector["payload_digest"]


def test_unknown_fields_fail_closed(vectors):
    payload = dict(next(v for v in vectors if v["name"] == "continuity_decision")["payload"])
    payload["watcher_authorized"] = True
    with pytest.raises(Exception):
        ContinuityDecision(**payload)


def test_continue_cannot_add_constraints(vectors):
    payload = dict(next(v for v in vectors if v["name"] == "continuity_decision")["payload"])
    payload["constraints"] = {"max_speed_mm_s": 900}
    with pytest.raises(Exception):
        ContinuityDecision(**payload)


def test_modify_requires_explicit_constraints(vectors):
    payload = dict(next(v for v in vectors if v["name"] == "continuity_decision")["payload"])
    payload["decision"] = "MODIFY_RUNTIME_BOUNDS"
    payload.pop("constraints", None)
    with pytest.raises(Exception):
        ContinuityDecision(**payload)


def test_observation_requires_exactly_one_signal_representation(vectors):
    payload = dict(next(v for v in vectors if v["name"] == "runtime_observation")["payload"])
    payload["signal_digest"] = "sha256:" + "f" * 64
    with pytest.raises(Exception):
        RuntimeObservation(**payload)


def test_recovery_plan_never_carries_execution_authority(vectors):
    payload = dict(next(v for v in vectors if v["name"] == "recovery_plan")["payload"])
    payload["carries_execution_authority"] = True
    with pytest.raises(Exception):
        RecoveryPlan(**payload)


def test_failed_recovery_must_halt(vectors):
    payload = dict(next(v for v in vectors if v["name"] == "recovery_receipt")["payload"])
    payload["result"] = "FAILED"
    payload["next_state"] = "PAUSED"
    with pytest.raises(Exception):
        RecoveryReceipt(**payload)


def test_runtime_continuity_registry_and_schema_validation(vectors):
    for name, model_cls in MODELS.items():
        artifact_type = model_cls.__name__
        assert artifact_type in ARTIFACT_TYPES
        payload = next(v for v in vectors if v["name"] == name)["payload"]
        result = check(artifact_type, payload)
        assert result.decision == "ACCEPT"
        assert result.payload_digest == next(
            v for v in vectors if v["name"] == name
        )["payload_digest"]
