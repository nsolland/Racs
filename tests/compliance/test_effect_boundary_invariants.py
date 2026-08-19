from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "spec" / "EFFECT_CHAIN_INTEGRITY_V0_2.md"
INDEX = ROOT / "spec" / "CANONICAL_CONTRACTS.md"


def _compact(value: str) -> str:
    return " ".join(value.split())


def test_effect_boundary_profile_registers_canonical_invariants() -> None:
    text = PROFILE.read_text(encoding="utf-8")
    for invariant in (
        "NO_DIRECT_EFFECT_PATH",
        "NULL_EFFECT_ON_DENY",
        "Structural Coupling Test",
        "Effector-exclusive authority",
        "Deterministic boundary replay",
    ):
        assert invariant in text


def test_null_effect_covers_every_non_allow_execution_outcome() -> None:
    text = PROFILE.read_text(encoding="utf-8")
    null_effect = _compact(
        text.split("### 2.2 `NULL_EFFECT_ON_DENY`", 1)[1].split("### 2.3", 1)[0]
    )
    for decision in ("DENY", "DEFER", "STEP_UP", "HALT"):
        assert f"`{decision}`" in null_effect
    assert "MUST NOT invoke an effector" in null_effect


def test_structural_coupling_covers_every_broken_basis_state() -> None:
    text = PROFILE.read_text(encoding="utf-8")
    coupling = _compact(
        text.split("### 2.3 Structural Coupling Test", 1)[1].split(
            "### 2.4", 1
        )[0]
    )
    for state in ("invalid", "stale", "revoked", "suspended", "unresolved"):
        assert state in coupling


def test_decision_relevant_state_and_memory_writes_are_governed_effects() -> None:
    text = PROFILE.read_text(encoding="utf-8")
    assert "state, memory, configuration, instruction or artifact write" in text
    assert "future consequence-bearing" in text
    assert "governed write boundary" in text


def test_boundary_replay_is_pinned_and_excludes_token_replay() -> None:
    text = PROFILE.read_text(encoding="utf-8")
    replay = _compact(
        text.split("### 2.5 Deterministic boundary replay", 1)[1].split(
            "## 3.", 1
        )[0]
    )
    for pinned_input in ("contract", "state", "authority", "evidence", "decision"):
        assert pinned_input in replay
    assert "without invoking the effector" in replay
    assert "not token-level LLM replay" in replay


def test_contract_index_registers_effect_boundary_profile_without_new_owner() -> None:
    index = INDEX.read_text(encoding="utf-8")
    assert "NO_DIRECT_EFFECT_PATH" in index
    assert "NULL_EFFECT_ON_DENY" in index
    assert "RACS owns effect-path and effect-chain integrity semantics" in index
    assert "REHT determines admissibility and issues exact-action clearance" in index
