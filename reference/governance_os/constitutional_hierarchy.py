"""Deterministic constitutional decision hierarchy for Governance OS.

Hard gates are evaluated in canonical precedence order. Lower levels cannot
compensate for a failed higher-level gate. Unknown mandatory state fails closed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
import json
from typing import Iterable, Mapping, Sequence


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    MODIFY = "MODIFY"
    DEFER = "DEFER"
    DENY = "DENY"
    STEP_UP = "STEP_UP"
    HALT = "HALT"


class GateState(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    CONFLICT = "CONFLICT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Level(str, Enum):
    CONSTITUTIONAL_LEGAL = "constitutional_legal"
    AUTHORITY_MANDATE = "authority_mandate"
    PURPOSE_SEMANTIC = "purpose_semantic_binding"
    RIGHTS_SAFETY = "rights_safety"
    EVIDENCE_REPRESENTATION = "evidence_representation"
    CONSEQUENCE = "consequence"
    SOFT_PRIORITIES = "soft_priorities"
    SCHEDULING = "scheduling"


PRECEDENCE: tuple[Level, ...] = (
    Level.CONSTITUTIONAL_LEGAL,
    Level.AUTHORITY_MANDATE,
    Level.PURPOSE_SEMANTIC,
    Level.RIGHTS_SAFETY,
    Level.EVIDENCE_REPRESENTATION,
    Level.CONSEQUENCE,
    Level.SOFT_PRIORITIES,
    Level.SCHEDULING,
)

HARD_LEVELS = frozenset(PRECEDENCE[:6])


@dataclass(frozen=True)
class GateResult:
    gate_id: str
    level: Level
    state: GateState
    mandatory: bool = True
    reason_code: str = ""
    evidence_digest: str = ""
    detail: str = ""

    def validate(self) -> None:
        if not self.gate_id.strip():
            raise ValueError("gate_id is required")
        if self.state in {GateState.FAIL, GateState.UNKNOWN, GateState.CONFLICT} and not self.reason_code:
            raise ValueError("non-pass gate requires reason_code")


@dataclass(frozen=True)
class HierarchyProfile:
    profile_id: str
    version: str
    required_gates: Mapping[Level, tuple[str, ...]] = field(default_factory=dict)

    def digest(self) -> str:
        payload = {
            "profile_id": self.profile_id,
            "version": self.version,
            "required_gates": {
                level.value: list(self.required_gates.get(level, ())) for level in PRECEDENCE
            },
        }
        return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class HierarchyDecision:
    verdict: Verdict
    decisive_level: Level | None
    reason_codes: tuple[str, ...]
    evaluated_gate_ids: tuple[str, ...]
    profile_digest: str
    decision_digest: str


def _decision_digest(payload: Mapping[str, object]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def evaluate_hierarchy(
    profile: HierarchyProfile,
    results: Iterable[GateResult],
    *,
    legitimate_conflict_levels: Sequence[Level] = (),
) -> HierarchyDecision:
    """Evaluate gates in strict precedence order.

    Rules:
    - FAIL at a hard level => DENY.
    - UNKNOWN mandatory state at a hard level => STEP_UP.
    - CONFLICT at a hard level => STEP_UP when legitimate, otherwise DENY.
    - Missing required hard gate => STEP_UP.
    - Soft/scheduling failures may produce MODIFY or DEFER, never override hard gates.
    """
    items = tuple(results)
    for item in items:
        item.validate()

    by_level: dict[Level, list[GateResult]] = {level: [] for level in PRECEDENCE}
    for item in items:
        by_level[item.level].append(item)

    evaluated: list[str] = []
    reason_codes: list[str] = []
    conflict_levels = set(legitimate_conflict_levels)

    for level in PRECEDENCE:
        level_items = sorted(by_level[level], key=lambda x: x.gate_id)
        evaluated.extend(item.gate_id for item in level_items)

        required = profile.required_gates.get(level, ())
        present = {item.gate_id for item in level_items}
        missing = sorted(set(required) - present)
        if level in HARD_LEVELS and missing:
            reason_codes.extend(f"MISSING_REQUIRED_GATE:{level.value}:{gate}" for gate in missing)
            return _build(Verdict.STEP_UP, level, reason_codes, evaluated, profile)

        failures = [item for item in level_items if item.state is GateState.FAIL]
        unknowns = [item for item in level_items if item.mandatory and item.state is GateState.UNKNOWN]
        conflicts = [item for item in level_items if item.state is GateState.CONFLICT]

        if level in HARD_LEVELS:
            if failures:
                reason_codes.extend(item.reason_code for item in failures)
                return _build(Verdict.DENY, level, reason_codes, evaluated, profile)
            if unknowns:
                reason_codes.extend(item.reason_code for item in unknowns)
                return _build(Verdict.STEP_UP, level, reason_codes, evaluated, profile)
            if conflicts:
                reason_codes.extend(item.reason_code for item in conflicts)
                verdict = Verdict.STEP_UP if level in conflict_levels else Verdict.DENY
                return _build(verdict, level, reason_codes, evaluated, profile)
        elif level is Level.SOFT_PRIORITIES:
            if failures or unknowns or conflicts:
                reason_codes.extend(item.reason_code for item in failures + unknowns + conflicts)
                return _build(Verdict.MODIFY, level, reason_codes, evaluated, profile)
        elif level is Level.SCHEDULING:
            if failures or unknowns or conflicts:
                reason_codes.extend(item.reason_code for item in failures + unknowns + conflicts)
                return _build(Verdict.DEFER, level, reason_codes, evaluated, profile)

    return _build(Verdict.ALLOW, None, (), evaluated, profile)


def _build(
    verdict: Verdict,
    decisive_level: Level | None,
    reason_codes: Sequence[str],
    evaluated: Sequence[str],
    profile: HierarchyProfile,
) -> HierarchyDecision:
    payload = {
        "verdict": verdict.value,
        "decisive_level": decisive_level.value if decisive_level else None,
        "reason_codes": list(reason_codes),
        "evaluated_gate_ids": list(evaluated),
        "profile_digest": profile.digest(),
    }
    return HierarchyDecision(
        verdict=verdict,
        decisive_level=decisive_level,
        reason_codes=tuple(reason_codes),
        evaluated_gate_ids=tuple(evaluated),
        profile_digest=profile.digest(),
        decision_digest=_decision_digest(payload),
    )
