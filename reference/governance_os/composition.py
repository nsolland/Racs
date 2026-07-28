"""Monotone composition of authoritative evaluation fragments.

Composition intersects restrictions, unions obligations and delegates the final
six-state decision to the canonical constitutional hierarchy. It cannot create
or widen authority and has no execution authority.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping, Sequence

from constitutional_hierarchy import (
    GateResult,
    GateState,
    HierarchyDecision,
    HierarchyProfile,
    Level,
    PRECEDENCE,
    evaluate_hierarchy,
)
from evaluation_fragments import (
    Constraint,
    EvaluationFragment,
    Obligation,
    fragment_set_digest,
    parse_evaluation_fragment,
)

_BASE_PATH = Path(__file__).parents[1] / "governance_os_v0_1.py"
if "governance_os_v0_1" in sys.modules:
    _BASE = sys.modules["governance_os_v0_1"]
else:
    _BASE_SPEC = importlib.util.spec_from_file_location("governance_os_v0_1", _BASE_PATH)
    if _BASE_SPEC is None or _BASE_SPEC.loader is None:
        raise RuntimeError("cannot load governance_os_v0_1")
    _BASE = importlib.util.module_from_spec(_BASE_SPEC)
    sys.modules["governance_os_v0_1"] = _BASE
    _BASE_SPEC.loader.exec_module(_BASE)

GovernanceError = _BASE.GovernanceError
digest = _BASE.digest


@dataclass(frozen=True)
class CompositionResult:
    hierarchy_decision: HierarchyDecision
    constraints: tuple[Constraint, ...]
    obligations: tuple[Obligation, ...]
    fragment_set_digest: str
    constraint_set_digest: str
    obligation_set_digest: str
    conflict_reason_codes: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "verdict": self.hierarchy_decision.verdict.value,
            "decisive_level": (
                self.hierarchy_decision.decisive_level.value
                if self.hierarchy_decision.decisive_level is not None else None
            ),
            "reason_codes": list(self.hierarchy_decision.reason_codes),
            "evaluated_gate_ids": list(self.hierarchy_decision.evaluated_gate_ids),
            "profile_digest": self.hierarchy_decision.profile_digest,
            "decision_digest": self.hierarchy_decision.decision_digest,
            "fragment_set_digest": self.fragment_set_digest,
            "constraint_set_digest": self.constraint_set_digest,
            "obligation_set_digest": self.obligation_set_digest,
            "conflict_reason_codes": list(self.conflict_reason_codes),
        }


def _level_rank(level: Level) -> int:
    return PRECEDENCE.index(level)


def _constraint_conflicts(
    fragments: Sequence[EvaluationFragment],
) -> tuple[list[GateResult], tuple[str, ...]]:
    sources: dict[tuple[str, str], list[tuple[Constraint, Level]]] = {}
    equals_by_namespace: dict[str, list[tuple[Constraint, Level]]] = {}
    prohibits_by_namespace: dict[str, list[tuple[Constraint, Level]]] = {}
    for fragment in fragments:
        if fragment.state is not GateState.PASS:
            continue
        for constraint in fragment.constraints:
            sources.setdefault((constraint.namespace, constraint.operator), []).append((constraint, fragment.level))
            if constraint.operator == "EQUALS":
                equals_by_namespace.setdefault(constraint.namespace, []).append((constraint, fragment.level))
            elif constraint.operator == "PROHIBITS":
                prohibits_by_namespace.setdefault(constraint.namespace, []).append((constraint, fragment.level))

    conflicts: list[tuple[Level, str]] = []
    opaque_intersection = {"EQUALS", "IN", "SUBSET_OF"}
    for (namespace, operator), items in sources.items():
        values = {constraint.value_digest for constraint, _ in items}
        if operator in opaque_intersection and len(values) > 1:
            level = min((level for _, level in items), key=_level_rank)
            conflicts.append((level, f"CONSTRAINT_INTERSECTION_UNPROVEN:{namespace}:{operator}"))

    for namespace, equal_items in equals_by_namespace.items():
        prohibited = prohibits_by_namespace.get(namespace, [])
        prohibited_values = {constraint.value_digest for constraint, _ in prohibited}
        matching = [(constraint, level) for constraint, level in equal_items if constraint.value_digest in prohibited_values]
        if matching:
            all_levels = [level for _, level in matching] + [level for _, level in prohibited]
            level = min(all_levels, key=_level_rank)
            conflicts.append((level, f"CONSTRAINT_EQUALS_PROHIBITED:{namespace}"))

    grouped: dict[Level, list[str]] = {}
    for level, reason in conflicts:
        grouped.setdefault(level, []).append(reason)
    gates = [
        GateResult(
            gate_id=f"composition-constraint-consistency:{level.value}",
            level=level,
            state=GateState.CONFLICT,
            mandatory=True,
            reason_code="|".join(sorted(set(reasons))),
            evidence_digest=digest(sorted(set(reasons))),
            detail="opaque constraint intersection cannot be proven non-empty",
        )
        for level, reasons in grouped.items()
    ]
    return gates, tuple(sorted({reason for _, reason in conflicts}))


def _compose_obligations(
    fragments: Sequence[EvaluationFragment],
) -> tuple[tuple[Obligation, ...], list[GateResult], tuple[str, ...]]:
    by_id: dict[str, list[tuple[Obligation, Level]]] = {}
    for fragment in fragments:
        if fragment.state is not GateState.PASS:
            continue
        for obligation in fragment.obligations:
            by_id.setdefault(obligation.obligation_id, []).append((obligation, fragment.level))

    effective: list[Obligation] = []
    conflicts: list[tuple[Level, str]] = []
    for obligation_id, items in by_id.items():
        variants = {item for item, _ in items}
        if len(variants) > 1:
            level = min((level for _, level in items), key=_level_rank)
            conflicts.append((level, f"OBLIGATION_DEFINITION_CONFLICT:{obligation_id}"))
        else:
            effective.append(next(iter(variants)))

    grouped: dict[Level, list[str]] = {}
    for level, reason in conflicts:
        grouped.setdefault(level, []).append(reason)
    gates = [
        GateResult(
            gate_id=f"composition-obligation-consistency:{level.value}",
            level=level,
            state=GateState.CONFLICT,
            mandatory=True,
            reason_code="|".join(sorted(set(reasons))),
            evidence_digest=digest(sorted(set(reasons))),
            detail="same obligation id has incompatible definitions",
        )
        for level, reasons in grouped.items()
    ]
    return tuple(sorted(effective)), gates, tuple(sorted({reason for _, reason in conflicts}))


def compose_evaluation_fragments(
    profile: HierarchyProfile,
    base_gate_results: Iterable[GateResult],
    fragment_records: Iterable[Mapping[str, Any]],
    *,
    now: str,
    subject_digest: str,
    legitimate_conflict_levels: Sequence[Level] = (),
    halt_reason_codes: Sequence[str] = (),
    halt_level: Level | None = None,
) -> CompositionResult:
    fragments = tuple(
        parse_evaluation_fragment(record, now=now, expected_subject_digest=subject_digest)
        for record in fragment_records
    )
    fragment_ids = [fragment.fragment_id for fragment in fragments]
    if len(fragment_ids) != len(set(fragment_ids)):
        raise GovernanceError("duplicate evaluation fragment id is forbidden")

    constraints = tuple(sorted({constraint for fragment in fragments if fragment.state is GateState.PASS for constraint in fragment.constraints}))
    constraint_gates, constraint_reasons = _constraint_conflicts(fragments)
    obligations, obligation_gates, obligation_reasons = _compose_obligations(fragments)

    gates = tuple(base_gate_results) + tuple(fragment.gate_result() for fragment in fragments) + tuple(constraint_gates) + tuple(obligation_gates)
    decision = evaluate_hierarchy(
        profile,
        gates,
        legitimate_conflict_levels=legitimate_conflict_levels,
        halt_reason_codes=halt_reason_codes,
        halt_level=halt_level,
    )
    empty_or_bound_fragment_digest = fragment_set_digest(fragments)
    constraint_digest = digest([item.payload() for item in constraints])
    obligation_digest = digest([item.payload() for item in obligations])
    return CompositionResult(
        hierarchy_decision=decision,
        constraints=constraints,
        obligations=obligations,
        fragment_set_digest=empty_or_bound_fragment_digest,
        constraint_set_digest=constraint_digest,
        obligation_set_digest=obligation_digest,
        conflict_reason_codes=tuple(sorted(set(constraint_reasons + obligation_reasons))),
    )


def bind_composition_to_clearance(
    governance_clearance: Mapping[str, Any],
    composition: CompositionResult,
) -> dict[str, Any]:
    """Bind composition evidence into an already-issued clearance record.

    This function cannot issue a clearance or alter its decision. It only adds
    deterministic evidence bindings and re-digests the resulting record.
    """
    receipt = deepcopy(dict(governance_clearance))
    if receipt.get("receipt_type") != "GOVERNANCE_CLEARANCE":
        raise GovernanceError("composition can only bind to GovernanceClearance")
    if receipt.get("decision") != composition.hierarchy_decision.verdict.value:
        raise GovernanceError("clearance decision does not match composition result")
    receipt.update({
        "evaluation_fragment_set_digest": composition.fragment_set_digest,
        "composed_constraint_set_digest": composition.constraint_set_digest,
        "composed_obligation_set_digest": composition.obligation_set_digest,
        "composition_decision_digest": composition.hierarchy_decision.decision_digest,
        "composition_profile_digest": composition.hierarchy_decision.profile_digest,
        "composition_conflict_reason_codes": list(composition.conflict_reason_codes),
    })
    if "receipt_digest" in receipt:
        receipt.pop("receipt_digest")
        receipt["receipt_digest"] = digest(receipt)
    return receipt
