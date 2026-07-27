"""Deterministic governed importance, weighting and priority engine.

Soft prioritisation is evaluated only after constitutional hard gates have
admitted an alternative. Weights are versioned, scoped and bounded. Results
include sensitivity and counterfactual evidence rather than a bare score.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Dict, Iterable, Mapping, Sequence, Tuple


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Criterion:
    criterion_id: str
    direction: str  # "maximize" or "minimize"
    minimum_weight: float
    maximum_weight: float
    uncertainty_penalty: float = 1.0

    def validate(self) -> None:
        if self.direction not in {"maximize", "minimize"}:
            raise ValueError("INVALID_DIRECTION")
        if not (0.0 <= self.minimum_weight <= self.maximum_weight <= 1.0):
            raise ValueError("INVALID_WEIGHT_RANGE")
        if self.uncertainty_penalty < 0.0:
            raise ValueError("INVALID_UNCERTAINTY_PENALTY")


@dataclass(frozen=True)
class WeightProfile:
    profile_id: str
    version: str
    scope: str
    weights: Mapping[str, float]
    parent_profile_id: str | None = None


@dataclass(frozen=True)
class Assessment:
    value: float
    uncertainty: float = 0.0

    def validate(self) -> None:
        if not (0.0 <= self.value <= 1.0):
            raise ValueError("VALUE_OUT_OF_RANGE")
        if not (0.0 <= self.uncertainty <= 1.0):
            raise ValueError("UNCERTAINTY_OUT_OF_RANGE")


@dataclass(frozen=True)
class Alternative:
    alternative_id: str
    admissible: bool
    assessments: Mapping[str, Assessment]


@dataclass(frozen=True)
class PriorityResult:
    decision: str
    winner: str | None
    scores: Mapping[str, float]
    robust_margin: float
    decisive_criteria: Tuple[str, ...]
    counterfactual: Mapping[str, float]
    reason_codes: Tuple[str, ...]
    profile_digest: str
    result_digest: str


def validate_profile(criteria: Sequence[Criterion], profile: WeightProfile) -> None:
    known = {c.criterion_id: c for c in criteria}
    if set(profile.weights) != set(known):
        raise ValueError("WEIGHT_CRITERIA_MISMATCH")
    total = 0.0
    for criterion in criteria:
        criterion.validate()
        weight = profile.weights[criterion.criterion_id]
        if not criterion.minimum_weight <= weight <= criterion.maximum_weight:
            raise ValueError("WEIGHT_OUTSIDE_GOVERNED_RANGE")
        total += weight
    if abs(total - 1.0) > 1e-9:
        raise ValueError("WEIGHTS_MUST_SUM_TO_ONE")


def inherit_profile(parent: WeightProfile, child: WeightProfile, criteria: Sequence[Criterion]) -> WeightProfile:
    """Child scope may refine weights only inside governed criterion ranges."""
    if child.parent_profile_id != parent.profile_id:
        raise ValueError("PARENT_PROFILE_MISMATCH")
    validate_profile(criteria, child)
    return child


def _utility(criterion: Criterion, assessment: Assessment) -> float:
    assessment.validate()
    directional = assessment.value if criterion.direction == "maximize" else 1.0 - assessment.value
    return directional - criterion.uncertainty_penalty * assessment.uncertainty


def evaluate(
    criteria: Sequence[Criterion],
    profile: WeightProfile,
    alternatives: Iterable[Alternative],
    robustness_threshold: float = 0.05,
) -> PriorityResult:
    validate_profile(criteria, profile)
    alternatives = tuple(alternatives)
    admitted = tuple(a for a in alternatives if a.admissible)
    if not admitted:
        return _result("DENY", None, {}, 0.0, (), {}, ("NO_ADMISSIBLE_ALTERNATIVE",), profile)

    criterion_map = {c.criterion_id: c for c in criteria}
    scores: Dict[str, float] = {}
    contributions: Dict[str, Dict[str, float]] = {}
    for alternative in admitted:
        if set(alternative.assessments) != set(criterion_map):
            raise ValueError("ASSESSMENT_CRITERIA_MISMATCH")
        contributions[alternative.alternative_id] = {}
        score = 0.0
        for criterion_id in sorted(criterion_map):
            contribution = profile.weights[criterion_id] * _utility(
                criterion_map[criterion_id], alternative.assessments[criterion_id]
            )
            contributions[alternative.alternative_id][criterion_id] = contribution
            score += contribution
        scores[alternative.alternative_id] = round(score, 12)

    ranking = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    winner, winner_score = ranking[0]
    runner_score = ranking[1][1] if len(ranking) > 1 else winner_score
    margin = round(winner_score - runner_score, 12)

    decisive = tuple(
        criterion_id
        for criterion_id, _ in sorted(
            contributions[winner].items(), key=lambda item: (-abs(item[1]), item[0])
        )[:3]
    )

    counterfactual: Dict[str, float] = {}
    if len(ranking) > 1:
        runner = ranking[1][0]
        for criterion_id in sorted(criterion_map):
            delta = contributions[winner][criterion_id] - contributions[runner][criterion_id]
            counterfactual[criterion_id] = round(delta, 12)

    if len(ranking) > 1 and margin < robustness_threshold:
        return _result(
            "STEP_UP", winner, scores, margin, decisive, counterfactual,
            ("PRIORITY_NOT_ROBUST", "HUMAN_JUDGMENT_REQUIRED"), profile,
        )
    return _result("ALLOW", winner, scores, margin, decisive, counterfactual, ("ROBUST_PRIORITY_WINNER",), profile)


def _result(decision, winner, scores, margin, decisive, counterfactual, reasons, profile):
    profile_payload = {
        "profile_id": profile.profile_id,
        "version": profile.version,
        "scope": profile.scope,
        "weights": dict(sorted(profile.weights.items())),
        "parent_profile_id": profile.parent_profile_id,
    }
    profile_digest = _digest(profile_payload)
    result_payload = {
        "decision": decision,
        "winner": winner,
        "scores": dict(sorted(scores.items())),
        "robust_margin": margin,
        "decisive_criteria": decisive,
        "counterfactual": dict(sorted(counterfactual.items())),
        "reason_codes": reasons,
        "profile_digest": profile_digest,
    }
    return PriorityResult(
        decision, winner, scores, margin, tuple(decisive), counterfactual,
        tuple(reasons), profile_digest, _digest(result_payload),
    )
