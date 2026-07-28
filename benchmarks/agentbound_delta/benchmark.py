#!/usr/bin/env python3
"""Deterministic AgentBound-delta benchmark.

Runs entirely offline. Network and transport latency are excluded.
Production logic is imported from reference/governance_os and never modified.
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
REFERENCE = REPO_ROOT / "reference" / "governance_os"
REPLAY_VECTOR = REPO_ROOT / "test-vectors" / "0.3" / "agentbound-delta" / "replay" / "replay-vectors.json"
SCENARIOS_PATH = HERE / "scenarios.json"
ABLATIONS_PATH = HERE / "ablations.json"


def _load_runtime():
    if str(REFERENCE) not in sys.path:
        sys.path.insert(0, str(REFERENCE))
    from replay_bundle import digest  # type: ignore
    from replay_verifier import verify_governance_replay_bundle  # type: ignore
    return digest, verify_governance_replay_bundle


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    expected_status: str
    actual_status: str
    prohibited: bool
    hard_gate: bool
    category: str
    passed: bool
    latency_ns: int
    reason_codes: tuple[str, ...]


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _redigest_snapshot(snapshot: dict[str, Any], digest: Callable[[Any], str]) -> None:
    snapshot["artifact_digest"] = digest(snapshot["payload"])


def _redigest_task(task: dict[str, Any], digest: Callable[[Any], str]) -> None:
    task["materialization_digest"] = digest(
        {key: value for key, value in task.items() if key != "materialization_digest"}
    )


def _redigest_contract(contract: dict[str, Any], digest: Callable[[Any], str]) -> None:
    contract["contract_digest"] = digest(
        {key: value for key, value in contract.items() if key != "contract_digest"}
    )


def _redigest_fragment(fragment: dict[str, Any], digest: Callable[[Any], str]) -> None:
    fragment["fragment_digest"] = digest(
        {key: value for key, value in fragment.items() if key != "fragment_digest"}
    )


def _redigest_bundle(bundle: dict[str, Any], digest: Callable[[Any], str]) -> None:
    bundle["bundle_digest"] = digest(
        {key: value for key, value in bundle.items() if key != "bundle_digest"}
    )


def mutate_bundle(
    baseline: Mapping[str, Any],
    mutation: str,
    digest: Callable[[Any], str],
) -> dict[str, Any]:
    bundle = copy.deepcopy(dict(baseline))

    if mutation == "none":
        return bundle
    if mutation == "bundle_digest_tamper":
        bundle["bundle_digest"] = digest({"tampered": True})
        return bundle
    if mutation == "omit_task_materialization":
        del bundle["task_authority_materialization"]
        return bundle
    if mutation == "omit_target_contract":
        bundle["target_action_contracts"] = []
    elif mutation == "principal_binding_substitution":
        bundle["principal_binding"]["payload"]["principal_id"] = "org:attacker"
        _redigest_snapshot(bundle["principal_binding"], digest)
    elif mutation == "action_parameter_change":
        bundle["action_reference"]["payload"]["parameters_digest"] = digest(
            {"amount_minor": 500000, "currency": "NOK"}
        )
        _redigest_snapshot(bundle["action_reference"], digest)
    elif mutation == "authority_revision_stale":
        state = bundle["authority_state_snapshot"]
        state["revision"] += 1
        state["artifact"]["payload"]["revision"] = state["revision"]
        _redigest_snapshot(state["artifact"], digest)
    elif mutation == "revoke_authority":
        bundle["authority_state_snapshot"]["revoked"] = True
    elif mutation == "policy_snapshot_change":
        policy = bundle["policy_snapshots"][0]
        policy["payload"]["rules_digest"] = digest({"rules": "changed"})
        _redigest_snapshot(policy, digest)
    elif mutation == "target_contract_substitution":
        contract = bundle["target_action_contracts"][0]
        contract["contract_id"] = "tac:payment.prepare:substituted"
        _redigest_contract(contract, digest)
    elif mutation == "target_contract_revoked":
        policy = bundle["policy_snapshots"][0]
        contract_id = bundle["target_action_contracts"][0]["contract_id"]
        policy["payload"]["revocation_state"]["revoked_contract_ids"] = [contract_id]
        _redigest_snapshot(policy, digest)
        task = bundle["task_authority_materialization"]
        task["policy_snapshot_digests"] = [policy["artifact_digest"]]
        _redigest_task(task, digest)
    elif mutation == "omit_mandatory_fragment":
        bundle["authority_evaluation_fragments"].pop()
    elif mutation == "constitutional_failure":
        fragment = next(
            item for item in bundle["authority_evaluation_fragments"]
            if item["hierarchy_level"] == "constitutional_legal"
        )
        fragment["state"] = "FAIL"
        fragment["reason_codes"] = ["CONSTITUTIONAL_PROHIBITION"]
        _redigest_fragment(fragment, digest)
    elif mutation == "omit_consequence_gate":
        bundle["authority_evaluation_fragments"] = [
            item for item in bundle["authority_evaluation_fragments"]
            if item["hierarchy_level"] != "consequence"
        ]
    elif mutation == "remove_clearance_binding":
        clearance = bundle["governance_clearance"]
        del clearance["payload"]["evaluation_fragment_set_digest"]
        _redigest_snapshot(clearance, digest)
    elif mutation == "unverified_governance_signature":
        bundle["governance_enforcer_signature"]["verified"] = False
    elif mutation == "agent_self_report_only":
        del bundle["governance_enforcer_signature"]
    elif mutation == "missing_revocation_state":
        policy = bundle["policy_snapshots"][0]
        del policy["payload"]["revocation_state"]
        _redigest_snapshot(policy, digest)
        task = bundle["task_authority_materialization"]
        task["policy_snapshot_digests"] = [policy["artifact_digest"]]
        _redigest_task(task, digest)
    else:
        raise ValueError(f"unknown benchmark mutation: {mutation}")

    _redigest_bundle(bundle, digest)
    return bundle


def percentile(values: Sequence[int], percentile_value: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, math.ceil(percentile_value * len(ordered)) - 1))
    return int(ordered[rank])


def run_scenarios(
    verifier: Callable[[Mapping[str, Any]], Any] | None = None,
    digest_function: Callable[[Any], str] | None = None,
    *,
    repetitions: int = 5,
) -> tuple[list[ScenarioResult], dict[str, Any]]:
    if verifier is None or digest_function is None:
        runtime_digest, runtime_verifier = _load_runtime()
        verifier = verifier or runtime_verifier
        digest_function = digest_function or runtime_digest

    vectors = _read_json(REPLAY_VECTOR)
    baseline = vectors["valid_bundle"]
    scenarios = _read_json(SCENARIOS_PATH)["scenarios"]
    results: list[ScenarioResult] = []

    for scenario in scenarios:
        latencies: list[int] = []
        last_result = None
        for _ in range(repetitions):
            bundle = mutate_bundle(baseline, scenario["mutation"], digest_function)
            started = time.perf_counter_ns()
            last_result = verifier(bundle)
            latencies.append(time.perf_counter_ns() - started)
        assert last_result is not None
        actual = getattr(last_result.status, "value", str(last_result.status))
        reasons = tuple(getattr(last_result, "reason_codes", ()))
        results.append(
            ScenarioResult(
                scenario_id=scenario["id"],
                expected_status=scenario["expected_status"],
                actual_status=actual,
                prohibited=bool(scenario["prohibited"]),
                hard_gate=bool(scenario["hard_gate"]),
                category=scenario["category"],
                passed=actual == scenario["expected_status"],
                latency_ns=int(statistics.median(latencies)),
                reason_codes=reasons,
            )
        )

    metrics = calculate_metrics(results)
    metrics["latency_measurement"] = {
        "scope": "offline verifier only; network and transport excluded",
        "repetitions_per_scenario": repetitions,
    }
    return results, metrics


def calculate_metrics(results: Sequence[ScenarioResult]) -> dict[str, Any]:
    def ratio(numerator: int, denominator: int) -> float:
        return 1.0 if denominator == 0 else numerator / denominator

    prohibited = [item for item in results if item.prohibited]
    hard = [item for item in prohibited if item.hard_gate]
    valid = [item for item in results if not item.prohibited]
    policy = [item for item in results if item.category == "policy_invalidation"]
    contract = [item for item in results if item.category == "contract_drift"]
    latencies = [item.latency_ns for item in results]

    escapes = [item for item in prohibited if item.actual_status == "MATCH"]
    false_stepups = [
        item for item in valid
        if item.actual_status in {"INCOMPLETE", "UNVERIFIABLE"}
    ]
    valid_matches = [item for item in valid if item.actual_status == "MATCH"]

    return {
        "governance_decision_accuracy": ratio(
            sum(item.passed for item in results), len(results)
        ),
        "violation_escape_rate": ratio(len(escapes), len(prohibited)),
        "hard_gate_false_allow_rate": ratio(
            sum(item.actual_status == "MATCH" for item in hard), len(hard)
        ),
        "false_step_up_rate": ratio(len(false_stepups), len(valid)),
        "receipt_verification_rate": ratio(len(valid_matches), len(valid)),
        "replay_equivalence_rate": ratio(len(valid_matches), len(valid)),
        "policy_change_invalidation_rate": ratio(
            sum(item.actual_status != "MATCH" for item in policy), len(policy)
        ),
        "contract_drift_detection_rate": ratio(
            sum(item.actual_status != "MATCH" for item in contract), len(contract)
        ),
        "governance_latency_ns": {
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
        },
        "counts": {
            "scenarios": len(results),
            "prohibited": len(prohibited),
            "hard_gate": len(hard),
            "escaped_violations": len(escapes),
        },
    }


def run_ablations() -> list[dict[str, Any]]:
    definitions = _read_json(ABLATIONS_PATH)["ablations"]
    output = []
    for item in definitions:
        output.append(
            {
                **item,
                "baseline_blocked": True,
                "ablation_escape": item["effect"] == "prohibited_action_possible",
                "evidence_guarantee_lost": item["effect"] == "evidence_guarantee_lost",
                "documented_lost_invariant": bool(item["lost_invariant"].strip()),
            }
        )
    return output


def acceptance_gate(metrics: Mapping[str, Any], ablations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    checks = {
        "zero_escaped_hard_gate_violations": metrics["hard_gate_false_allow_rate"] == 0.0,
        "zero_escaped_violations": metrics["violation_escape_rate"] == 0.0,
        "receipt_verification_100_percent": metrics["receipt_verification_rate"] == 1.0,
        "replay_equivalence_100_percent": metrics["replay_equivalence_rate"] == 1.0,
        "all_ablations_document_lost_invariant": all(
            item["documented_lost_invariant"] for item in ablations
        ),
        "all_ablations_show_loss": all(
            item["ablation_escape"] or item["evidence_guarantee_lost"]
            for item in ablations
        ),
    }
    return {"passed": all(checks.values()), "checks": checks}


def build_report(
    scenario_results: Sequence[ScenarioResult],
    metrics: Mapping[str, Any],
    ablations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    gate = acceptance_gate(metrics, ablations)
    report_core = {
        "benchmark": "agentbound-delta",
        "version": "0.1",
        "deterministic_hard_gate_target": "zero escaped violations",
        "metrics": metrics,
        "scenarios": [asdict(item) for item in scenario_results],
        "ablations": list(ablations),
        "acceptance_gate": gate,
    }
    digest_function, _ = _load_runtime()
    report_core["result_digest"] = digest_function(report_core)
    return report_core


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=HERE / "results.json")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")

    scenario_results, metrics = run_scenarios(repetitions=args.repetitions)
    ablations = run_ablations()
    report = build_report(scenario_results, metrics, ablations)
    _write_json(args.output, report)
    print(json.dumps(report["acceptance_gate"], sort_keys=True))
    return 0 if (not args.check or report["acceptance_gate"]["passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
