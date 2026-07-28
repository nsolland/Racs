import json
import unittest

from benchmark import (
    ABLATIONS_PATH,
    SCENARIOS_PATH,
    ScenarioResult,
    acceptance_gate,
    calculate_metrics,
    percentile,
    run_ablations,
)


class BenchmarkHarnessTests(unittest.TestCase):
    def test_scenario_ids_and_mutations_are_unique(self):
        data = json.loads(SCENARIOS_PATH.read_text())
        ids = [item["id"] for item in data["scenarios"]]
        mutations = [item["mutation"] for item in data["scenarios"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(mutations), len(set(mutations)))

    def test_all_required_ablations_exist(self):
        data = json.loads(ABLATIONS_PATH.read_text())
        ids = {item["id"] for item in data["ablations"]}
        self.assertEqual(
            {
                "remove_principal_binding",
                "remove_task_materialization",
                "remove_target_contract",
                "remove_authority_state_freshness",
                "remove_constitutional_hierarchy",
                "remove_consequence_gate",
                "remove_replay_protection",
                "remove_receipt_verification",
                "trust_agent_self_report",
                "allow_stale_policy_snapshots",
            },
            ids,
        )

    def test_all_ablations_document_loss(self):
        for item in run_ablations():
            self.assertTrue(item["documented_lost_invariant"])
            self.assertTrue(item["ablation_escape"] or item["evidence_guarantee_lost"])

    def test_percentile_is_deterministic(self):
        values = [50, 10, 30, 20, 40]
        self.assertEqual(30, percentile(values, 0.50))
        self.assertEqual(50, percentile(values, 0.95))
        self.assertEqual(50, percentile(values, 0.99))

    def test_metrics_and_acceptance_gate(self):
        results = [
            ScenarioResult(
                scenario_id="valid",
                expected_status="MATCH",
                actual_status="MATCH",
                prohibited=False,
                hard_gate=False,
                category="valid",
                passed=True,
                latency_ns=100,
                reason_codes=(),
            ),
            ScenarioResult(
                scenario_id="hard-deny",
                expected_status="MISMATCH",
                actual_status="MISMATCH",
                prohibited=True,
                hard_gate=True,
                category="policy_invalidation",
                passed=True,
                latency_ns=200,
                reason_codes=("blocked",),
            ),
            ScenarioResult(
                scenario_id="contract-deny",
                expected_status="INCOMPLETE",
                actual_status="INCOMPLETE",
                prohibited=True,
                hard_gate=True,
                category="contract_drift",
                passed=True,
                latency_ns=300,
                reason_codes=("blocked",),
            ),
        ]
        metrics = calculate_metrics(results)
        gate = acceptance_gate(metrics, run_ablations())
        self.assertEqual(1.0, metrics["governance_decision_accuracy"])
        self.assertEqual(0.0, metrics["violation_escape_rate"])
        self.assertEqual(0.0, metrics["hard_gate_false_allow_rate"])
        self.assertEqual(1.0, metrics["receipt_verification_rate"])
        self.assertTrue(gate["passed"])

    def test_escape_fails_acceptance_gate(self):
        results = [
            ScenarioResult(
                scenario_id="valid",
                expected_status="MATCH",
                actual_status="MATCH",
                prohibited=False,
                hard_gate=False,
                category="valid",
                passed=True,
                latency_ns=100,
                reason_codes=(),
            ),
            ScenarioResult(
                scenario_id="escaped",
                expected_status="MISMATCH",
                actual_status="MATCH",
                prohibited=True,
                hard_gate=True,
                category="authority",
                passed=False,
                latency_ns=100,
                reason_codes=(),
            ),
        ]
        metrics = calculate_metrics(results)
        self.assertFalse(acceptance_gate(metrics, run_ablations())["passed"])


if __name__ == "__main__":
    unittest.main()
