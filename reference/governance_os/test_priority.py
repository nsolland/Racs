import unittest

from priority import Assessment, Alternative, Criterion, WeightProfile, evaluate, inherit_profile


CRITERIA = (
    Criterion("expected_value", "maximize", 0.2, 0.7, 0.5),
    Criterion("reversibility", "maximize", 0.1, 0.5, 0.5),
    Criterion("resource_use", "minimize", 0.1, 0.5, 1.0),
)
PROFILE = WeightProfile(
    "enterprise-default", "1", "enterprise",
    {"expected_value": 0.5, "reversibility": 0.2, "resource_use": 0.3},
)


def alt(name, admitted, value, reversible, resource, uncertainty=0.0):
    return Alternative(name, admitted, {
        "expected_value": Assessment(value, uncertainty),
        "reversibility": Assessment(reversible, uncertainty),
        "resource_use": Assessment(resource, uncertainty),
    })


class PriorityTests(unittest.TestCase):
    def test_inadmissible_high_score_cannot_win(self):
        result = evaluate(CRITERIA, PROFILE, (
            alt("constitutionally_blocked", False, 1.0, 1.0, 0.0),
            alt("admissible", True, 0.7, 0.8, 0.3),
        ))
        self.assertEqual(result.decision, "ALLOW")
        self.assertEqual(result.winner, "admissible")
        self.assertNotIn("constitutionally_blocked", result.scores)

    def test_uncertainty_can_require_step_up(self):
        result = evaluate(CRITERIA, PROFILE, (
            alt("a", True, 0.70, 0.70, 0.30, 0.10),
            alt("b", True, 0.69, 0.70, 0.30, 0.10),
        ), robustness_threshold=0.02)
        self.assertEqual(result.decision, "STEP_UP")
        self.assertIn("PRIORITY_NOT_ROBUST", result.reason_codes)

    def test_robust_winner_has_counterfactual_and_digest(self):
        result = evaluate(CRITERIA, PROFILE, (
            alt("a", True, 0.95, 0.90, 0.10),
            alt("b", True, 0.50, 0.40, 0.80),
        ))
        self.assertEqual(result.decision, "ALLOW")
        self.assertEqual(result.winner, "a")
        self.assertTrue(result.counterfactual)
        self.assertEqual(len(result.profile_digest), 64)
        self.assertEqual(len(result.result_digest), 64)

    def test_weights_outside_governed_range_rejected(self):
        bad = WeightProfile("bad", "1", "enterprise", {
            "expected_value": 0.8, "reversibility": 0.1, "resource_use": 0.1,
        })
        with self.assertRaisesRegex(ValueError, "WEIGHT_OUTSIDE_GOVERNED_RANGE"):
            evaluate(CRITERIA, bad, (alt("a", True, 0.5, 0.5, 0.5),))

    def test_scope_inheritance_requires_parent_binding(self):
        child = WeightProfile("team", "1", "team:a", dict(PROFILE.weights), "wrong")
        with self.assertRaisesRegex(ValueError, "PARENT_PROFILE_MISMATCH"):
            inherit_profile(PROFILE, child, CRITERIA)

    def test_deterministic_result(self):
        alternatives = (
            alt("b", True, 0.6, 0.5, 0.4),
            alt("a", True, 0.6, 0.5, 0.4),
        )
        first = evaluate(CRITERIA, PROFILE, alternatives)
        second = evaluate(CRITERIA, PROFILE, reversed(alternatives))
        self.assertEqual(first.winner, "a")
        self.assertEqual(first.result_digest, second.result_digest)


if __name__ == "__main__":
    unittest.main()
