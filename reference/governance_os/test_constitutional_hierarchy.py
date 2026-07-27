import unittest

from constitutional_hierarchy import (
    GateResult,
    GateState,
    HierarchyProfile,
    Level,
    Verdict,
    evaluate_hierarchy,
)


PROFILE = HierarchyProfile(
    profile_id="enterprise-default",
    version="1",
    required_gates={
        Level.CONSTITUTIONAL_LEGAL: ("constitution",),
        Level.AUTHORITY_MANDATE: ("authority",),
        Level.PURPOSE_SEMANTIC: ("purpose",),
    },
)


def passed(gate_id, level):
    return GateResult(gate_id, level, GateState.PASS)


class ConstitutionalHierarchyTests(unittest.TestCase):
    def baseline(self):
        return [
            passed("constitution", Level.CONSTITUTIONAL_LEGAL),
            passed("authority", Level.AUTHORITY_MANDATE),
            passed("purpose", Level.PURPOSE_SEMANTIC),
        ]

    def test_lower_level_cannot_override_constitutional_failure(self):
        results = self.baseline()
        results[0] = GateResult(
            "constitution", Level.CONSTITUTIONAL_LEGAL, GateState.FAIL,
            reason_code="CONSTITUTIONAL_PROHIBITION",
        )
        results.append(passed("high-value", Level.SOFT_PRIORITIES))
        decision = evaluate_hierarchy(PROFILE, results)
        self.assertEqual(Verdict.DENY, decision.verdict)
        self.assertEqual(Level.CONSTITUTIONAL_LEGAL, decision.decisive_level)

    def test_unknown_mandatory_authority_steps_up(self):
        results = self.baseline()
        results[1] = GateResult(
            "authority", Level.AUTHORITY_MANDATE, GateState.UNKNOWN,
            reason_code="AUTHORITY_STATE_UNKNOWN",
        )
        decision = evaluate_hierarchy(PROFILE, results)
        self.assertEqual(Verdict.STEP_UP, decision.verdict)

    def test_missing_required_gate_steps_up(self):
        decision = evaluate_hierarchy(PROFILE, [passed("constitution", Level.CONSTITUTIONAL_LEGAL)])
        self.assertEqual(Verdict.STEP_UP, decision.verdict)
        self.assertIn("MISSING_REQUIRED_GATE:authority_mandate:authority", decision.reason_codes)

    def test_legitimate_conflict_steps_up(self):
        results = self.baseline()
        results.append(GateResult(
            "rights-conflict", Level.RIGHTS_SAFETY, GateState.CONFLICT,
            reason_code="RIGHTS_CONFLICT_UNRESOLVED",
        ))
        decision = evaluate_hierarchy(
            PROFILE, results, legitimate_conflict_levels=(Level.RIGHTS_SAFETY,)
        )
        self.assertEqual(Verdict.STEP_UP, decision.verdict)

    def test_soft_failure_modifies_only_after_hard_gates_pass(self):
        results = self.baseline() + [GateResult(
            "preference", Level.SOFT_PRIORITIES, GateState.FAIL,
            reason_code="PREFERENCE_NOT_MET",
        )]
        decision = evaluate_hierarchy(PROFILE, results)
        self.assertEqual(Verdict.MODIFY, decision.verdict)

    def test_scheduling_failure_defers(self):
        results = self.baseline() + [GateResult(
            "window", Level.SCHEDULING, GateState.FAIL,
            reason_code="EXECUTION_WINDOW_CLOSED",
        )]
        decision = evaluate_hierarchy(PROFILE, results)
        self.assertEqual(Verdict.DEFER, decision.verdict)

    def test_deterministic_digest(self):
        results = self.baseline()
        first = evaluate_hierarchy(PROFILE, results)
        second = evaluate_hierarchy(PROFILE, reversed(results))
        self.assertEqual(first.decision_digest, second.decision_digest)


if __name__ == "__main__":
    unittest.main()
