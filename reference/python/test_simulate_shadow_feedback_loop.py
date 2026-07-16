# Test for Shadow Feedback Loop Simulation

import pytest
from simulate_shadow_feedback_loop import ShadowFeedbackLoopSimulation

class TestShadowFeedbackLoopSimulation:
    def test_collect_simulated_feedback(self):
        simulation = ShadowFeedbackLoopSimulation()
        simulation.collect_simulated_feedback("agent_1", "It worked perfectly!")
        feedback = simulation.generate_feedback_report()
        assert len(feedback) == 1
        assert feedback[0]["agent_id"] == "agent_1"
        assert feedback[0]["feedback"] == "It worked perfectly!"
