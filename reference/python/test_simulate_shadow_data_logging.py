# Test for Shadow Data Logging Simulation

import pytest
from simulate_shadow_data_logging import ShadowDataLoggingSimulation

class TestShadowDataLoggingSimulation:
    def test_log_simulated_action(self):
        simulation = ShadowDataLoggingSimulation()
        simulation.log_simulated_action("agent_1", "logging action")
        logs = simulation.retrieve_logs()
        assert len(logs) == 1
        assert logs[0]["agent_id"] == "agent_1"
        assert logs[0]["action"] == "logging action"
