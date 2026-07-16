# Test for Shadow Execution Control Simulation

import pytest
from simulate_shadow_execution_control import ShadowExecutionControlSimulation

class TestShadowExecutionControlSimulation:
    def test_simulate_action(self):
        simulation = ShadowExecutionControlSimulation()
        simulation.simulate_action("agent_1", "execute_task", True)
        report = simulation.generate_simulation_report()
        assert len(report) == 1
        assert report[0]["agent_id"] == "agent_1"
        assert report[0]["action"] == "execute_task"
        assert report[0]["success"] is True
