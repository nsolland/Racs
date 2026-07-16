# Test for Shadow Intelligence Monitoring Simulation

import pytest
from simulate_shadow_intelligence_monitoring import ShadowIntelligenceMonitoringSimulation

class TestShadowIntelligenceMonitoringSimulation:
    def test_simulate_decision(self):
        simulation = ShadowIntelligenceMonitoringSimulation()
        simulation.simulate_decision("agent_1", "decision_made", "successful")
        report = simulation.generate_decision_report()
        assert len(report) == 1
        assert report[0]["agent_id"] == "agent_1"
        assert report[0]["decision"] == "decision_made"
        assert report[0]["outcome"] == "successful"
