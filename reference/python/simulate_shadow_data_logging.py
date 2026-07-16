# Shadow Data Logging Simulation

import time

class ShadowDataLoggingSimulation:
    """Simulates logging decisions and actions in shadow mode."""

    def __init__(self):
        self.simulated_logs = []  # Maintain a simulation log of actions

    def log_simulated_action(self, agent_id: str, action: str):
        """Log every action taken by the agent in simulation mode."""
        self.simulated_logs.append({
            "agent_id": agent_id,
            "action": action,
            "timestamp": time.time()
        })

    def retrieve_logs(self) -> list:
        """Returns all logged simulated actions."""
        return self.simulated_logs

    """Simulates logging decisions and actions in shadow mode."""

    def __init__(self):
        self.simulated_logs = []  # Maintain a simulation log of actions

    def log_simulated_action(self, agent_id: str, action: str):
        """Log every action taken by the agent in simulation mode."""
        self.simulated_logs.append({
            "agent_id": agent_id,
            "action": action,
            "timestamp": time.time()
        })

    def retrieve_logs(self) -> list:
        """Returns all logged simulated actions."""
        return self.simulated_logs
