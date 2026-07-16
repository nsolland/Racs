# Trust Economy Validation Checks

from trust_metrics import TrustMetric, TrustMonitor

class TrustValidator:
    """Handles the validation of trust-related operations and decisions."""

    def __init__(self, trust_monitor: TrustMonitor):
        self.trust_monitor = trust_monitor

    def validate_interaction(self, agent_id: str, action: str) -> bool:
        """Validates whether an interaction can proceed based on the trust status of the agent."""
        metric = self.trust_monitor.get_or_create_metric(agent_id)
        current_status = metric.get_trust_status()

        if current_status == "Low Trust":
            print(f"Interaction {action} denied for agent {agent_id} due to low trust.")
            return False
        elif current_status == "High Trust":
            print(f"Interaction {action} approved for agent {agent_id}. High trust.")
            return True
        else:
            print(f"Interaction {action} under review for agent {agent_id}.")
            return True  # Moderate trust can proceed after additional checks

    def audit_interactions(self):
        """Generate audit reports on trust metrics and agent interactions."""
        print("--- Auditing Trust Interactions ---")
        self.trust_monitor.report_metrics()

    """Handles the validation of trust-related operations and decisions."""

    def __init__(self, trust_monitor: TrustMonitor):
        self.trust_monitor = trust_monitor

    def validate_interaction(self, agent_id: str, action: str) -> bool:
        """Validates whether an interaction can proceed based on the trust status of the agent."""
        metric = self.trust_monitor.get_or_create_metric(agent_id)
        current_status = metric.get_trust_status()

        if current_status == "Low Trust":
            print(f"Interaction {action} denied for agent {agent_id} due to low trust.")
            return False
        elif current_status == "High Trust":
            print(f"Interaction {action} approved for agent {agent_id}. High trust.")
            return True
        else:
            print(f"Interaction {action} under review for agent {agent_id}.")
            return True  # Moderate trust can proceed after additional checks

    def audit_interactions(self):
        """Generate audit reports on trust metrics and agent interactions."""
        print("--- Auditing Trust Interactions ---")
        self.trust_monitor.report_metrics()
