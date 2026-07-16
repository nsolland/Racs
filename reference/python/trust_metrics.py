# Trust Metrics Implementation for Trust Economy

class TrustMetric:
    """Represents a trust metric for an agent based on historical interactions."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.trust_score = 1.0  # Initialize to a neutral score
        self.history = []  # Tracks changes in trust over time
        self.action_weights = {"read": 0.1, "write": 0.2}  # Example weighting based on action type

    def update_trust_score(self, change: float, action: str):
        """Update the trust score based on interactions; calculates based on action weight and time decay."""
        weight = self.action_weights.get(action, 0.1)   # Default weight
        self.trust_score += change * weight
        self.history.append((action, change, self.trust_score))  # Track action performance
        self.validate_trust_score()  # Ensure score is within bounds

    def adjust_for_time_decay(self, time_period: float):
        """Adjust score based on the time factor; older interactions decay trust value."""
        # Simple decay model — new metrics can introduce complexity
        decay_rate = 0.05
        self.trust_score *= (1 - decay_rate) ** time_period
        self.validate_trust_score()  # Validate the adjusted score

    def validate_trust_score(self):
        """Ensure the trust score remains within valid bounds (0 to 1)."""
        if self.trust_score < 0:
            self.trust_score = 0
        elif self.trust_score > 1:
            self.trust_score = 1

    def get_trust_status(self) -> str:
        """Returns current trust status based on thresholds."""
        if self.trust_score < 0.5:
            return "Low Trust"
        elif self.trust_score < 0.8:
            return "Moderate Trust"
        else:
            return "High Trust"

    def get_history(self):
        """Returns the history of trust changes."""
        return self.history

    def reset_history(self):
        """Resets the history of interactions."""
        self.history = []

    """Represents a trust metric for an agent based on historical interactions."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.trust_score = 1.0  # Initialize to a neutral score
        self.history = []  # Tracks changes in trust over time
        self.action_weights = {"read": 0.1, "write": 0.2}  # Example weighting based on action type

    def update_trust_score(self, change: float, action: str):
        """Update the trust score based on interactions. Calculate and apply weights for actions."""
        weight = self.action_weights.get(action, 0.1)   # Default to a neutral weight if not found
        self.trust_score += change * weight
        self.history.append((change, self.trust_score))
        self.validate_trust_score()

    def validate_trust_score(self):
        """Ensure the trust score remains within valid bounds (0 to 1)."""
        if self.trust_score < 0:
            self.trust_score = 0
        elif self.trust_score > 1:
            self.trust_score = 1

    def get_trust_status(self) -> str:
        """Returns the current trust status based on trust value's thresholds."""
        if self.trust_score < 0.5:
            return "Low Trust"
        elif self.trust_score < 0.8:
            return "Moderate Trust"
        else:
            return "High Trust"

    def get_history(self):
        """Return the history of trust score changes."""
        return self.history

    def reset_history(self):
        """Reset the history of trust interactions."""
        self.history = []

    """Represents a trust metric for an agent based on historical interactions."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.trust_score = 1.0  # Initialize to a neutral score
        self.history = []  # Tracks changes in trust over time

    def update_trust_score(self, change: float):
        """Update the trust score based on interactions. Positive or negative modifications should reflect specific interactions."""
        self.trust_score += change
        self.history.append((change, self.trust_score))
        self.validate_trust_score()

    def validate_trust_score(self):
        """Ensure the trust score remains within valid bounds (0 to 1)."""
        if self.trust_score < 0:
            self.trust_score = 0
        elif self.trust_score > 1:
            self.trust_score = 1

    def get_trust_status(self) -> str:
        """Returns the current trust status based on trust value's thresholds."""
        if self.trust_score < 0.5:
            return "Low Trust"
        elif self.trust_score < 0.8:
            return "Moderate Trust"
        else:
            return "High Trust"


class TrustMonitor:
    """Monitors interactions and updates trust metrics accordingly."""

    def __init__(self):
        self.metrics = {}

    def get_or_create_metric(self, agent_id: str) -> TrustMetric:
        if agent_id not in self.metrics:
            self.metrics[agent_id] = TrustMetric(agent_id)
        return self.metrics[agent_id]

    def record_interaction(self, agent_id: str, positive: bool):
        """Record an interaction and update the agent's trust score based on whether it was positive or negative."""
        metric = self.get_or_create_metric(agent_id)
        change = 0.1 if positive else -0.1  # Example scoring system
        metric.update_trust_score(change)

    def report_metrics(self):
        for metric in self.metrics.values():
            print(f"Agent: {metric.agent_id}, Trust Score: {metric.trust_score}, Status: {metric.get_trust_status()}")
