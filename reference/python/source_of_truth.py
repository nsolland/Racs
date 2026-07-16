# Source-of-Truth Implementation for Trust Economy

# Source-of-Truth Implementation for Trust Economy

from typing import Any

class SourceOfTruth:
    """Manages authoritative data sources and validation mechanisms."""

    def __init__(self):
        self.data = {}  # Holds trusted data entries

    def add_data_entry(self, key: str, value: Any) -> None:
        """Adds a new data entry to the source of truth."""
        self.data[key] = value

    def validate_entry(self, key: str, expected_value: Any) -> bool:
        """Checks if the data entry matches the expected value."""
        return key in self.data and self.data[key] == expected_value

    def remove_data_entry(self, key: str) -> None:
        """Removes an entry from the source of truth."""
        if key in self.data:
            del self.data[key]

    def generate_audit_log(self) -> dict:
        """Generates an audit log of existing data entries for traceability."""
        return {key: value for key, value in self.data.items()}


class DataValidator:
    """Validates actions against entries in the Source of Truth."""

    def __init__(self, source: SourceOfTruth):
        self.source = source

    def can_proceed_with_action(self, action_id: str, expected_value: Any) -> bool:
        """Validates whether the specified action can proceed based on trusted data."""
        return self.source.validate_entry(action_id, expected_value)

    def audit_data(self):
        """Audit the source of truth entries for integrity."""
        audit_log = self.source.generate_audit_log()
        # Further auditing logic can be added as necessary
        print(audit_log)

    """Manages authoritative data sources and validation mechanisms."""

    def __init__(self):
        self.data = {}  # Holds trusted data entries

    def add_data_entry(self, key: str, value: Any) -> None:
        """Adds a new data entry to the source of truth."""
        self.data[key] = value

    def validate_entry(self, key: str, expected_value: Any) -> bool:
        """Checks if the data entry matches the expected value."""
        return key in self.data and self.data[key] == expected_value

    def remove_data_entry(self, key: str) -> None:
        """Removes an entry from the source of truth."""
        if key in self.data:
            del self.data[key]

    def generate_audit_log(self) -> dict:
        """Generates an audit log of existing data entries for traceability."""
        return {key: value for key, value in self.data.items()}


class DataValidator:
    """Validates actions against entries in the Source of Truth."""

    def __init__(self, source: SourceOfTruth):
        self.source = source

    def can_proceed_with_action(self, action_id: str, expected_value: Any) -> bool:
        """Validates whether the specified action can proceed based on trusted data."""
        return self.source.validate_entry(action_id, expected_value)

    def audit_data(self):
        """Audit the source of truth entries for integrity."""
        audit_log = self.source.generate_audit_log()
        # Further auditing logic can be added as necessary
        print(audit_log)
