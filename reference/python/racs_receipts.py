import jsonschema
import json
import os
from typing import Any, Dict, Optional

class ReceiptError(Exception):
    """Raised on receipt construction or validation failure."""

    def __init__(self, message: str):
        super().__init__(message)


def validate_receipt(payload: Any) -> None:
    # Check if payload is a Receipt object
    if isinstance(payload, Receipt):
        payload = payload.__dict__  
    # Validate presence of required fields
    if not payload.get("action"):
        raise ReceiptError("Action cannot be empty")
    if not payload.get("authority"):
        raise ReceiptError("Authority cannot be empty")
    if not payload.get("policy"):
        raise ReceiptError("Policy cannot be empty")  # Empty policy should raise error
    if not payload.get("evidence"):
        raise ReceiptError("Evidence cannot be empty")
    # Validate schema presence
    schema = payload.get("schema")
    if not schema:
        raise ReceiptError("Schema must be provided for validation.")
    jsonschema.validate(instance=payload, schema=schema)

class Receipt:
    """Represents a RACS receipt with all necessary fields."""
    def __init__(self, *, action: str, authority: str, policy: str, evidence: str):
        self.action = action
        self.authority = authority
        self.policy = policy
        self.evidence = evidence
        self.payload_digest = sha256_digest(self.__dict__)
        self.schema_version = "0.2.0"
        self.issued_at = _now_iso()  

    def validate(self) -> None:
        if not self.action:
            raise ReceiptError("Action cannot be empty.")
        if not self.authority:
            raise ReceiptError("Authority cannot be empty.")
        if not self.policy:
            raise ReceiptError("Policy cannot be empty.")
        if not self.evidence:
            raise ReceiptError("Evidence cannot be empty.")

__all__ = ["Receipt", "validate_receipt", "ReceiptError"]