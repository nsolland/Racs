import pytest
from racs_receipts import Receipt, validate_receipt, ReceiptError
from jsonschema.exceptions import ValidationError

# Define schema for receipt validation
_VALID_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        "action": {"type": "string"},
        "authority": {"type": "string"},
        "policy": {"type": "string"},
        "evidence": {"type": "string"}
    },
    "required": ["action", "authority", "policy", "evidence"]
}

# Test functions for validating receipt

def test_valid_receipt():
    receipt = Receipt(
        action='some_action',
        authority='user_id',
        policy='policy_id',
        evidence='evidence_id'
    )
    validate_receipt({
        "action": receipt.action,
        "authority": receipt.authority,
        "policy": receipt.policy,
        "evidence": receipt.evidence,
        "schema": _VALID_SCHEMA
    })  # Valid schema provided


def test_invalid_receipt_empty_policy():
    receipt = Receipt(
        action='some_action',
        authority='user_id',
        policy='',  # Triggering validation error
        evidence='evidence_id'
    )
    # Validate receipt, expect to catch validation error
    with pytest.raises(ValidationError):
        validate_receipt({
            "action": receipt.action,
            "authority": receipt.authority,
            "policy": receipt.policy,
            "evidence": receipt.evidence,
            "schema": _VALID_SCHEMA
        })