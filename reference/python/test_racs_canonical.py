import pytest
from racs_receipts import Receipt, validate_receipt, ReceiptError

# Test functions for validating receipt

def test_empty_authority_context():
    receipt = Receipt(
        action='some_action',
        authority='',  # Here it should be empty to trigger validation
        policy='policy_id',
        evidence='evidence_id'
    )
    with pytest.raises(ReceiptError):  # Expecting a ReceiptError
        receipt.validate()


def test_empty_policy_context():
    receipt = Receipt(
        action='some_action',
        authority='user_id',
        policy='',  # Set empty here
        evidence='evidence_id'
    )
    with pytest.raises(ReceiptError):
        receipt.validate()


def test_empty_evidence_package():
    receipt = Receipt(
        action='some_action',
        authority='user_id',
        policy='policy_id',
        evidence=''  # Also empty here
    )
    with pytest.raises(ReceiptError):
        receipt.validate()