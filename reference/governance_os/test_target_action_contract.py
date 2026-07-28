import copy
import unittest

from target_action_contract import (
    GovernanceError,
    digest,
    validate_target_action_contract,
)


NOW = "2026-07-28T06:45:30Z"


def contract():
    item = {
        "contract_version": "target-action-contract-0.3",
        "contract_id": "tac:payment.prepare:v3",
        "issuer": "payments-platform",
        "issuer_identity_digest": digest({"issuer": "payments-platform"}),
        "target_system_id": "payments:prod",
        "connector_id": "connector:payments-v2",
        "operation": "payment.prepare",
        "parameter_schema_digest": digest({"schema": "payment.prepare.v3"}),
        "semantic_effects": [
            {
                "effect_class": "financial_reservation",
                "description": "Reserves funds without settlement.",
                "consequential": True,
            }
        ],
        "side_effect_classes": ["financial_reservation"],
        "data_read_classes": ["confidential"],
        "data_write_classes": ["restricted_financial"],
        "visibility": "external",
        "reversibility": "conditionally_reversible",
        "rollback_capability": {
            "available": True,
            "requires_separate_authority": True,
            "maximum_window_seconds": 900,
        },
        "financial_effect": "commitment",
        "maximum_expected_cost": {"amount_minor": 250000, "currency": "NOK"},
        "privilege_required": "finance_preparer",
        "human_approval_requirement": "conditional",
        "receipt_requirement": [
            "governance_clearance",
            "execution_receipt",
            "outcome_evidence",
        ],
        "outcome_evidence_requirement": [
            "payment_reservation_status",
            "ledger_entry_reference",
        ],
        "valid_from": "2026-07-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
        "supersedes": None,
        "revocation_ref": "revocation:target-contracts/payments",
        "signature_scheme": "Ed25519",
        "signature_digest": digest({"signature": "target-contract"}),
        "signature_verified": True,
        "authority_granting": False,
        "digest_profile": "rfc8785-sha256-excluding:contract_digest",
        "contract_digest": "sha256:placeholder",
    }
    item["contract_digest"] = digest(
        {key: value for key, value in item.items() if key != "contract_digest"}
    )
    return item


def redigest(item):
    item["contract_digest"] = digest(
        {key: value for key, value in item.items() if key != "contract_digest"}
    )
    return item


class TargetActionContractTests(unittest.TestCase):
    def setUp(self):
        self.item = contract()

    def validate(self, item=None, **kwargs):
        return validate_target_action_contract(
            item or self.item,
            now=kwargs.pop("now", NOW),
            expected_target_system_id=kwargs.pop("target", "payments:prod"),
            expected_connector_id=kwargs.pop("connector", "connector:payments-v2"),
            expected_operation=kwargs.pop("operation", "payment.prepare"),
            **kwargs,
        )

    def test_valid_contract_returns_defensive_copy(self):
        result = self.validate()
        self.assertEqual(self.item, result)
        self.assertIsNot(self.item, result)

    def test_contract_cannot_grant_authority(self):
        item = copy.deepcopy(self.item)
        item["authority_granting"] = True
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "cannot grant principal authority"):
            self.validate(item=item)

    def test_unverified_signature_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["signature_verified"] = False
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "not verified"):
            self.validate(item=item)

    def test_expired_contract_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["expires_at"] = "2026-07-27T23:59:59Z"
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "inactive"):
            self.validate(item=item)

    def test_revoked_contract_is_rejected(self):
        with self.assertRaisesRegex(GovernanceError, "revoked"):
            self.validate(revoked_contract_ids=[self.item["contract_id"]])

    def test_target_mismatch_is_rejected(self):
        with self.assertRaisesRegex(GovernanceError, "target mismatch"):
            self.validate(target="payments:test")

    def test_connector_mismatch_is_rejected(self):
        with self.assertRaisesRegex(GovernanceError, "connector mismatch"):
            self.validate(connector="connector:payments-v3")

    def test_operation_mismatch_is_rejected(self):
        with self.assertRaisesRegex(GovernanceError, "operation mismatch"):
            self.validate(operation="payment.settle")

    def test_unknown_reversibility_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["reversibility"] = "unknown"
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "unknown reversibility"):
            self.validate(item=item)

    def test_missing_semantic_effect_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["semantic_effects"] = []
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "semantic_effects"):
            self.validate(item=item)

    def test_missing_execution_receipt_requirement_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["receipt_requirement"] = ["governance_clearance"]
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "execution receipt"):
            self.validate(item=item)

    def test_inconsistent_rollback_window_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["rollback_capability"]["available"] = False
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "active time window"):
            self.validate(item=item)

    def test_digest_mutation_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["operation"] = "payment.settle"
        with self.assertRaisesRegex(GovernanceError, "digest mismatch"):
            self.validate(item=item, operation="payment.settle")

    def test_missing_outcome_evidence_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["outcome_evidence_requirement"] = []
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "outcome_evidence_requirement"):
            self.validate(item=item)


if __name__ == "__main__":
    unittest.main()
