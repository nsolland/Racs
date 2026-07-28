import copy
import unittest

from task_authority import (
    GovernanceError,
    digest,
    reject_standing_grant_for_execution,
    validate_task_authority_materialization,
)


NOW = "2026-07-28T06:45:30Z"
POLICY_DIGEST = digest({"policy": "v5"})
CONTRACT_DIGEST = digest({"target-contract": "v3"})


def parent_grant():
    return {
        "grant_id": "grant:17",
        "principal_binding_digest": digest({"principal": "org:example"}),
        "agent_identity_digest": digest({"agent": "ap-1"}),
        "delegation_chain_digest": digest({"chain": "17"}),
        "purpose_refs": ["purpose:accounts-payable"],
        "allowed_action_types": ["payment.prepare", "invoice.read"],
        "allowed_target_ids": ["invoice:1042", "vendor:77"],
        "allowed_capabilities": ["payment.prepare", "erp.invoice.read"],
        "resource_constraints": {
            "invoice_ids": ["1042", "1043"],
            "vendor_ids": ["77"],
            "environment": "production",
        },
        "maximum_consequence_class": "financial_commitment_low",
        "reversibility_ceiling": "conditionally_reversible",
        "data_class_ceiling": "confidential",
        "privilege_ceiling": "finance_preparer",
        "spend_limit": {"amount_minor": 500000, "currency": "NOK"},
        "max_action_count": 2,
        "valid_from": "2026-07-28T06:00:00Z",
        "valid_until": "2026-07-28T07:00:00Z",
        "authorized_materializer_ids": ["authority-materializer-1"],
        "revoked": False,
    }


def authority_state():
    return {
        "grant_id": "grant:17",
        "revision": 7,
        "revoked": False,
        "updated_at": "2026-07-28T06:45:00Z",
    }


def materialization(parent, state):
    item = {
        "materialization_version": "task-authority-materialization-0.3",
        "task_authority_id": "task-auth:invoice-1042",
        "principal_binding_digest": parent["principal_binding_digest"],
        "agent_identity_digest": parent["agent_identity_digest"],
        "parent_authority_grant_digest": digest(parent),
        "parent_authority_state_digest": digest(state),
        "authority_state_revision": state["revision"],
        "delegation_chain_digest": parent["delegation_chain_digest"],
        "task_id": "task:approve-invoice-1042",
        "purpose_refs": ["purpose:accounts-payable"],
        "task_scope": {
            "allowed_action_types": ["payment.prepare"],
            "allowed_target_ids": ["invoice:1042"],
            "allowed_capabilities": ["payment.prepare"],
            "resource_constraints": {
                "invoice_ids": ["1042"],
                "vendor_ids": ["77"],
                "environment": "production",
            },
            "maximum_consequence_class": parent["maximum_consequence_class"],
            "reversibility_ceiling": parent["reversibility_ceiling"],
            "data_class_ceiling": parent["data_class_ceiling"],
            "privilege_ceiling": parent["privilege_ceiling"],
            "spend_limit": {"amount_minor": 250000, "currency": "NOK"},
        },
        "policy_snapshot_digests": [POLICY_DIGEST],
        "target_action_contract_digests": [CONTRACT_DIGEST],
        "valid_from": "2026-07-28T06:40:00Z",
        "expires_at": "2026-07-28T06:50:00Z",
        "max_action_count": 1,
        "nonce": "7c0d1f58a88d4a7f9d43e0aa",
        "materialized_at": "2026-07-28T06:45:00Z",
        "materializer_id": "authority-materializer-1",
        "self_refresh_allowed": False,
        "execution_authority": "NONE",
        "digest_profile": "rfc8785-sha256-excluding:materialization_digest",
        "materialization_digest": "sha256:placeholder",
        "signature_or_attestation": {
            "scheme": "Ed25519",
            "signer_id": "authority-materializer-1",
            "signed_payload_digest": digest({"claim": "materialized"}),
            "signature_digest": digest({"signature": "materializer"}),
            "verified": True,
        },
    }
    item["materialization_digest"] = digest(
        {key: value for key, value in item.items() if key != "materialization_digest"}
    )
    return item


def redigest(item):
    item["materialization_digest"] = digest(
        {key: value for key, value in item.items() if key != "materialization_digest"}
    )
    return item


class TaskAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.parent = parent_grant()
        self.state = authority_state()
        self.item = materialization(self.parent, self.state)
        self.contracts = [{"contract_digest": CONTRACT_DIGEST}]

    def validate(self, item=None, parent=None, state=None, **kwargs):
        return validate_task_authority_materialization(
            item or self.item,
            parent or self.parent,
            state or self.state,
            current_policy_snapshot_digests=kwargs.pop("policies", [POLICY_DIGEST]),
            target_contracts=kwargs.pop("contracts", self.contracts),
            now=kwargs.pop("now", NOW),
            **kwargs,
        )

    def test_valid_materialization_returns_defensive_copy(self):
        result = self.validate()
        self.assertEqual(self.item, result)
        self.assertIsNot(self.item, result)

    def test_standing_grant_is_rejected_at_execution_boundary(self):
        with self.assertRaisesRegex(GovernanceError, "standing authority"):
            reject_standing_grant_for_execution({"grant_id": "grant:17", "standing": True})

    def test_action_scope_widening_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["task_scope"]["allowed_action_types"].append("payment.settle")
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "widens parent authority"):
            self.validate(item=item)

    def test_resource_scope_widening_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["task_scope"]["resource_constraints"]["invoice_ids"].append("9999")
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "resource constraints"):
            self.validate(item=item)

    def test_spend_widening_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["task_scope"]["spend_limit"]["amount_minor"] = 500001
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "spend limit"):
            self.validate(item=item)

    def test_authority_revision_change_invalidates_materialization(self):
        state = copy.deepcopy(self.state)
        state["revision"] = 8
        with self.assertRaisesRegex(GovernanceError, "revision is stale"):
            self.validate(state=state)

    def test_policy_snapshot_change_invalidates_materialization(self):
        with self.assertRaisesRegex(GovernanceError, "policy snapshot"):
            self.validate(policies=[digest({"policy": "v6"})])

    def test_target_contract_change_invalidates_materialization(self):
        with self.assertRaisesRegex(GovernanceError, "target action contract"):
            self.validate(contracts=[{"contract_digest": digest({"target-contract": "v4"})}])

    def test_expired_materialization_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["expires_at"] = "2026-07-28T06:44:00Z"
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "inactive"):
            self.validate(item=item)

    def test_revoked_authority_is_rejected(self):
        state = copy.deepcopy(self.state)
        state["revoked"] = True
        with self.assertRaisesRegex(GovernanceError, "revoked"):
            self.validate(state=state)

    def test_reused_nonce_is_rejected(self):
        with self.assertRaisesRegex(GovernanceError, "already been used"):
            self.validate(used_nonces=[self.item["nonce"]])

    def test_self_refresh_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["self_refresh_allowed"] = True
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "cannot self-refresh"):
            self.validate(item=item)

    def test_unauthorized_materializer_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["materializer_id"] = "agent:ap-1"
        item["signature_or_attestation"]["signer_id"] = "agent:ap-1"
        redigest(item)
        with self.assertRaisesRegex(GovernanceError, "not authorized"):
            self.validate(item=item)

    def test_digest_mutation_is_rejected(self):
        item = copy.deepcopy(self.item)
        item["task_scope"]["allowed_target_ids"] = ["invoice:1043"]
        with self.assertRaisesRegex(GovernanceError, "digest mismatch"):
            self.validate(item=item)

    def test_stale_authority_state_is_rejected(self):
        state = copy.deepcopy(self.state)
        state["updated_at"] = "2026-07-28T06:30:00Z"
        item = materialization(self.parent, state)
        with self.assertRaisesRegex(GovernanceError, "authority state is stale"):
            self.validate(item=item, state=state)


if __name__ == "__main__":
    unittest.main()
