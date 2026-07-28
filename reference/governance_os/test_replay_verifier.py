import copy
import json
from pathlib import Path
import unittest

from replay_bundle import digest
from replay_verifier import ReplayStatus, verify_governance_replay_bundle

VECTOR_PATH = Path(__file__).parents[2] / "test-vectors/0.3/agentbound-delta/replay/replay-vectors.json"


def fixture():
    return copy.deepcopy(json.loads(VECTOR_PATH.read_text())["valid_bundle"])


def redigest_bundle(bundle):
    bundle["bundle_digest"] = digest({key: value for key, value in bundle.items() if key != "bundle_digest"})
    return bundle


def redigest_snapshot(snapshot):
    snapshot["artifact_digest"] = digest(snapshot["payload"])
    return snapshot


def redigest_contract(contract):
    contract["contract_digest"] = digest({key: value for key, value in contract.items() if key != "contract_digest"})
    return contract


def redigest_task(task):
    task["materialization_digest"] = digest({key: value for key, value in task.items() if key != "materialization_digest"})
    return task


class ReplayVerifierTests(unittest.TestCase):
    def test_valid_bundle_matches(self):
        result = verify_governance_replay_bundle(fixture())
        self.assertEqual(ReplayStatus.MATCH, result.status)
        self.assertEqual((), result.reason_codes)
        self.assertEqual(result.supplied_bundle_digest, result.recomputed_bundle_digest)
        self.assertEqual(result.supplied_decision, result.recomputed_decision)

    def test_result_is_deterministic(self):
        first = verify_governance_replay_bundle(fixture())
        second = verify_governance_replay_bundle(fixture())
        self.assertEqual(first.result_digest, second.result_digest)

    def test_missing_bundle_field_is_incomplete(self):
        bundle = fixture()
        del bundle["reason_code_profile"]
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.INCOMPLETE, result.status)

    def test_bundle_digest_mutation_is_mismatch(self):
        bundle = fixture()
        bundle["bundle_digest"] = digest({"tampered": True})
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)

    def test_omitted_mandatory_fragment_is_incomplete(self):
        bundle = fixture()
        bundle["authority_evaluation_fragments"].pop()
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.INCOMPLETE, result.status)
        self.assertIn("mandatory evaluation fragments", result.reason_codes[0])

    def test_action_parameter_substitution_is_mismatch(self):
        bundle = fixture()
        bundle["action_reference"]["payload"]["parameters_digest"] = digest({"amount_minor": 500000, "currency": "NOK"})
        redigest_snapshot(bundle["action_reference"])
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)

    def test_target_contract_substitution_is_mismatch(self):
        bundle = fixture()
        contract = bundle["target_action_contracts"][0]
        contract["contract_id"] = "tac:payment.prepare:v4"
        redigest_contract(contract)
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)
        self.assertIn("target action contract set mismatch", result.reason_codes[0])

    def test_stale_authority_revision_is_mismatch(self):
        bundle = fixture()
        bundle["authority_state_snapshot"]["revision"] = 8
        bundle["authority_state_snapshot"]["artifact"]["payload"]["revision"] = 8
        redigest_snapshot(bundle["authority_state_snapshot"]["artifact"])
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)
        self.assertIn("authority state substitution", result.reason_codes[0])

    def test_revoked_authority_is_mismatch(self):
        bundle = fixture()
        bundle["authority_state_snapshot"]["revoked"] = True
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)
        self.assertIn("authority was revoked", result.reason_codes[0])

    def test_revoked_target_contract_is_mismatch(self):
        bundle = fixture()
        policy = bundle["policy_snapshots"][0]
        policy["payload"]["revocation_state"]["revoked_contract_ids"] = [bundle["target_action_contracts"][0]["contract_id"]]
        redigest_snapshot(policy)
        bundle["task_authority_materialization"]["policy_snapshot_digests"] = [policy["artifact_digest"]]
        redigest_task(bundle["task_authority_materialization"])
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)
        self.assertIn("target action contract was revoked", result.reason_codes[0])

    def test_missing_revocation_state_is_unverifiable(self):
        bundle = fixture()
        policy = bundle["policy_snapshots"][0]
        del policy["payload"]["revocation_state"]
        redigest_snapshot(policy)
        bundle["task_authority_materialization"]["policy_snapshot_digests"] = [policy["artifact_digest"]]
        redigest_task(bundle["task_authority_materialization"])
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.UNVERIFIABLE, result.status)

    def test_unverified_governance_signature_is_unverifiable(self):
        bundle = fixture()
        bundle["governance_enforcer_signature"]["verified"] = False
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.UNVERIFIABLE, result.status)

    def test_unverified_target_contract_is_unverifiable(self):
        bundle = fixture()
        contract = bundle["target_action_contracts"][0]
        contract["signature_verified"] = False
        redigest_contract(contract)
        bundle["task_authority_materialization"]["target_action_contract_digests"] = [contract["contract_digest"]]
        redigest_task(bundle["task_authority_materialization"])
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.UNVERIFIABLE, result.status)

    def test_unsupported_canonicalization_is_unverifiable(self):
        bundle = fixture()
        bundle["canonicalization_profile"]["profile_id"] = "OTHER"
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.UNVERIFIABLE, result.status)

    def test_clearance_missing_binding_is_incomplete(self):
        bundle = fixture()
        clearance = bundle["governance_clearance"]
        del clearance["payload"]["evaluation_fragment_set_digest"]
        redigest_snapshot(clearance)
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.INCOMPLETE, result.status)

    def test_clearance_cannot_claim_execution_receipt(self):
        bundle = fixture()
        clearance = bundle["governance_clearance"]
        clearance["payload"]["execution_receipt"] = True
        redigest_snapshot(clearance)
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)
        self.assertIn("conflated", result.reason_codes[0])

    def test_composition_decision_mutation_is_mismatch(self):
        bundle = fixture()
        bundle["composition_result"]["verdict"] = "DENY"
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)
        self.assertIn("composition verdict mismatch", result.reason_codes[0])

    def test_governance_signature_must_bind_recomputed_decision(self):
        bundle = fixture()
        bundle["governance_enforcer_signature"]["signed_payload_digest"] = bundle["governance_clearance"]["artifact_digest"]
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)
        self.assertIn("governance signature decision binding", result.reason_codes[0])

    def test_proposer_signature_must_bind_exact_action(self):
        bundle = fixture()
        bundle["proposer_signature_or_attestation"]["signed_payload_digest"] = digest({"other": "action"})
        redigest_bundle(bundle)
        result = verify_governance_replay_bundle(bundle)
        self.assertEqual(ReplayStatus.MISMATCH, result.status)
        self.assertIn("proposer signature action binding", result.reason_codes[0])


if __name__ == "__main__":
    unittest.main()
