import sys
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).with_name("governance_os_v0_1.py")
spec = importlib.util.spec_from_file_location("gos", MODULE)
gos = importlib.util.module_from_spec(spec)
sys.modules["gos"] = gos
spec.loader.exec_module(gos)



def fixtures():
    intent = {
        "intent_id": "BI-1", "board_authority": "board-resolution-2026-07",
        "purpose": "Procure approved compute", "allowed_outcomes": ["capacity acquired"],
        "prohibited_outcomes": ["unbounded commitment"], "approved_at": "2026-07-01T09:00:00Z",
    }
    case = {
        "case_id": "BC-1", "intent_id": "BI-1", "principal": "agent:buyer-1",
        "actions": ["purchase"], "resource_scope": ["compute:eu-west"],
        "max_single_exposure": 1000, "max_cumulative_exposure": 3000,
        "valid_from": "2026-07-01T09:00:00Z", "valid_until": "2026-08-01T09:00:00Z",
        "evidence_digest": "sha256:evidence",
    }
    request = {
        "mandate_id": "EM-1", "version": "1", "principal": "agent:buyer-1",
        "actions": ["purchase"], "resource_scope": ["compute:eu-west"],
        "max_single_exposure": 500, "max_cumulative_exposure": 1500,
        "valid_from": "2026-07-02T09:00:00Z", "valid_until": "2026-07-31T09:00:00Z",
    }
    snapshot = {
        "snapshot_id": "AGS-1", "captured_at": "2026-07-27T05:00:00Z",
        "active_paths": [{"mandate_id": "EM-1", "principal": "agent:buyer-1", "active": True}],
        "revoked_mandates": [], "cumulative_exposure": {"EM-1": 400},
    }
    action = {
        "action_id": "A-1", "principal": "agent:buyer-1", "action": "purchase",
        "resource": "compute:eu-west", "exposure": 500, "evidence_digest": "sha256:live-evidence",
    }
    return intent, case, request, snapshot, action


class GovernanceOSConformance(unittest.TestCase):
    def test_happy_path_and_determinism(self):
        intent, case, request, snapshot, action = fixtures()
        first = gos.compile_mandate(intent, case, request)
        second = gos.compile_mandate(intent, case, request)
        self.assertEqual(first.mandate_digest, second.mandate_digest)
        receipt = gos.evaluate_action(first, snapshot, action, "2026-07-27T05:01:00Z")
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertTrue(receipt["human_authority_final"])

    def test_action_widening_fails_closed(self):
        intent, case, request, _, _ = fixtures()
        request["actions"] = ["purchase", "publish"]
        with self.assertRaisesRegex(gos.GovernanceError, "action widening"):
            gos.compile_mandate(intent, case, request)

    def test_resource_and_exposure_are_live_checked(self):
        intent, case, request, snapshot, action = fixtures()
        mandate = gos.compile_mandate(intent, case, request)
        action["resource"] = "compute:us-east"
        action["exposure"] = 1200
        receipt = gos.evaluate_action(mandate, snapshot, action, "2026-07-27T05:01:00Z")
        self.assertEqual(receipt["decision"], "DENY")
        self.assertIn("RESOURCE_OUT_OF_SCOPE", receipt["reasons"])
        self.assertIn("SINGLE_EXPOSURE_EXCEEDED", receipt["reasons"])

    def test_revocation_cascades_to_denial(self):
        intent, case, request, snapshot, action = fixtures()
        mandate = gos.compile_mandate(intent, case, request)
        snapshot["revoked_mandates"] = ["EM-1"]
        receipt = gos.evaluate_action(mandate, snapshot, action, "2026-07-27T05:01:00Z")
        self.assertEqual(receipt["decision"], "DENY")
        self.assertIn("MANDATE_REVOKED", receipt["reasons"])

    def test_changed_evidence_changes_receipt(self):
        intent, case, request, snapshot, action = fixtures()
        mandate = gos.compile_mandate(intent, case, request)
        one = gos.evaluate_action(mandate, snapshot, action, "2026-07-27T05:01:00Z")
        action["evidence_digest"] = "sha256:changed"
        two = gos.evaluate_action(mandate, snapshot, action, "2026-07-27T05:01:00Z")
        self.assertNotEqual(one["receipt_digest"], two["receipt_digest"])


if __name__ == "__main__":
    unittest.main()
