import importlib.util
from pathlib import Path
import sys
import unittest

BASE_MODULE = Path(__file__).with_name("governance_os_v0_1.py")
base_spec = importlib.util.spec_from_file_location("gos", BASE_MODULE)
gos = importlib.util.module_from_spec(base_spec)
sys.modules.setdefault("gos", gos)
base_spec.loader.exec_module(gos)

MODULE = Path(__file__).with_name("distributed_authority_v0_1.py")
spec = importlib.util.spec_from_file_location("distributed", MODULE)
distributed = importlib.util.module_from_spec(spec)
sys.modules.setdefault("distributed", distributed)
spec.loader.exec_module(distributed)


def fixtures():
    intent = {
        "intent_id": "BI-1",
        "board_authority": "board-resolution-2026-07",
        "purpose": "Procure approved compute",
        "allowed_outcomes": ["capacity acquired"],
        "prohibited_outcomes": ["unbounded commitment"],
        "approved_at": "2026-07-01T09:00:00Z",
    }
    case = {
        "case_id": "BC-1",
        "intent_id": "BI-1",
        "principal": "agent:buyer-1",
        "actions": ["purchase"],
        "resource_scope": ["compute:eu-west"],
        "max_single_exposure": 500,
        "max_cumulative_exposure": 1500,
        "valid_from": "2026-07-01T09:00:00Z",
        "valid_until": "2026-08-01T09:00:00Z",
        "evidence_digest": "sha256:evidence",
    }
    request = {
        "mandate_id": "EM-1",
        "version": "1",
        "principal": "agent:buyer-1",
        "actions": ["purchase"],
        "resource_scope": ["compute:eu-west"],
        "max_single_exposure": 500,
        "max_cumulative_exposure": 1500,
        "valid_from": "2026-07-02T09:00:00Z",
        "valid_until": "2026-07-31T09:00:00Z",
    }
    mandate = gos.compile_mandate(intent, case, request)
    grant = {
        "authority_id": "AUTH-1",
        "authority_version": "1",
        "issuer": "board:acme",
        "issued_at": "2026-07-02T09:00:00Z",
        "valid_until": "2026-07-31T09:00:00Z",
        "mandate_digest": mandate.mandate_digest,
        "total_exposure": 1200,
        "consequence_limits": {
            "COMPUTE_PURCHASE": {"max_count": 3, "max_exposure": 1000},
            "EXTERNAL_PUBLICATION": {"max_count": 1, "max_exposure": 100},
        },
        "forbidden_combinations": [
            {
                "policy_id": "NO_PURCHASE_PLUS_PUBLICATION",
                "classes": ["COMPUTE_PURCHASE", "EXTERNAL_PUBLICATION"],
            }
        ],
        "signature_scheme": "external-verifier:v1",
        "signature_digest": "sha256:signed-authority",
        "signature_verified": True,
    }
    state = {
        "authority_id": "AUTH-1",
        "authority_version": "1",
        "mandate_digest": mandate.mandate_digest,
        "revision": 0,
        "remaining_exposure": 1200,
        "revoked": False,
        "last_transition_digest": None,
        "updated_at": "2026-07-27T05:00:00Z",
    }
    snapshot = {
        "snapshot_id": "SNAP-1",
        "captured_at": "2026-07-27T05:00:30Z",
        "substrate_id": "cloud:one",
        "authority_id": "AUTH-1",
        "authority_version": "1",
        "authority_revision": 0,
        "mandate_digest": mandate.mandate_digest,
        "active": True,
    }
    action = {
        "action_id": "ACTION-1",
        "principal": "agent:buyer-1",
        "action": "purchase",
        "resource": "compute:eu-west",
        "exposure": 300,
        "evidence_digest": "sha256:live-evidence",
        "consequence_class": "COMPUTE_PURCHASE",
        "substrate_id": "cloud:one",
        "expected_authority_revision": 0,
    }
    return mandate, grant, state, snapshot, action


def hierarchy_context(constitution_state=None):
    state = constitution_state or distributed.GateState.PASS
    reason = "" if state is distributed.GateState.PASS else "CONSTITUTIONAL_PROHIBITION"
    profile = distributed.HierarchyProfile(
        profile_id="enterprise-distributed",
        version="1",
        required_gates={
            distributed.Level.CONSTITUTIONAL_LEGAL: ("constitution",),
            distributed.Level.AUTHORITY_MANDATE: ("distributed-authority",),
            distributed.Level.PURPOSE_SEMANTIC: ("purpose",),
            distributed.Level.EVIDENCE_REPRESENTATION: ("distributed-evidence",),
            distributed.Level.CONSEQUENCE: ("distributed-consequence",),
        },
    )
    upstream = (
        distributed.GateResult(
            "constitution",
            distributed.Level.CONSTITUTIONAL_LEGAL,
            state,
            reason_code=reason,
            evidence_digest="sha256:constitution",
        ),
        distributed.GateResult(
            "purpose",
            distributed.Level.PURPOSE_SEMANTIC,
            distributed.GateState.PASS,
            evidence_digest="sha256:purpose",
        ),
    )
    return profile, upstream


def evaluate(
    mandate,
    grant,
    state,
    snapshot,
    action,
    transitions,
    now="2026-07-27T05:01:00Z",
    constitution_state=None,
):
    profile, upstream = hierarchy_context(constitution_state)
    return distributed.evaluate_distributed_action(
        mandate,
        grant,
        state,
        snapshot,
        action,
        transitions,
        now,
        profile,
        upstream,
    )


def clear_and_apply(
    mandate,
    grant,
    state,
    snapshot,
    action,
    transitions,
    now="2026-07-27T05:01:00Z",
):
    clearance = evaluate(
        mandate, grant, state, snapshot, action, transitions, now
    )
    if clearance["decision"] != "ALLOW":
        return clearance, state, None
    next_state, transition = distributed.apply_authority_transition(
        grant, state, clearance, now
    )
    return clearance, next_state, transition


class DistributedAuthorityConformance(unittest.TestCase):
    def test_cross_substrate_consumption_updates_live_authority(self):
        mandate, grant, state, snapshot, action = fixtures()
        clearance, state, first = clear_and_apply(
            mandate, grant, state, snapshot, action, []
        )
        self.assertEqual(clearance["decision"], "ALLOW")
        self.assertEqual(state["revision"], 1)
        self.assertEqual(state["remaining_exposure"], 900)

        second_snapshot = dict(snapshot)
        second_snapshot.update(
            {
                "snapshot_id": "SNAP-2",
                "captured_at": "2026-07-27T05:01:20Z",
                "substrate_id": "cloud:two",
                "authority_revision": 1,
            }
        )
        second_action = dict(action)
        second_action.update(
            {
                "action_id": "ACTION-2",
                "substrate_id": "cloud:two",
                "expected_authority_revision": 1,
                "exposure": 400,
            }
        )
        second_clearance, state, second = clear_and_apply(
            mandate,
            grant,
            state,
            second_snapshot,
            second_action,
            [first],
            "2026-07-27T05:01:30Z",
        )
        self.assertEqual(second_clearance["decision"], "ALLOW")
        self.assertEqual(state["revision"], 2)
        self.assertEqual(state["remaining_exposure"], 500)
        distributed.validate_authority_state(grant, state, [first, second])

    def test_constitutional_hierarchy_cannot_be_bypassed(self):
        mandate, grant, state, snapshot, action = fixtures()
        receipt = evaluate(
            mandate,
            grant,
            state,
            snapshot,
            action,
            [],
            constitution_state=distributed.GateState.FAIL,
        )
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["remaining_exposure_after"], 1200)
        self.assertEqual(
            receipt["hierarchy_decisive_level"],
            distributed.Level.CONSTITUTIONAL_LEGAL.value,
        )
        with self.assertRaisesRegex(distributed.GovernanceError, "denied clearance"):
            distributed.apply_authority_transition(
                grant, state, receipt, "2026-07-27T05:01:00Z"
            )

    def test_stale_revision_fails_closed_through_authority_gate(self):
        mandate, grant, state, snapshot, action = fixtures()
        _, state, transition = clear_and_apply(
            mandate, grant, state, snapshot, action, []
        )
        stale_action = dict(action)
        stale_action["action_id"] = "ACTION-2"
        receipt = evaluate(
            mandate,
            grant,
            state,
            snapshot,
            stale_action,
            [transition],
            "2026-07-27T05:01:10Z",
        )
        self.assertEqual(receipt["decision"], "DENY")
        self.assertIn("STALE_AUTHORITY_REVISION", receipt["reasons"])
        self.assertIn("DISTRIBUTED_AUTHORITY_FAILED", receipt["reasons"])

    def test_compare_and_set_prevents_double_consumption(self):
        mandate, grant, state, snapshot, action = fixtures()
        clearance = evaluate(mandate, grant, state, snapshot, action, [])
        state_after, _ = distributed.apply_authority_transition(
            grant, state, clearance, "2026-07-27T05:01:00Z"
        )
        with self.assertRaisesRegex(distributed.GovernanceError, "compare-and-set"):
            distributed.apply_authority_transition(
                grant, state_after, clearance, "2026-07-27T05:01:01Z"
            )

    def test_cross_substrate_forbidden_composition_is_denied(self):
        mandate, grant, state, snapshot, action = fixtures()
        _, state, transition = clear_and_apply(
            mandate, grant, state, snapshot, action, []
        )
        second_snapshot = dict(snapshot)
        second_snapshot.update(
            {
                "snapshot_id": "SNAP-2",
                "captured_at": "2026-07-27T05:01:20Z",
                "substrate_id": "publisher:one",
                "authority_revision": 1,
            }
        )
        second_action = dict(action)
        second_action.update(
            {
                "action_id": "ACTION-2",
                "substrate_id": "publisher:one",
                "expected_authority_revision": 1,
                "consequence_class": "EXTERNAL_PUBLICATION",
                "exposure": 50,
            }
        )
        receipt = evaluate(
            mandate,
            grant,
            state,
            second_snapshot,
            second_action,
            [transition],
            "2026-07-27T05:01:30Z",
        )
        self.assertEqual(receipt["decision"], "DENY")
        self.assertIn(
            "FORBIDDEN_COMBINATION:NO_PURCHASE_PLUS_PUBLICATION",
            receipt["reasons"],
        )
        self.assertIn("DISTRIBUTED_CONSEQUENCE_FAILED", receipt["reasons"])

    def test_replay_and_consequence_accumulation_are_governed(self):
        mandate, grant, state, snapshot, action = fixtures()
        _, state, first = clear_and_apply(
            mandate, grant, state, snapshot, action, []
        )
        replay_snapshot = dict(snapshot)
        replay_snapshot.update(
            {
                "snapshot_id": "SNAP-2",
                "captured_at": "2026-07-27T05:01:20Z",
                "authority_revision": 1,
            }
        )
        replay = dict(action)
        replay["expected_authority_revision"] = 1
        receipt = evaluate(
            mandate,
            grant,
            state,
            replay_snapshot,
            replay,
            [first],
            "2026-07-27T05:01:30Z",
        )
        self.assertIn("ACTION_REPLAY", receipt["reasons"])

        large = dict(replay)
        large["action_id"] = "ACTION-2"
        large["exposure"] = 800
        receipt = evaluate(
            mandate,
            grant,
            state,
            replay_snapshot,
            large,
            [first],
            "2026-07-27T05:01:30Z",
        )
        self.assertIn("CONSEQUENCE_EXPOSURE_EXCEEDED", receipt["reasons"])
        self.assertIn("SINGLE_EXPOSURE_EXCEEDED", receipt["reasons"])

    def test_evidence_failure_uses_canonical_evidence_level(self):
        mandate, grant, state, snapshot, action = fixtures()
        action["evidence_digest"] = "not-bound"
        receipt = evaluate(mandate, grant, state, snapshot, action, [])
        self.assertEqual(receipt["decision"], "DENY")
        self.assertIn("EVIDENCE_NOT_BOUND", receipt["reasons"])
        self.assertEqual(
            receipt["hierarchy_decisive_level"],
            distributed.Level.EVIDENCE_REPRESENTATION.value,
        )

    def test_tampered_transition_history_fails_closed(self):
        mandate, grant, state, snapshot, action = fixtures()
        _, state, transition = clear_and_apply(
            mandate, grant, state, snapshot, action, []
        )
        tampered = dict(transition)
        tampered["exposure"] = 1
        with self.assertRaisesRegex(distributed.GovernanceError, "digest mismatch"):
            distributed.validate_authority_state(grant, state, [tampered])

    def test_revocation_signature_and_snapshot_freshness_fail_closed(self):
        mandate, grant, state, snapshot, action = fixtures()
        state["revoked"] = True
        receipt = evaluate(mandate, grant, state, snapshot, action, [])
        self.assertIn("AUTHORITY_REVOKED", receipt["reasons"])

        state["revoked"] = False
        bad_grant = dict(grant)
        bad_grant["signature_verified"] = False
        with self.assertRaisesRegex(distributed.GovernanceError, "signature"):
            evaluate(mandate, bad_grant, state, snapshot, action, [])

        stale_snapshot = dict(snapshot)
        stale_snapshot["captured_at"] = "2026-07-27T04:00:00Z"
        receipt = evaluate(
            mandate, grant, state, stale_snapshot, action, []
        )
        self.assertIn("STALE_AUTHORITY_SNAPSHOT", receipt["reasons"])

    def test_clearance_and_execution_receipts_remain_separate(self):
        mandate, grant, state, snapshot, action = fixtures()
        clearance, _, transition = clear_and_apply(
            mandate, grant, state, snapshot, action, []
        )
        execution = {
            "execution_id": "EXEC-1",
            "action_id": action["action_id"],
            "action_digest": clearance["action_digest"],
            "executed_at": "2026-07-27T05:01:05Z",
            "status": "SUCCEEDED",
            "outcome_ref": "outcome://compute-capacity/1",
            "substrate_id": action["substrate_id"],
        }
        execution_receipt = distributed.record_execution(
            clearance, transition, execution, []
        )
        self.assertEqual(clearance["receipt_type"], "GOVERNANCE_CLEARANCE")
        self.assertEqual(execution_receipt["receipt_type"], "EXECUTION")
        self.assertEqual(
            execution_receipt["clearance_receipt_digest"],
            clearance["receipt_digest"],
        )
        with self.assertRaisesRegex(distributed.GovernanceError, "duplicate execution"):
            distributed.record_execution(
                clearance, transition, execution, [execution_receipt]
            )

    def test_transition_order_does_not_change_clearance_digest(self):
        mandate, grant, state, snapshot, action = fixtures()
        _, state, first = clear_and_apply(
            mandate, grant, state, snapshot, action, []
        )
        second_snapshot = dict(snapshot)
        second_snapshot.update(
            {
                "snapshot_id": "SNAP-2",
                "captured_at": "2026-07-27T05:01:20Z",
                "authority_revision": 1,
            }
        )
        second_action = dict(action)
        second_action.update(
            {
                "action_id": "ACTION-2",
                "expected_authority_revision": 1,
                "exposure": 100,
            }
        )
        _, state, second = clear_and_apply(
            mandate,
            grant,
            state,
            second_snapshot,
            second_action,
            [first],
            "2026-07-27T05:01:30Z",
        )
        third_snapshot = dict(second_snapshot)
        third_snapshot.update(
            {
                "snapshot_id": "SNAP-3",
                "captured_at": "2026-07-27T05:01:40Z",
                "authority_revision": 2,
            }
        )
        third_action = dict(action)
        third_action.update(
            {
                "action_id": "ACTION-3",
                "expected_authority_revision": 2,
                "exposure": 50,
            }
        )
        one = evaluate(
            mandate,
            grant,
            state,
            third_snapshot,
            third_action,
            [first, second],
            "2026-07-27T05:01:45Z",
        )
        two = evaluate(
            mandate,
            grant,
            state,
            third_snapshot,
            third_action,
            [second, first],
            "2026-07-27T05:01:45Z",
        )
        self.assertEqual(one["receipt_digest"], two["receipt_digest"])
        self.assertEqual(
            one["hierarchy_gate_results_digest"],
            two["hierarchy_gate_results_digest"],
        )


if __name__ == "__main__":
    unittest.main()
