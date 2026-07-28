import copy
import unittest

from composition import (
    GovernanceError,
    bind_composition_to_clearance,
    compose_evaluation_fragments,
    digest,
)
from constitutional_hierarchy import (
    GateResult,
    GateState,
    HierarchyProfile,
    Level,
    Verdict,
)

NOW = "2026-07-28T07:30:00Z"
SUBJECT = digest({"action": "A-1"})

PROFILE = HierarchyProfile(
    profile_id="agentbound-delta",
    version="1",
    required_gates={
        Level.CONSTITUTIONAL_LEGAL: ("constitution",),
        Level.AUTHORITY_MANDATE: ("authority", "fragment:authority"),
        Level.PURPOSE_SEMANTIC: ("purpose",),
        Level.CONSEQUENCE: ("fragment:consequence",),
    },
)


def base_gates():
    return (
        GateResult("constitution", Level.CONSTITUTIONAL_LEGAL, GateState.PASS),
        GateResult("authority", Level.AUTHORITY_MANDATE, GateState.PASS),
        GateResult("purpose", Level.PURPOSE_SEMANTIC, GateState.PASS),
    )


def fragment(
    fragment_id,
    level,
    *,
    state="PASS",
    reasons=None,
    constraints=None,
    obligations=None,
    subject=SUBJECT,
):
    item = {
        "fragment_version": "authority-evaluation-fragment-0.3",
        "fragment_id": fragment_id,
        "evaluator_id": f"evaluator:{fragment_id}",
        "evaluator_role": "independent_validator",
        "hierarchy_level": level.value,
        "subject_digest": subject,
        "policy_or_contract_digest": digest({"policy": fragment_id}),
        "state": state,
        "mandatory": True,
        "constraints": constraints or [],
        "obligations": obligations or [],
        "reason_codes": reasons or [],
        "evidence_digest": digest({"evidence": fragment_id}),
        "evaluated_at": "2026-07-28T07:29:00Z",
        "expires_at": "2026-07-28T07:35:00Z",
        "authority_effect": "NO_AUTHORITY_CREATION",
        "can_issue_clearance": False,
        "digest_profile": "rfc8785-sha256-excluding:fragment_digest",
        "fragment_digest": "sha256:placeholder",
        "signature_or_attestation": {
            "scheme": "Ed25519",
            "signer_id": f"evaluator:{fragment_id}",
            "signed_payload_digest": digest({"submitted": fragment_id}),
            "signature_digest": digest({"signature": fragment_id}),
            "verified": True,
        },
    }
    item["fragment_digest"] = digest(
        {key: value for key, value in item.items() if key != "fragment_digest"}
    )
    return item


def default_fragments():
    return [
        fragment(
            "fragment:authority",
            Level.AUTHORITY_MANDATE,
            constraints=[{
                "constraint_id": "limit:spend",
                "namespace": "spend.maximum",
                "operator": "MAX",
                "value_digest": digest({"amount_minor": 250000, "currency": "NOK"}),
            }],
            obligations=[{
                "obligation_id": "obligation:approval",
                "kind": "human_approval",
                "payload_digest": digest({"role": "controller"}),
                "must_be_satisfied_before": "commit",
            }],
        ),
        fragment(
            "fragment:consequence",
            Level.CONSEQUENCE,
            constraints=[{
                "constraint_id": "limit:visibility",
                "namespace": "visibility",
                "operator": "EQUALS",
                "value_digest": digest("external"),
            }],
            obligations=[{
                "obligation_id": "obligation:receipt",
                "kind": "execution_receipt",
                "payload_digest": digest({"required": True}),
                "must_be_satisfied_before": "outcome_close",
            }],
        ),
    ]


def compose(records=None, **kwargs):
    return compose_evaluation_fragments(
        PROFILE,
        base_gates(),
        records if records is not None else default_fragments(),
        now=NOW,
        subject_digest=SUBJECT,
        **kwargs,
    )


class MonotoneCompositionTests(unittest.TestCase):
    def test_all_hard_fragments_pass_and_restrictions_accumulate(self):
        result = compose()
        self.assertEqual(Verdict.ALLOW, result.hierarchy_decision.verdict)
        self.assertEqual(2, len(result.constraints))
        self.assertEqual(2, len(result.obligations))

    def test_order_does_not_change_digests(self):
        first = compose(default_fragments())
        second = compose(list(reversed(default_fragments())))
        self.assertEqual(first.fragment_set_digest, second.fragment_set_digest)
        self.assertEqual(first.constraint_set_digest, second.constraint_set_digest)
        self.assertEqual(first.obligation_set_digest, second.obligation_set_digest)
        self.assertEqual(first.hierarchy_decision.decision_digest, second.hierarchy_decision.decision_digest)

    def test_hard_failure_cannot_be_overridden_by_pass(self):
        records = default_fragments()
        records[0] = fragment(
            "fragment:authority",
            Level.AUTHORITY_MANDATE,
            state="FAIL",
            reasons=["AUTHORITY_REVOKED"],
        )
        result = compose(records)
        self.assertEqual(Verdict.DENY, result.hierarchy_decision.verdict)

    def test_missing_mandatory_fragment_steps_up(self):
        result = compose(default_fragments()[1:])
        self.assertEqual(Verdict.STEP_UP, result.hierarchy_decision.verdict)
        self.assertIn("MISSING_REQUIRED_GATE:authority_mandate:fragment:authority", result.hierarchy_decision.reason_codes)

    def test_opaque_equals_conflict_denies_at_hard_level(self):
        records = default_fragments()
        records.append(fragment(
            "fragment:consequence-2",
            Level.CONSEQUENCE,
            constraints=[{
                "constraint_id": "limit:visibility-2",
                "namespace": "visibility",
                "operator": "EQUALS",
                "value_digest": digest("private"),
            }],
        ))
        result = compose(records)
        self.assertEqual(Verdict.DENY, result.hierarchy_decision.verdict)
        self.assertIn("CONSTRAINT_INTERSECTION_UNPROVEN:visibility:EQUALS", result.conflict_reason_codes)

    def test_legitimate_constraint_conflict_steps_up(self):
        records = default_fragments()
        records.append(fragment(
            "fragment:consequence-2",
            Level.CONSEQUENCE,
            constraints=[{
                "constraint_id": "limit:visibility-2",
                "namespace": "visibility",
                "operator": "EQUALS",
                "value_digest": digest("private"),
            }],
        ))
        result = compose(records, legitimate_conflict_levels=(Level.CONSEQUENCE,))
        self.assertEqual(Verdict.STEP_UP, result.hierarchy_decision.verdict)

    def test_obligations_union_without_erasure(self):
        result = compose()
        ids = {item.obligation_id for item in result.obligations}
        self.assertEqual({"obligation:approval", "obligation:receipt"}, ids)

    def test_conflicting_obligation_definition_denies(self):
        records = default_fragments()
        records.append(fragment(
            "fragment:consequence-2",
            Level.CONSEQUENCE,
            obligations=[{
                "obligation_id": "obligation:receipt",
                "kind": "publish_receipt",
                "payload_digest": digest({"required": True}),
                "must_be_satisfied_before": "commit",
            }],
        ))
        result = compose(records)
        self.assertEqual(Verdict.DENY, result.hierarchy_decision.verdict)
        self.assertIn("OBLIGATION_DEFINITION_CONFLICT:obligation:receipt", result.conflict_reason_codes)

    def test_independent_halt_dominates_all_passes(self):
        result = compose(halt_reason_codes=("OUT_OF_BAND_HALT",))
        self.assertEqual(Verdict.HALT, result.hierarchy_decision.verdict)

    def test_fragment_cannot_create_authority(self):
        item = default_fragments()[0]
        item["authority_effect"] = "AUTHORITY_CREATED"
        item["fragment_digest"] = digest({key: value for key, value in item.items() if key != "fragment_digest"})
        with self.assertRaisesRegex(GovernanceError, "cannot create authority"):
            compose([item, default_fragments()[1]])

    def test_expired_fragment_is_rejected(self):
        item = default_fragments()[0]
        item["expires_at"] = "2026-07-28T07:20:00Z"
        item["fragment_digest"] = digest({key: value for key, value in item.items() if key != "fragment_digest"})
        with self.assertRaisesRegex(GovernanceError, "inactive"):
            compose([item, default_fragments()[1]])

    def test_subject_substitution_is_rejected(self):
        item = fragment("fragment:authority", Level.AUTHORITY_MANDATE, subject=digest({"action": "A-2"}))
        with self.assertRaisesRegex(GovernanceError, "subject mismatch"):
            compose([item, default_fragments()[1]])

    def test_duplicate_fragment_id_is_rejected(self):
        records = default_fragments()
        records.append(copy.deepcopy(records[0]))
        with self.assertRaisesRegex(GovernanceError, "duplicate evaluation fragment"):
            compose(records)

    def test_digest_mutation_is_rejected(self):
        item = default_fragments()[0]
        item["state"] = "FAIL"
        item["reason_codes"] = ["TAMPERED"]
        with self.assertRaisesRegex(GovernanceError, "digest mismatch"):
            compose([item, default_fragments()[1]])

    def test_composition_binds_to_existing_clearance_without_changing_decision(self):
        result = compose()
        clearance = {
            "receipt_type": "GOVERNANCE_CLEARANCE",
            "decision": "ALLOW",
            "action_id": "A-1",
            "receipt_digest": "sha256:old",
        }
        bound = bind_composition_to_clearance(clearance, result)
        self.assertEqual("ALLOW", bound["decision"])
        self.assertEqual(result.fragment_set_digest, bound["evaluation_fragment_set_digest"])
        self.assertNotEqual("sha256:old", bound["receipt_digest"])

    def test_clearance_decision_mismatch_is_rejected(self):
        result = compose()
        with self.assertRaisesRegex(GovernanceError, "does not match"):
            bind_composition_to_clearance(
                {"receipt_type": "GOVERNANCE_CLEARANCE", "decision": "DENY"},
                result,
            )


if __name__ == "__main__":
    unittest.main()
