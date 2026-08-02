import copy
import unittest

from aaec_trajectory import (
    MinimumResponse,
    ReasonCode,
    ValidationStatus,
    digest,
    target_set_digest,
    validate_aaec_trajectory_context,
)


NOW = "2026-08-02T20:00:00Z"
AUTHORITY_LINEAGE = digest({"authority": "root-grant", "revision": 9})
PRINCIPAL = digest({"principal": "org:example"})
AGENT = digest({"agent": "agent:jade-test"})
ROOT = digest({"trajectory": "aaec:test:1"})


def redigest(item):
    item["context_digest"] = digest(
        {key: value for key, value in item.items() if key != "context_digest"}
    )
    return item


def make_context(
    *,
    sequence_no=0,
    previous=None,
    action_class="GENERAL",
    target_ids=None,
    action_overrides=None,
    evidence=None,
    ceilings=None,
):
    target_ids = target_ids or ["database:customer"]
    action = {
        "action_ref": f"action:{sequence_no}",
        "action_class": action_class,
        "target_ids": list(target_ids),
        "new_target_ids": [],
        "authority_amplification": False,
        "persistence_creation": False,
        "integrity_control_change": False,
        "destructive": False,
        "irreversible": False,
        "secret_access": False,
        "lateral_movement": False,
        "machine_speed_adaptive_retry": False,
        "observed_egress_bytes": 0,
        "credential_provenance": "NOT_APPLICABLE",
        "identity_provenance": "NOT_APPLICABLE",
        "target_expansion_authorized": False,
        "target_expansion_clearance_digest": None,
        "claims": [],
    }
    if action_overrides:
        action.update(action_overrides)

    previous_counters = (
        previous["cumulative_consequence"]
        if previous
        else {
            "action_count": 0,
            "destructive_action_count": 0,
            "irreversible_action_count": 0,
            "secret_access_count": 0,
            "privilege_change_count": 0,
            "persistence_change_count": 0,
            "lateral_target_expansion_count": 0,
            "observed_egress_bytes": 0,
        }
    )
    deltas = {
        "action_count": 1,
        "destructive_action_count": int(bool(action["destructive"])),
        "irreversible_action_count": int(bool(action["irreversible"])),
        "secret_access_count": int(bool(action["secret_access"])),
        "privilege_change_count": int(bool(action["authority_amplification"])),
        "persistence_change_count": int(bool(action["persistence_creation"])),
        "lateral_target_expansion_count": len(action["new_target_ids"]),
        "observed_egress_bytes": action["observed_egress_bytes"],
    }
    cumulative = {
        field: previous_counters[field] + deltas[field]
        for field in previous_counters
    }
    default_ceilings = {
        "action_count": 20,
        "destructive_action_count": 2,
        "irreversible_action_count": 1,
        "secret_access_count": 2,
        "privilege_change_count": 1,
        "persistence_change_count": 0,
        "lateral_target_expansion_count": 1,
        "observed_egress_bytes": 1024,
    }
    if ceilings:
        default_ceilings.update(ceilings)

    item = {
        "trajectory_version": "aaec-trajectory-context-0.3",
        "trajectory_id": "trajectory:aaec:test-1",
        "trajectory_root_digest": ROOT,
        "sequence_no": sequence_no,
        "prior_terminal_receipt_digest": (
            previous["terminal_receipt_digest"] if previous else None
        ),
        "terminal_receipt_digest": digest({"receipt": sequence_no}),
        "authority_lineage_digest": AUTHORITY_LINEAGE,
        "principal_binding_digest": PRINCIPAL,
        "agent_identity_digest": AGENT,
        "target_ids": list(target_ids),
        "target_set_digest": target_set_digest(target_ids),
        "cumulative_consequence": cumulative,
        "ceilings": default_ceilings,
        "action_observation": action,
        "evidence_bindings": evidence or {},
        "valid_from": "2026-08-02T19:55:00Z",
        "valid_until": "2026-08-02T20:05:00Z",
        "issued_at": "2026-08-02T19:59:00Z",
        "independent_halt": False,
        "halt_reason_digest": None,
        "authority_effect": "NO_AUTHORITY_CREATION",
        "execution_authority": "NONE",
        "digest_profile": "rfc8785-sha256-excluding:context_digest",
        "context_digest": "sha256:placeholder",
    }
    return redigest(item)


def evaluate(item, previous=None, authorized_targets=None):
    return validate_aaec_trajectory_context(
        item,
        previous_context=previous,
        expected_authority_lineage_digest=AUTHORITY_LINEAGE,
        authorized_target_ids=authorized_targets or ["database:customer"],
        now=NOW,
    )


class AAECTrajectoryTests(unittest.TestCase):
    def test_valid_first_action_matches_without_execution_authority(self):
        result = evaluate(make_context())
        self.assertEqual(ValidationStatus.MATCH, result.validation_status)
        self.assertEqual(MinimumResponse.NONE, result.minimum_response)
        self.assertEqual("NONE", result.execution_authority)

    def test_missing_prior_receipt_fails_closed(self):
        first = make_context()
        second = make_context(sequence_no=1, previous=first)
        second["prior_terminal_receipt_digest"] = None
        redigest(second)
        result = evaluate(second, first)
        self.assertEqual(ValidationStatus.INCOMPLETE, result.validation_status)
        self.assertEqual(MinimumResponse.DENY, result.minimum_response)
        self.assertIn(ReasonCode.TRAJECTORY_LINEAGE_MISSING.value, result.reason_codes)

    def test_substituted_prior_receipt_is_rejected(self):
        first = make_context()
        second = make_context(sequence_no=1, previous=first)
        second["prior_terminal_receipt_digest"] = digest({"receipt": "other"})
        redigest(second)
        result = evaluate(second, first)
        self.assertEqual(ValidationStatus.MISMATCH, result.validation_status)
        self.assertIn(ReasonCode.TRAJECTORY_LINEAGE_MISMATCH.value, result.reason_codes)

    def test_harvested_credential_cannot_bootstrap_authority(self):
        item = make_context(
            action_class="PRIVILEGE_CHANGE",
            action_overrides={
                "authority_amplification": True,
                "credential_provenance": "HARVESTED",
            },
            evidence={"authority_transition_clearance": digest({"clearance": 1})},
        )
        result = evaluate(item)
        self.assertEqual(MinimumResponse.DENY, result.minimum_response)
        self.assertIn(
            ReasonCode.HARVESTED_CREDENTIAL_PROVENANCE.value,
            result.reason_codes,
        )

    def test_self_created_identity_cannot_authorize_creator_trajectory(self):
        item = make_context(
            action_class="IDENTITY_CREATE",
            action_overrides={
                "authority_amplification": True,
                "identity_provenance": "SELF_CREATED_IN_TRAJECTORY",
            },
            evidence={"authority_transition_clearance": digest({"clearance": 1})},
        )
        result = evaluate(item)
        self.assertEqual(MinimumResponse.DENY, result.minimum_response)
        self.assertIn(ReasonCode.SELF_CREATED_AUTHORITY.value, result.reason_codes)

    def test_target_discovery_cannot_silently_expand_target_set(self):
        first = make_context()
        second = make_context(
            sequence_no=1,
            previous=first,
            action_class="TARGET_DISCOVERY",
            target_ids=["database:customer", "database:payments"],
            action_overrides={"new_target_ids": ["database:payments"]},
        )
        result = evaluate(
            second,
            first,
            authorized_targets=["database:customer", "database:payments"],
        )
        self.assertEqual(MinimumResponse.DENY, result.minimum_response)
        self.assertIn(ReasonCode.TARGET_SET_EXPANSION.value, result.reason_codes)
        self.assertIn(
            ReasonCode.TARGET_EXPANSION_EVIDENCE_MISSING.value,
            result.reason_codes,
        )

    def test_authorized_target_expansion_requires_bound_clearance(self):
        first = make_context()
        second = make_context(
            sequence_no=1,
            previous=first,
            action_class="TARGET_DISCOVERY",
            target_ids=["database:customer", "database:payments"],
            action_overrides={
                "new_target_ids": ["database:payments"],
                "target_expansion_authorized": True,
                "target_expansion_clearance_digest": digest({"clearance": "target"}),
            },
        )
        result = evaluate(
            second,
            first,
            authorized_targets=["database:customer", "database:payments"],
        )
        self.assertEqual(ValidationStatus.MATCH, result.validation_status)
        self.assertEqual(MinimumResponse.NONE, result.minimum_response)

    def test_repeated_destructive_actions_trip_cumulative_ceiling(self):
        first = make_context(
            action_class="DATA_DELETE",
            action_overrides={"destructive": True, "irreversible": True},
            evidence={
                "destructive_action_clearance": digest({"clearance": 1}),
                "reversibility_assessment": digest({"assessment": 1}),
            },
            ceilings={"destructive_action_count": 1, "irreversible_action_count": 1},
        )
        second = make_context(
            sequence_no=1,
            previous=first,
            action_class="DATA_DELETE",
            action_overrides={"destructive": True, "irreversible": True},
            evidence={
                "destructive_action_clearance": digest({"clearance": 2}),
                "reversibility_assessment": digest({"assessment": 2}),
            },
            ceilings={"destructive_action_count": 1, "irreversible_action_count": 1},
        )
        result = evaluate(second, first)
        self.assertEqual(MinimumResponse.HALT, result.minimum_response)
        self.assertIn(
            ReasonCode.CUMULATIVE_CEILING_EXCEEDED.value,
            result.reason_codes,
        )

    def test_database_drop_requires_fresh_human_approval(self):
        item = make_context(
            action_class="DATABASE_DROP",
            action_overrides={"destructive": True, "irreversible": True},
            evidence={
                "destructive_action_clearance": digest({"clearance": 1}),
                "reversibility_assessment": digest({"assessment": 1}),
            },
        )
        result = evaluate(item)
        self.assertEqual(ValidationStatus.INCOMPLETE, result.validation_status)
        self.assertEqual(MinimumResponse.DENY, result.minimum_response)
        self.assertIn(
            ReasonCode.DESTRUCTIVE_OBLIGATION_MISSING.value,
            result.reason_codes,
        )

    def test_unverified_exfiltration_claim_is_not_observed_outcome(self):
        item = make_context(
            action_class="EGRESS",
            action_overrides={
                "claims": [
                    {
                        "claim_type": "EXFILTRATION",
                        "statement_digest": digest({"claim": "exfiltrated"}),
                        "observed_evidence_digest": None,
                        "verification_state": "UNVERIFIED",
                    }
                ]
            },
        )
        result = evaluate(item)
        self.assertEqual((), result.observed_claim_types)
        self.assertEqual(("EXFILTRATION",), result.unverified_claim_types)
        self.assertEqual(MinimumResponse.STEP_UP, result.minimum_response)
        self.assertIn(
            ReasonCode.UNVERIFIED_EXFILTRATION_CLAIM.value,
            result.reason_codes,
        )

    def test_machine_speed_retry_is_risk_signal_not_maliciousness_proof(self):
        result = evaluate(
            make_context(action_overrides={"machine_speed_adaptive_retry": True})
        )
        self.assertEqual(ValidationStatus.MATCH, result.validation_status)
        self.assertEqual(MinimumResponse.STEP_UP, result.minimum_response)
        self.assertIn(
            ReasonCode.MACHINE_SPEED_ADAPTIVE_RETRY.value,
            result.reason_codes,
        )

    def test_independent_halt_dominates_all_other_responses(self):
        item = make_context(action_overrides={"machine_speed_adaptive_retry": True})
        item["independent_halt"] = True
        item["halt_reason_digest"] = digest({"halt": "operator"})
        redigest(item)
        result = evaluate(item)
        self.assertEqual(MinimumResponse.HALT, result.minimum_response)
        self.assertIn(ReasonCode.INDEPENDENT_HALT.value, result.reason_codes)

    def test_counter_regression_is_rejected(self):
        first = make_context()
        second = make_context(sequence_no=1, previous=first)
        second["cumulative_consequence"]["action_count"] = 0
        redigest(second)
        result = evaluate(second, first)
        self.assertEqual(MinimumResponse.DENY, result.minimum_response)
        self.assertIn(ReasonCode.COUNTER_REGRESSION.value, result.reason_codes)

    def test_context_digest_mutation_is_unverifiable(self):
        item = make_context()
        item["target_ids"] = ["database:payments"]
        result = evaluate(item)
        self.assertEqual(ValidationStatus.UNVERIFIABLE, result.validation_status)
        self.assertIn(
            ReasonCode.CONTEXT_DIGEST_MISMATCH.value,
            result.reason_codes,
        )


if __name__ == "__main__":
    unittest.main()
