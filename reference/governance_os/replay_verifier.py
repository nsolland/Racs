"""Deterministic offline verification of GovernanceReplayBundle v0.3."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from composition import compose_evaluation_fragments
from constitutional_hierarchy import Level
from replay_bundle import (
    GovernanceError,
    ReplayIncompleteError,
    ReplayMismatchError,
    ReplayUnverifiableError,
    digest,
    extract_revocation_state,
    hierarchy_profile_from_snapshot,
    parse_time,
    prefixed_hierarchy_digest,
    required_hard_gate_ids,
    validate_bundle_envelope,
    verify_record_digest,
)


class ReplayStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    INCOMPLETE = "INCOMPLETE"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True)
class ReplayVerificationResult:
    status: ReplayStatus
    reason_codes: tuple[str, ...]
    supplied_bundle_digest: str | None
    recomputed_bundle_digest: str | None
    supplied_decision: str | None
    recomputed_decision: str | None
    supplied_decision_digest: str | None
    recomputed_decision_digest: str | None
    result_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "supplied_bundle_digest": self.supplied_bundle_digest,
            "recomputed_bundle_digest": self.recomputed_bundle_digest,
            "supplied_decision": self.supplied_decision,
            "recomputed_decision": self.recomputed_decision,
            "supplied_decision_digest": self.supplied_decision_digest,
            "recomputed_decision_digest": self.recomputed_decision_digest,
            "result_digest": self.result_digest,
        }


def _result(
    status: ReplayStatus,
    reasons: Sequence[str],
    *,
    bundle: Mapping[str, Any] | None = None,
    recomputed_bundle_digest: str | None = None,
    recomputed_decision: str | None = None,
    recomputed_decision_digest: str | None = None,
) -> ReplayVerificationResult:
    supplied_bundle_digest = None
    supplied_decision = None
    supplied_decision_digest = None
    if isinstance(bundle, Mapping):
        supplied_bundle_digest = bundle.get("bundle_digest")
        composition = bundle.get("composition_result")
        if isinstance(composition, Mapping):
            supplied_decision = composition.get("verdict")
            supplied_decision_digest = composition.get("decision_digest")
    core = {
        "status": status.value,
        "reason_codes": sorted(set(reasons)),
        "supplied_bundle_digest": supplied_bundle_digest,
        "recomputed_bundle_digest": recomputed_bundle_digest,
        "supplied_decision": supplied_decision,
        "recomputed_decision": recomputed_decision,
        "supplied_decision_digest": supplied_decision_digest,
        "recomputed_decision_digest": recomputed_decision_digest,
    }
    return ReplayVerificationResult(
        status=status,
        reason_codes=tuple(core["reason_codes"]),
        supplied_bundle_digest=supplied_bundle_digest,
        recomputed_bundle_digest=recomputed_bundle_digest,
        supplied_decision=supplied_decision,
        recomputed_decision=recomputed_decision,
        supplied_decision_digest=supplied_decision_digest,
        recomputed_decision_digest=recomputed_decision_digest,
        result_digest=digest(core),
    )


def _assert_equal(actual: Any, expected: Any, reason: str) -> None:
    if actual != expected:
        raise ReplayMismatchError(reason)


def _snapshot_digest(bundle: Mapping[str, Any], field: str) -> str:
    snapshot = bundle[field]
    if not isinstance(snapshot, Mapping):
        raise ReplayIncompleteError(f"{field} must be an artifact snapshot")
    value = snapshot.get("artifact_digest")
    if not isinstance(value, str):
        raise ReplayIncompleteError(f"{field} artifact digest is absent")
    return value


def _verify_task_bindings(bundle: Mapping[str, Any]) -> None:
    task = bundle["task_authority_materialization"]
    state = bundle["authority_state_snapshot"]
    _assert_equal(task.get("principal_binding_digest"), _snapshot_digest(bundle, "principal_binding"), "principal binding substitution")
    _assert_equal(task.get("agent_identity_digest"), _snapshot_digest(bundle, "agent_identity_reference"), "agent identity substitution")
    _assert_equal(task.get("delegation_chain_digest"), _snapshot_digest(bundle, "delegation_chain_reference"), "delegation chain substitution")
    _assert_equal(task.get("parent_authority_grant_digest"), _snapshot_digest(bundle, "authority_grant"), "authority grant substitution")
    _assert_equal(
        task.get("parent_authority_state_digest"),
        state["artifact"]["artifact_digest"],
        "authority state substitution",
    )
    _assert_equal(task.get("authority_state_revision"), state.get("revision"), "authority revision mismatch")
    _assert_equal(
        state["artifact"]["payload"].get("revision"),
        state.get("revision"),
        "authority state payload revision mismatch",
    )
    if state.get("revoked") is True:
        raise ReplayMismatchError("authority was revoked at decision time")
    if task.get("self_refresh_allowed") is not False:
        raise ReplayMismatchError("task authority self-refresh is forbidden")
    if task.get("execution_authority") != "NONE":
        raise ReplayMismatchError("task materialization carries execution authority")
    if task.get("digest_profile") != "rfc8785-sha256-excluding:materialization_digest":
        raise ReplayUnverifiableError("unsupported task materialization digest profile")
    verify_record_digest(task, "materialization_digest", "TaskAuthorityMaterialization")

    decision_time = parse_time(str(bundle["decision_timestamp"]))
    valid_from = parse_time(str(task.get("valid_from")))
    expires_at = parse_time(str(task.get("expires_at")))
    materialized_at = parse_time(str(task.get("materialized_at")))
    if not (valid_from <= materialized_at <= decision_time <= expires_at):
        raise ReplayMismatchError("task materialization was inactive at decision time")
    observed_at = parse_time(str(state.get("observed_at")))
    if observed_at > decision_time:
        raise ReplayMismatchError("authority state was observed after the decision")


def _verify_policy_and_contract_bindings(bundle: Mapping[str, Any]) -> None:
    task = bundle["task_authority_materialization"]
    policy_snapshots = bundle["policy_snapshots"]
    policy_digests = {snapshot["artifact_digest"] for snapshot in policy_snapshots}
    _assert_equal(
        set(task.get("policy_snapshot_digests", [])),
        policy_digests,
        "policy snapshot set mismatch",
    )

    contracts = bundle["target_action_contracts"]
    contract_digests: set[str] = set()
    decision_time = parse_time(str(bundle["decision_timestamp"]))
    action = bundle["action_reference"]["payload"]
    revocation_state = extract_revocation_state(policy_snapshots)
    revocation_observed = parse_time(str(revocation_state["observed_at"]))
    if revocation_observed > decision_time:
        raise ReplayMismatchError("revocation state was observed after the decision")
    revoked_ids = set(revocation_state["revoked_contract_ids"])
    matching_contracts = 0
    for contract in contracts:
        if not isinstance(contract, Mapping):
            raise ReplayIncompleteError("target action contract must be an object")
        if contract.get("contract_version") != "target-action-contract-0.3":
            raise ReplayUnverifiableError("unsupported target action contract version")
        if contract.get("digest_profile") != "rfc8785-sha256-excluding:contract_digest":
            raise ReplayUnverifiableError("unsupported target action contract digest profile")
        verify_record_digest(contract, "contract_digest", "TargetActionContract")
        if contract.get("signature_verified") is not True:
            raise ReplayUnverifiableError("target action contract signature is not verified")
        if contract.get("authority_granting") is not False:
            raise ReplayMismatchError("target action contract grants authority")
        contract_id = contract.get("contract_id")
        if contract_id in revoked_ids:
            raise ReplayMismatchError("target action contract was revoked at decision time")
        if not (parse_time(str(contract.get("valid_from"))) <= decision_time <= parse_time(str(contract.get("expires_at")))):
            raise ReplayMismatchError("target action contract was inactive at decision time")
        contract_digests.add(str(contract["contract_digest"]))
        if contract.get("operation") == action.get("operation") and contract.get("target_system_id") == action.get("target"):
            matching_contracts += 1
    _assert_equal(
        set(task.get("target_action_contract_digests", [])),
        contract_digests,
        "target action contract set mismatch",
    )
    if matching_contracts != 1:
        raise ReplayMismatchError("exact action does not resolve to one target action contract")


def _profile_replay_options(bundle: Mapping[str, Any]) -> tuple[tuple[Level, ...], tuple[str, ...], Level | None]:
    payload = bundle["hierarchy_profile"]["payload"]
    legitimate: list[Level] = []
    for value in payload.get("legitimate_conflict_levels", []):
        try:
            legitimate.append(Level(str(value)))
        except ValueError as exc:
            raise ReplayUnverifiableError(f"unsupported legitimate conflict level: {value}") from exc
    halt_reasons = tuple(payload.get("halt_reason_codes", []))
    if any(not isinstance(reason, str) or not reason for reason in halt_reasons):
        raise ReplayIncompleteError("halt_reason_codes contains an invalid value")
    halt_level_value = payload.get("halt_level")
    halt_level = None
    if halt_level_value is not None:
        try:
            halt_level = Level(str(halt_level_value))
        except ValueError as exc:
            raise ReplayUnverifiableError(f"unsupported halt level: {halt_level_value}") from exc
    return tuple(legitimate), halt_reasons, halt_level


def _recompute_composition(bundle: Mapping[str, Any]):
    profile = hierarchy_profile_from_snapshot(bundle["hierarchy_profile"])
    fragments = bundle["authority_evaluation_fragments"]
    present_ids = {
        fragment.get("fragment_id")
        for fragment in fragments
        if isinstance(fragment, Mapping)
    }
    missing = sorted(required_hard_gate_ids(profile) - present_ids)
    if missing:
        raise ReplayIncompleteError("mandatory evaluation fragments are absent: " + ", ".join(missing))
    legitimate, halt_reasons, halt_level = _profile_replay_options(bundle)
    return compose_evaluation_fragments(
        profile,
        (),
        fragments,
        now=str(bundle["decision_timestamp"]),
        subject_digest=_snapshot_digest(bundle, "action_reference"),
        legitimate_conflict_levels=legitimate,
        halt_reason_codes=halt_reasons,
        halt_level=halt_level,
    )


def _verify_composition_and_clearance(bundle: Mapping[str, Any], composition) -> tuple[str, str]:
    supplied = bundle["composition_result"]
    decision = composition.hierarchy_decision
    recomputed_decision_digest = prefixed_hierarchy_digest(decision.decision_digest)
    recomputed_profile_digest = prefixed_hierarchy_digest(decision.profile_digest)
    comparisons = {
        "verdict": decision.verdict.value,
        "decisive_level": decision.decisive_level.value if decision.decisive_level is not None else None,
        "reason_codes": sorted(decision.reason_codes),
        "constraint_set_digest": composition.constraint_set_digest,
        "obligation_set_digest": composition.obligation_set_digest,
        "fragment_set_digest": composition.fragment_set_digest,
        "profile_digest": recomputed_profile_digest,
        "decision_digest": recomputed_decision_digest,
    }
    for field, expected in comparisons.items():
        actual = supplied.get(field)
        if field == "reason_codes" and isinstance(actual, list):
            actual = sorted(actual)
        _assert_equal(actual, expected, f"composition {field} mismatch")

    clearance = bundle["governance_clearance"]
    payload = clearance["payload"]
    required = (
        "decision",
        "action_reference_digest",
        "evaluation_fragment_set_digest",
        "composed_constraint_set_digest",
        "composed_obligation_set_digest",
        "composition_decision_digest",
        "composition_profile_digest",
        "execution_receipt",
    )
    missing = sorted(set(required) - set(payload))
    if missing:
        raise ReplayIncompleteError("GovernanceClearance payload missing: " + ", ".join(missing))
    _assert_equal(payload["decision"], decision.verdict.value, "clearance decision mismatch")
    _assert_equal(payload["action_reference_digest"], _snapshot_digest(bundle, "action_reference"), "clearance action binding mismatch")
    _assert_equal(payload["evaluation_fragment_set_digest"], composition.fragment_set_digest, "clearance fragment-set binding mismatch")
    _assert_equal(payload["composed_constraint_set_digest"], composition.constraint_set_digest, "clearance constraint-set binding mismatch")
    _assert_equal(payload["composed_obligation_set_digest"], composition.obligation_set_digest, "clearance obligation-set binding mismatch")
    _assert_equal(payload["composition_decision_digest"], recomputed_decision_digest, "clearance decision digest mismatch")
    _assert_equal(payload["composition_profile_digest"], recomputed_profile_digest, "clearance profile digest mismatch")
    if payload["execution_receipt"] is not False:
        raise ReplayMismatchError("GovernanceClearance is conflated with execution evidence")

    proposer = bundle["proposer_signature_or_attestation"]
    enforcer = bundle["governance_enforcer_signature"]
    _assert_equal(proposer["signed_payload_digest"], _snapshot_digest(bundle, "action_reference"), "proposer signature action binding mismatch")
    _assert_equal(enforcer["signed_payload_digest"], recomputed_decision_digest, "governance signature decision binding mismatch")
    return decision.verdict.value, recomputed_decision_digest


def verify_governance_replay_bundle(value: Mapping[str, Any]) -> ReplayVerificationResult:
    raw = value if isinstance(value, Mapping) else None
    recomputed_bundle_digest = None
    recomputed_decision = None
    recomputed_decision_digest = None
    try:
        bundle = validate_bundle_envelope(value)
        recomputed_bundle_digest = digest({key: item for key, item in bundle.items() if key != "bundle_digest"})
        _verify_task_bindings(bundle)
        _verify_policy_and_contract_bindings(bundle)
        composition = _recompute_composition(bundle)
        recomputed_decision, recomputed_decision_digest = _verify_composition_and_clearance(bundle, composition)
        return _result(
            ReplayStatus.MATCH,
            (),
            bundle=bundle,
            recomputed_bundle_digest=recomputed_bundle_digest,
            recomputed_decision=recomputed_decision,
            recomputed_decision_digest=recomputed_decision_digest,
        )
    except ReplayIncompleteError as exc:
        return _result(
            ReplayStatus.INCOMPLETE,
            (str(exc),),
            bundle=raw,
            recomputed_bundle_digest=recomputed_bundle_digest,
            recomputed_decision=recomputed_decision,
            recomputed_decision_digest=recomputed_decision_digest,
        )
    except ReplayUnverifiableError as exc:
        return _result(
            ReplayStatus.UNVERIFIABLE,
            (str(exc),),
            bundle=raw,
            recomputed_bundle_digest=recomputed_bundle_digest,
            recomputed_decision=recomputed_decision,
            recomputed_decision_digest=recomputed_decision_digest,
        )
    except (ReplayMismatchError, GovernanceError, ValueError, TypeError) as exc:
        return _result(
            ReplayStatus.MISMATCH,
            (str(exc),),
            bundle=raw,
            recomputed_bundle_digest=recomputed_bundle_digest,
            recomputed_decision=recomputed_decision,
            recomputed_decision_digest=recomputed_decision_digest,
        )
