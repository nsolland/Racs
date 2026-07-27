"""Distributed authority and compositional consequence control (GOS-002).

Separate substrates may enforce locally, but they must bind to the same
independently issued authority grant and a revisioned live authority state.
The gate verifies authority; it never creates or reinterprets it.

This is a deterministic standard-library reference implementation. Signature
verification is performed upstream; this module requires the verifier result and
the digest-bound signed grant. State transitions use compare-and-set semantics.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys
from typing import Any, Iterable

_BASE_PATH = Path(__file__).with_name("governance_os_v0_1.py")
_BASE_SPEC = importlib.util.spec_from_file_location("governance_os_v0_1", _BASE_PATH)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("cannot load governance_os_v0_1")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules.setdefault("governance_os_v0_1", _BASE)
_BASE_SPEC.loader.exec_module(_BASE)

_HIERARCHY_PATH = Path(__file__).with_name("governance_os") / "constitutional_hierarchy.py"
_HIERARCHY_SPEC = importlib.util.spec_from_file_location(
    "governance_os_constitutional_hierarchy", _HIERARCHY_PATH
)
if _HIERARCHY_SPEC is None or _HIERARCHY_SPEC.loader is None:
    raise RuntimeError("cannot load constitutional_hierarchy")
_HIERARCHY = importlib.util.module_from_spec(_HIERARCHY_SPEC)
sys.modules.setdefault("governance_os_constitutional_hierarchy", _HIERARCHY)
_HIERARCHY_SPEC.loader.exec_module(_HIERARCHY)

CompiledMandate = _BASE.CompiledMandate
GovernanceError = _BASE.GovernanceError
digest = _BASE.digest
parse_time = _BASE.parse_time
require_keys = _BASE.require_keys
GateResult = _HIERARCHY.GateResult
GateState = _HIERARCHY.GateState
HierarchyProfile = _HIERARCHY.HierarchyProfile
Level = _HIERARCHY.Level
Verdict = _HIERARCHY.Verdict
evaluate_hierarchy = _HIERARCHY.evaluate_hierarchy


def _require_non_negative_int(value: Any, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise GovernanceError(f"{field} must be an integer") from exc
    if parsed < 0:
        raise GovernanceError(f"{field} must be non-negative")
    return parsed


def _verify_record_digest(record: dict[str, Any], digest_field: str, kind: str) -> None:
    require_keys(record, (digest_field,), kind)
    unsigned = {key: value for key, value in record.items() if key != digest_field}
    if record[digest_field] != digest(unsigned):
        raise GovernanceError(f"{kind} digest mismatch")


def _transition_set_digest(transitions: Iterable[dict[str, Any]]) -> str:
    return digest(sorted(item["transition_receipt_digest"] for item in transitions))


def _gate_result_payload(result: Any) -> dict[str, Any]:
    return {
        "gate_id": result.gate_id,
        "level": result.level.value,
        "state": result.state.value,
        "mandatory": result.mandatory,
        "reason_code": result.reason_code,
        "evidence_digest": result.evidence_digest,
        "detail": result.detail,
    }


def _gate_results_digest(results: Iterable[Any]) -> str:
    normalized = sorted(
        (_gate_result_payload(result) for result in results),
        key=lambda item: (item["level"], item["gate_id"]),
    )
    return digest(normalized)


def _internal_gate(
    gate_id: str,
    level: Any,
    reasons: list[str],
    evidence_digest: str,
) -> Any:
    return GateResult(
        gate_id=gate_id,
        level=level,
        state=GateState.PASS if not reasons else GateState.FAIL,
        reason_code="" if not reasons else f"{gate_id.upper().replace('-', '_')}_FAILED",
        evidence_digest=evidence_digest,
        detail="|".join(sorted(set(reasons))),
    )


def validate_authority_grant(grant: dict[str, Any], mandate: CompiledMandate, now: str) -> None:
    require_keys(
        grant,
        (
            "authority_id",
            "authority_version",
            "issuer",
            "issued_at",
            "valid_until",
            "mandate_digest",
            "total_exposure",
            "consequence_limits",
            "forbidden_combinations",
            "signature_scheme",
            "signature_digest",
            "signature_verified",
        ),
        "AuthorityGrant",
    )
    current = parse_time(now)
    if not grant["issuer"] or not grant["signature_scheme"]:
        raise GovernanceError("authority issuer and signature scheme must be explicit")
    if grant["signature_verified"] is not True:
        raise GovernanceError("authority signature is not verified")
    if not str(grant["signature_digest"]).startswith("sha256:"):
        raise GovernanceError("authority signature must be digest-bound")
    if grant["mandate_digest"] != mandate.mandate_digest:
        raise GovernanceError("authority grant is not bound to mandate")
    if current < parse_time(grant["issued_at"]) or current > parse_time(grant["valid_until"]):
        raise GovernanceError("authority grant is inactive")
    total = _require_non_negative_int(grant["total_exposure"], "total_exposure")
    if total > mandate.max_cumulative_exposure:
        raise GovernanceError("authority grant widens mandate exposure")
    limits = grant["consequence_limits"]
    if not isinstance(limits, dict) or not limits:
        raise GovernanceError("consequence_limits must be a non-empty object")
    for consequence_class, limit in limits.items():
        if not consequence_class or not isinstance(limit, dict):
            raise GovernanceError("invalid consequence limit")
        require_keys(limit, ("max_count", "max_exposure"), f"ConsequenceLimit[{consequence_class}]")
        _require_non_negative_int(limit["max_count"], f"{consequence_class}.max_count")
        _require_non_negative_int(limit["max_exposure"], f"{consequence_class}.max_exposure")
    for policy in grant["forbidden_combinations"]:
        require_keys(policy, ("policy_id", "classes"), "ForbiddenCombination")
        if not policy["policy_id"] or len(set(policy["classes"])) < 2:
            raise GovernanceError("forbidden combination must name at least two classes")


def validate_authority_state(
    grant: dict[str, Any],
    state: dict[str, Any],
    transitions: list[dict[str, Any]],
) -> None:
    require_keys(
        state,
        (
            "authority_id",
            "authority_version",
            "mandate_digest",
            "revision",
            "remaining_exposure",
            "revoked",
            "last_transition_digest",
            "updated_at",
        ),
        "AuthorityState",
    )
    if state["authority_id"] != grant["authority_id"]:
        raise GovernanceError("authority state id mismatch")
    if state["authority_version"] != grant["authority_version"]:
        raise GovernanceError("authority state version mismatch")
    if state["mandate_digest"] != grant["mandate_digest"]:
        raise GovernanceError("authority state mandate mismatch")
    revision = _require_non_negative_int(state["revision"], "authority revision")
    remaining = _require_non_negative_int(state["remaining_exposure"], "remaining_exposure")
    if remaining > _require_non_negative_int(grant["total_exposure"], "total_exposure"):
        raise GovernanceError("authority state exceeds grant")
    parse_time(state["updated_at"])
    validate_transition_chain(grant, state, transitions)
    if revision == 0 and state["last_transition_digest"] is not None:
        raise GovernanceError("revision zero cannot have a transition digest")


def validate_transition_chain(
    grant: dict[str, Any],
    state: dict[str, Any],
    transitions: list[dict[str, Any]],
) -> None:
    revision = _require_non_negative_int(state["revision"], "authority revision")
    if len(transitions) != revision:
        raise GovernanceError("transition history is incomplete")
    ordered = sorted(transitions, key=lambda item: int(item["revision_after"]))
    previous_digest = None
    remaining = _require_non_negative_int(grant["total_exposure"], "total_exposure")
    for expected_revision, transition in enumerate(ordered, start=1):
        require_keys(
            transition,
            (
                "transition_receipt_version",
                "authority_id",
                "authority_version",
                "mandate_digest",
                "revision_before",
                "revision_after",
                "remaining_before",
                "remaining_after",
                "action_id",
                "action_digest",
                "consequence_class",
                "exposure",
                "substrate_id",
                "clearance_receipt_digest",
                "previous_transition_digest",
                "applied_at",
                "transition_receipt_digest",
            ),
            "AuthorityTransitionReceipt",
        )
        _verify_record_digest(transition, "transition_receipt_digest", "AuthorityTransitionReceipt")
        if transition["transition_receipt_version"] != "distributed-authority-transition-0.1":
            raise GovernanceError("unsupported authority transition receipt")
        if transition["authority_id"] != grant["authority_id"] or transition["authority_version"] != grant["authority_version"]:
            raise GovernanceError("transition authority mismatch")
        if transition["mandate_digest"] != grant["mandate_digest"]:
            raise GovernanceError("transition mandate mismatch")
        if int(transition["revision_before"]) != expected_revision - 1 or int(transition["revision_after"]) != expected_revision:
            raise GovernanceError("transition revisions are not contiguous")
        if transition["previous_transition_digest"] != previous_digest:
            raise GovernanceError("transition chain is broken")
        if int(transition["remaining_before"]) != remaining:
            raise GovernanceError("transition remaining authority mismatch")
        exposure = _require_non_negative_int(transition["exposure"], "transition exposure")
        remaining -= exposure
        if remaining < 0 or int(transition["remaining_after"]) != remaining:
            raise GovernanceError("transition consumption mismatch")
        parse_time(transition["applied_at"])
        previous_digest = transition["transition_receipt_digest"]
    if revision:
        if previous_digest != state["last_transition_digest"]:
            raise GovernanceError("authority state does not match transition head")
        if remaining != int(state["remaining_exposure"]):
            raise GovernanceError("authority state remaining exposure mismatch")
    elif transitions:
        raise GovernanceError("revision zero cannot contain transitions")


def _composition_reasons(
    grant: dict[str, Any],
    transitions: list[dict[str, Any]],
    action: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    consequence_class = action["consequence_class"]
    exposure = _require_non_negative_int(action["exposure"], "action exposure")
    limits = grant["consequence_limits"]
    if consequence_class not in limits:
        reasons.append("CONSEQUENCE_CLASS_NOT_AUTHORIZED")
    else:
        matching = [item for item in transitions if item["consequence_class"] == consequence_class]
        prior_count = len(matching)
        prior_exposure = sum(int(item["exposure"]) for item in matching)
        limit = limits[consequence_class]
        if prior_count + 1 > int(limit["max_count"]):
            reasons.append("CONSEQUENCE_COUNT_EXCEEDED")
        if prior_exposure + exposure > int(limit["max_exposure"]):
            reasons.append("CONSEQUENCE_EXPOSURE_EXCEEDED")
    classes = {item["consequence_class"] for item in transitions}
    classes.add(consequence_class)
    for policy in grant["forbidden_combinations"]:
        if set(policy["classes"]).issubset(classes):
            reasons.append(f"FORBIDDEN_COMBINATION:{policy['policy_id']}")
    return reasons


def evaluate_distributed_action(
    mandate: CompiledMandate,
    grant: dict[str, Any],
    state: dict[str, Any],
    authority_snapshot: dict[str, Any],
    action: dict[str, Any],
    transitions: list[dict[str, Any]],
    now: str,
    hierarchy_profile: Any,
    upstream_gate_results: Iterable[Any],
    max_snapshot_age_seconds: int = 60,
) -> dict[str, Any]:
    """Evaluate local authority and consequence gates through the canonical hierarchy.

    The returned receipt is a governance clearance, not an execution receipt.
    Only an ``ALLOW`` clearance may be atomically applied to the live authority
    state with ``apply_authority_transition``.
    """
    validate_authority_grant(grant, mandate, now)
    validate_authority_state(grant, state, transitions)
    require_keys(
        authority_snapshot,
        (
            "snapshot_id",
            "captured_at",
            "substrate_id",
            "authority_id",
            "authority_version",
            "authority_revision",
            "mandate_digest",
            "active",
        ),
        "LocalAuthoritySnapshot",
    )
    require_keys(
        action,
        (
            "action_id",
            "principal",
            "action",
            "resource",
            "exposure",
            "evidence_digest",
            "consequence_class",
            "substrate_id",
            "expected_authority_revision",
        ),
        "DistributedActionCase",
    )
    current = parse_time(now)
    captured = parse_time(authority_snapshot["captured_at"])
    max_age = _require_non_negative_int(max_snapshot_age_seconds, "max_snapshot_age_seconds")
    authority_reasons: list[str] = []
    evidence_reasons: list[str] = []
    consequence_reasons: list[str] = []

    if state["revoked"] is True:
        authority_reasons.append("AUTHORITY_REVOKED")
    if authority_snapshot["active"] is not True:
        authority_reasons.append("AUTHORITY_PATH_INACTIVE")
    if authority_snapshot["authority_id"] != grant["authority_id"]:
        authority_reasons.append("AUTHORITY_ID_MISMATCH")
    if authority_snapshot["authority_version"] != grant["authority_version"]:
        authority_reasons.append("AUTHORITY_VERSION_MISMATCH")
    if authority_snapshot["mandate_digest"] != mandate.mandate_digest:
        authority_reasons.append("MANDATE_BINDING_MISMATCH")
    if int(authority_snapshot["authority_revision"]) != int(state["revision"]):
        authority_reasons.append("STALE_AUTHORITY_REVISION")
    if int(action["expected_authority_revision"]) != int(state["revision"]):
        authority_reasons.append("STALE_AUTHORITY_REVISION")
    if authority_snapshot["substrate_id"] != action["substrate_id"]:
        authority_reasons.append("SUBSTRATE_MISMATCH")
    if captured > current or current - captured > timedelta(seconds=max_age):
        authority_reasons.append("STALE_AUTHORITY_SNAPSHOT")
    if action["principal"] != mandate.principal:
        authority_reasons.append("PRINCIPAL_MISMATCH")
    if action["action"] not in mandate.permitted_actions:
        authority_reasons.append("ACTION_OUT_OF_SCOPE")
    if action["resource"] not in mandate.resource_scope:
        authority_reasons.append("RESOURCE_OUT_OF_SCOPE")

    exposure = _require_non_negative_int(action["exposure"], "action exposure")
    if not str(action["evidence_digest"]).startswith("sha256:"):
        evidence_reasons.append("EVIDENCE_NOT_BOUND")
    if exposure > mandate.max_single_exposure:
        consequence_reasons.append("SINGLE_EXPOSURE_EXCEEDED")
    if exposure > int(state["remaining_exposure"]):
        consequence_reasons.append("AUTHORITY_EXHAUSTED")
    if any(item["action_id"] == action["action_id"] for item in transitions):
        consequence_reasons.append("ACTION_REPLAY")
    consequence_reasons.extend(_composition_reasons(grant, transitions, action))

    context_digest = digest(
        {
            "authority_grant": grant,
            "authority_state": state,
            "authority_snapshot": authority_snapshot,
            "action": action,
            "transition_set_digest": _transition_set_digest(transitions),
        }
    )
    internal_gate_results = (
        _internal_gate(
            "distributed-authority",
            Level.AUTHORITY_MANDATE,
            authority_reasons,
            context_digest,
        ),
        _internal_gate(
            "distributed-evidence",
            Level.EVIDENCE_REPRESENTATION,
            evidence_reasons,
            context_digest,
        ),
        _internal_gate(
            "distributed-consequence",
            Level.CONSEQUENCE,
            consequence_reasons,
            context_digest,
        ),
    )
    all_gate_results = tuple(upstream_gate_results) + internal_gate_results
    hierarchy_decision = evaluate_hierarchy(hierarchy_profile, all_gate_results)
    decision = hierarchy_decision.verdict.value
    reasons = sorted(
        set(
            authority_reasons
            + evidence_reasons
            + consequence_reasons
            + list(hierarchy_decision.reason_codes)
        )
    )

    remaining_before = int(state["remaining_exposure"])
    remaining_after = remaining_before - exposure if decision == Verdict.ALLOW.value else remaining_before
    revision_before = int(state["revision"])
    receipt = {
        "receipt_version": "distributed-authority-0.2",
        "receipt_type": "GOVERNANCE_CLEARANCE",
        "authority_id": grant["authority_id"],
        "authority_version": grant["authority_version"],
        "authority_grant_digest": digest(grant),
        "mandate_digest": mandate.mandate_digest,
        "authority_state_digest": digest(state),
        "authority_snapshot_digest": digest(authority_snapshot),
        "prior_transition_set_digest": _transition_set_digest(transitions),
        "hierarchy_profile_digest": hierarchy_profile.digest(),
        "hierarchy_gate_results_digest": _gate_results_digest(all_gate_results),
        "hierarchy_decision_digest": hierarchy_decision.decision_digest,
        "hierarchy_decisive_level": (
            hierarchy_decision.decisive_level.value
            if hierarchy_decision.decisive_level is not None
            else None
        ),
        "evaluated_gate_ids": list(hierarchy_decision.evaluated_gate_ids),
        "action_id": action["action_id"],
        "action_digest": digest(action),
        "principal": action["principal"],
        "substrate_id": action["substrate_id"],
        "consequence_class": action["consequence_class"],
        "exposure": exposure,
        "authority_revision_before": revision_before,
        "proposed_authority_revision_after": (
            revision_before + 1 if decision == Verdict.ALLOW.value else revision_before
        ),
        "remaining_exposure_before": remaining_before,
        "remaining_exposure_after": remaining_after,
        "evaluated_at": now,
        "decision": decision,
        "reasons": reasons,
        "authority_created_by_gate": False,
        "human_authority_final": True,
    }
    receipt["receipt_digest"] = digest(receipt)
    return receipt


def apply_authority_transition(
    grant: dict[str, Any],
    state: dict[str, Any],
    clearance_receipt: dict[str, Any],
    applied_at: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Atomically apply an allowed clearance using compare-and-set semantics."""
    _verify_record_digest(clearance_receipt, "receipt_digest", "GovernanceClearanceReceipt")
    require_keys(
        clearance_receipt,
        (
            "receipt_version",
            "receipt_type",
            "hierarchy_profile_digest",
            "hierarchy_gate_results_digest",
            "hierarchy_decision_digest",
            "hierarchy_decisive_level",
            "evaluated_gate_ids",
            "authority_created_by_gate",
            "human_authority_final",
        ),
        "GovernanceClearanceReceipt",
    )
    if clearance_receipt["receipt_version"] != "distributed-authority-0.2":
        raise GovernanceError("unsupported governance clearance receipt")
    if clearance_receipt.get("receipt_type") != "GOVERNANCE_CLEARANCE":
        raise GovernanceError("receipt is not a governance clearance")
    if clearance_receipt.get("decision") != "ALLOW":
        raise GovernanceError("denied clearance cannot consume authority")
    required_gates = {
        "distributed-authority",
        "distributed-evidence",
        "distributed-consequence",
    }
    if not required_gates.issubset(set(clearance_receipt["evaluated_gate_ids"])):
        raise GovernanceError("clearance bypassed required hierarchy gates")
    if clearance_receipt["hierarchy_decisive_level"] is not None:
        raise GovernanceError("allowed clearance cannot have a decisive failure level")
    if clearance_receipt["authority_created_by_gate"] is not False:
        raise GovernanceError("gate-created authority is forbidden")
    if clearance_receipt["human_authority_final"] is not True:
        raise GovernanceError("human authority finality is missing")
    if clearance_receipt["authority_id"] != state["authority_id"] or clearance_receipt["authority_version"] != state["authority_version"]:
        raise GovernanceError("clearance authority mismatch")
    if clearance_receipt["mandate_digest"] != state["mandate_digest"] or state["mandate_digest"] != grant["mandate_digest"]:
        raise GovernanceError("clearance mandate mismatch")
    revision_before = int(state["revision"])
    if int(clearance_receipt["authority_revision_before"]) != revision_before:
        raise GovernanceError("authority compare-and-set failed")
    if int(clearance_receipt["proposed_authority_revision_after"]) != revision_before + 1:
        raise GovernanceError("invalid proposed authority revision")
    remaining_before = int(state["remaining_exposure"])
    if int(clearance_receipt["remaining_exposure_before"]) != remaining_before:
        raise GovernanceError("clearance used stale remaining authority")
    remaining_after = int(clearance_receipt["remaining_exposure_after"])
    exposure = int(clearance_receipt["exposure"])
    if remaining_after != remaining_before - exposure or remaining_after < 0:
        raise GovernanceError("clearance authority consumption mismatch")
    parse_time(applied_at)

    next_state_core = deepcopy(state)
    next_state_core["revision"] = revision_before + 1
    next_state_core["remaining_exposure"] = remaining_after
    next_state_core["updated_at"] = applied_at
    next_state_core["last_transition_digest"] = None
    transition = {
        "transition_receipt_version": "distributed-authority-transition-0.1",
        "authority_id": state["authority_id"],
        "authority_version": state["authority_version"],
        "mandate_digest": state["mandate_digest"],
        "revision_before": revision_before,
        "revision_after": revision_before + 1,
        "remaining_before": remaining_before,
        "remaining_after": remaining_after,
        "action_id": clearance_receipt["action_id"],
        "action_digest": clearance_receipt["action_digest"],
        "consequence_class": clearance_receipt["consequence_class"],
        "exposure": exposure,
        "substrate_id": clearance_receipt["substrate_id"],
        "clearance_receipt_digest": clearance_receipt["receipt_digest"],
        "previous_transition_digest": state["last_transition_digest"],
        "authority_state_core_digest": digest(next_state_core),
        "applied_at": applied_at,
    }
    transition["transition_receipt_digest"] = digest(transition)
    next_state = deepcopy(next_state_core)
    next_state["last_transition_digest"] = transition["transition_receipt_digest"]
    return next_state, transition


def record_execution(
    clearance_receipt: dict[str, Any],
    transition_receipt: dict[str, Any],
    execution: dict[str, Any],
    prior_execution_receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Record execution separately from clearance and authority consumption."""
    _verify_record_digest(clearance_receipt, "receipt_digest", "GovernanceClearanceReceipt")
    _verify_record_digest(transition_receipt, "transition_receipt_digest", "AuthorityTransitionReceipt")
    require_keys(
        execution,
        ("execution_id", "action_id", "action_digest", "executed_at", "status", "outcome_ref", "substrate_id"),
        "ExecutionRecord",
    )
    if clearance_receipt.get("decision") != "ALLOW":
        raise GovernanceError("execution requires allowed clearance")
    if transition_receipt["clearance_receipt_digest"] != clearance_receipt["receipt_digest"]:
        raise GovernanceError("execution transition does not bind clearance")
    if execution["action_id"] != clearance_receipt["action_id"] or execution["action_digest"] != clearance_receipt["action_digest"]:
        raise GovernanceError("execution does not match cleared action")
    if execution["substrate_id"] != clearance_receipt["substrate_id"]:
        raise GovernanceError("execution substrate mismatch")
    parse_time(execution["executed_at"])
    for receipt in prior_execution_receipts:
        _verify_record_digest(receipt, "execution_receipt_digest", "ExecutionReceipt")
        if receipt["execution_id"] == execution["execution_id"] or receipt["clearance_receipt_digest"] == clearance_receipt["receipt_digest"]:
            raise GovernanceError("duplicate execution")
    receipt = {
        "execution_receipt_version": "distributed-execution-0.1",
        "receipt_type": "EXECUTION",
        "execution_id": execution["execution_id"],
        "action_id": execution["action_id"],
        "authority_id": clearance_receipt["authority_id"],
        "authority_version": clearance_receipt["authority_version"],
        "mandate_digest": clearance_receipt["mandate_digest"],
        "clearance_receipt_digest": clearance_receipt["receipt_digest"],
        "transition_receipt_digest": transition_receipt["transition_receipt_digest"],
        "execution_digest": digest(execution),
        "executed_at": execution["executed_at"],
        "status": execution["status"],
        "outcome_ref": execution["outcome_ref"],
        "substrate_id": execution["substrate_id"],
        "prior_execution_set_digest": digest(sorted(item["execution_receipt_digest"] for item in prior_execution_receipts)),
    }
    receipt["execution_receipt_digest"] = digest(receipt)
    return receipt
