"""Deterministic Governance OS vertical slice (GOS-001).

Human board intent is descriptive input, never executable authority. This module
compiles narrow mandates and validates the live authority path immediately before
a consequential action. Standard library only; fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Iterable


class GovernanceError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise GovernanceError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def require_keys(value: dict[str, Any], keys: Iterable[str], kind: str) -> None:
    missing = sorted(set(keys) - set(value))
    if missing:
        raise GovernanceError(f"{kind} missing required fields: {', '.join(missing)}")


@dataclass(frozen=True)
class CompiledMandate:
    mandate_id: str
    version: str
    principal: str
    permitted_actions: tuple[str, ...]
    resource_scope: tuple[str, ...]
    max_single_exposure: int
    max_cumulative_exposure: int
    valid_from: str
    valid_until: str
    intent_digest: str
    business_case_digest: str
    mandate_digest: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["permitted_actions"] = list(self.permitted_actions)
        value["resource_scope"] = list(self.resource_scope)
        return value


def validate_board_intent(intent: dict[str, Any]) -> None:
    require_keys(intent, ("intent_id", "board_authority", "purpose", "allowed_outcomes", "prohibited_outcomes", "approved_at"), "BoardIntent")
    if not intent["board_authority"] or not intent["purpose"]:
        raise GovernanceError("BoardIntent authority and purpose must be explicit")
    if not isinstance(intent["allowed_outcomes"], list) or not intent["allowed_outcomes"]:
        raise GovernanceError("BoardIntent allowed_outcomes must be non-empty")
    parse_time(intent["approved_at"])


def validate_business_case(case: dict[str, Any], intent: dict[str, Any]) -> None:
    require_keys(case, ("case_id", "intent_id", "principal", "actions", "resource_scope", "max_single_exposure", "max_cumulative_exposure", "valid_from", "valid_until", "evidence_digest"), "ExecutableBusinessCase")
    if case["intent_id"] != intent["intent_id"]:
        raise GovernanceError("business case is not bound to board intent")
    if not case["actions"] or not case["resource_scope"]:
        raise GovernanceError("actions and resource_scope must be explicit and non-empty")
    if int(case["max_single_exposure"]) < 0 or int(case["max_cumulative_exposure"]) < int(case["max_single_exposure"]):
        raise GovernanceError("invalid exposure limits")
    if parse_time(case["valid_until"]) <= parse_time(case["valid_from"]):
        raise GovernanceError("valid_until must be after valid_from")
    if not str(case["evidence_digest"]).startswith("sha256:"):
        raise GovernanceError("business case evidence must be digest-bound")


def compile_mandate(intent: dict[str, Any], case: dict[str, Any], requested: dict[str, Any]) -> CompiledMandate:
    validate_board_intent(intent)
    validate_business_case(case, intent)
    require_keys(requested, ("mandate_id", "version", "principal", "actions", "resource_scope", "max_single_exposure", "max_cumulative_exposure", "valid_from", "valid_until"), "EnterpriseMandate request")
    if requested["principal"] != case["principal"]:
        raise GovernanceError("principal widening is forbidden")
    actions = tuple(sorted(set(requested["actions"])))
    resources = tuple(sorted(set(requested["resource_scope"])))
    if not set(actions).issubset(set(case["actions"])):
        raise GovernanceError("action widening is forbidden")
    if not set(resources).issubset(set(case["resource_scope"])):
        raise GovernanceError("resource widening is forbidden")
    single = int(requested["max_single_exposure"])
    cumulative = int(requested["max_cumulative_exposure"])
    if single > int(case["max_single_exposure"]) or cumulative > int(case["max_cumulative_exposure"]):
        raise GovernanceError("exposure widening is forbidden")
    if parse_time(requested["valid_from"]) < parse_time(case["valid_from"]) or parse_time(requested["valid_until"]) > parse_time(case["valid_until"]):
        raise GovernanceError("time-window widening is forbidden")
    unsigned = {
        "mandate_id": requested["mandate_id"], "version": requested["version"],
        "principal": requested["principal"], "permitted_actions": list(actions),
        "resource_scope": list(resources), "max_single_exposure": single,
        "max_cumulative_exposure": cumulative, "valid_from": requested["valid_from"],
        "valid_until": requested["valid_until"], "intent_digest": digest(intent),
        "business_case_digest": digest(case),
    }
    return CompiledMandate(**unsigned, mandate_digest=digest(unsigned))


def evaluate_action(mandate: CompiledMandate, authority_snapshot: dict[str, Any], action: dict[str, Any], now: str) -> dict[str, Any]:
    require_keys(authority_snapshot, ("snapshot_id", "captured_at", "active_paths", "revoked_mandates", "cumulative_exposure"), "AuthorityGraphSnapshot")
    require_keys(action, ("action_id", "principal", "action", "resource", "exposure", "evidence_digest"), "ActionCase")
    current = parse_time(now)
    reasons: list[str] = []
    if not (parse_time(mandate.valid_from) <= current <= parse_time(mandate.valid_until)):
        reasons.append("MANDATE_INACTIVE")
    if mandate.mandate_id in authority_snapshot["revoked_mandates"]:
        reasons.append("MANDATE_REVOKED")
    active = any(path.get("mandate_id") == mandate.mandate_id and path.get("principal") == mandate.principal and path.get("active") is True for path in authority_snapshot["active_paths"])
    if not active:
        reasons.append("NO_ACTIVE_AUTHORITY_PATH")
    if action["principal"] != mandate.principal:
        reasons.append("PRINCIPAL_MISMATCH")
    if action["action"] not in mandate.permitted_actions:
        reasons.append("ACTION_OUT_OF_SCOPE")
    if action["resource"] not in mandate.resource_scope:
        reasons.append("RESOURCE_OUT_OF_SCOPE")
    exposure = int(action["exposure"])
    prior = int(authority_snapshot["cumulative_exposure"].get(mandate.mandate_id, 0))
    if exposure > mandate.max_single_exposure:
        reasons.append("SINGLE_EXPOSURE_EXCEEDED")
    if prior + exposure > mandate.max_cumulative_exposure:
        reasons.append("CUMULATIVE_EXPOSURE_EXCEEDED")
    if not str(action["evidence_digest"]).startswith("sha256:"):
        reasons.append("EVIDENCE_NOT_BOUND")
    decision = "ALLOW" if not reasons else "DENY"
    receipt = {
        "receipt_version": "gos-0.1", "action_id": action["action_id"],
        "intent_digest": mandate.intent_digest, "business_case_digest": mandate.business_case_digest,
        "mandate_digest": mandate.mandate_digest, "authority_snapshot_digest": digest(authority_snapshot),
        "action_digest": digest(action), "evaluated_at": now, "decision": decision,
        "reasons": sorted(reasons), "human_authority_final": True,
    }
    receipt["receipt_digest"] = digest(receipt)
    return receipt
