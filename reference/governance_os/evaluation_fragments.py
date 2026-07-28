"""Typed, non-authoritative evaluation fragments for monotone composition."""
from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from constitutional_hierarchy import GateResult, GateState, Level

_BASE_PATH = Path(__file__).parents[1] / "governance_os_v0_1.py"
if "governance_os_v0_1" in sys.modules:
    _BASE = sys.modules["governance_os_v0_1"]
else:
    _BASE_SPEC = importlib.util.spec_from_file_location("governance_os_v0_1", _BASE_PATH)
    if _BASE_SPEC is None or _BASE_SPEC.loader is None:
        raise RuntimeError("cannot load governance_os_v0_1")
    _BASE = importlib.util.module_from_spec(_BASE_SPEC)
    sys.modules["governance_os_v0_1"] = _BASE
    _BASE_SPEC.loader.exec_module(_BASE)

GovernanceError = _BASE.GovernanceError
digest = _BASE.digest
parse_time = _BASE.parse_time
require_keys = _BASE.require_keys


@dataclass(frozen=True, order=True)
class Constraint:
    namespace: str
    operator: str
    value_digest: str
    constraint_id: str

    def payload(self) -> dict[str, str]:
        return {
            "constraint_id": self.constraint_id,
            "namespace": self.namespace,
            "operator": self.operator,
            "value_digest": self.value_digest,
        }


@dataclass(frozen=True, order=True)
class Obligation:
    obligation_id: str
    kind: str
    payload_digest: str
    must_be_satisfied_before: str

    def payload(self) -> dict[str, str]:
        return {
            "obligation_id": self.obligation_id,
            "kind": self.kind,
            "payload_digest": self.payload_digest,
            "must_be_satisfied_before": self.must_be_satisfied_before,
        }


@dataclass(frozen=True)
class EvaluationFragment:
    fragment_id: str
    evaluator_id: str
    evaluator_role: str
    level: Level
    state: GateState
    mandatory: bool
    subject_digest: str
    policy_or_contract_digest: str
    constraints: tuple[Constraint, ...]
    obligations: tuple[Obligation, ...]
    reason_codes: tuple[str, ...]
    evidence_digest: str
    evaluated_at: str
    expires_at: str
    fragment_digest: str
    raw: Mapping[str, Any]

    def gate_result(self) -> GateResult:
        reason_code = "|".join(self.reason_codes)
        return GateResult(
            gate_id=self.fragment_id,
            level=self.level,
            state=self.state,
            mandatory=self.mandatory,
            reason_code=reason_code,
            evidence_digest=self.evidence_digest,
            detail=f"evaluator={self.evaluator_id};role={self.evaluator_role}",
        )

    def normalized_payload(self) -> dict[str, Any]:
        return {
            "fragment_id": self.fragment_id,
            "evaluator_id": self.evaluator_id,
            "evaluator_role": self.evaluator_role,
            "hierarchy_level": self.level.value,
            "state": self.state.value,
            "mandatory": self.mandatory,
            "subject_digest": self.subject_digest,
            "policy_or_contract_digest": self.policy_or_contract_digest,
            "constraints": [item.payload() for item in self.constraints],
            "obligations": [item.payload() for item in self.obligations],
            "reason_codes": list(self.reason_codes),
            "evidence_digest": self.evidence_digest,
            "evaluated_at": self.evaluated_at,
            "expires_at": self.expires_at,
            "fragment_digest": self.fragment_digest,
        }


def _verify_digest(record: Mapping[str, Any], field: str, kind: str) -> None:
    unsigned = {key: value for key, value in record.items() if key != field}
    if record[field] != digest(unsigned):
        raise GovernanceError(f"{kind} digest mismatch")


def _constraints(value: Any) -> tuple[Constraint, ...]:
    if not isinstance(value, list):
        raise GovernanceError("fragment constraints must be an array")
    parsed: list[Constraint] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise GovernanceError("constraint must be an object")
        require_keys(dict(item), ("constraint_id", "namespace", "operator", "value_digest"), "Constraint")
        if item["operator"] not in {"EQUALS", "IN", "SUBSET_OF", "MAX", "MIN", "BEFORE", "AFTER", "PROHIBITS"}:
            raise GovernanceError("unsupported constraint operator")
        if not item["constraint_id"] or not item["namespace"]:
            raise GovernanceError("constraint id and namespace are required")
        if not str(item["value_digest"]).startswith("sha256:"):
            raise GovernanceError("constraint value must be digest-bound")
        parsed.append(Constraint(
            namespace=str(item["namespace"]),
            operator=str(item["operator"]),
            value_digest=str(item["value_digest"]),
            constraint_id=str(item["constraint_id"]),
        ))
    if len(parsed) != len(set(parsed)):
        raise GovernanceError("duplicate constraint is forbidden")
    return tuple(sorted(parsed))


def _obligations(value: Any) -> tuple[Obligation, ...]:
    if not isinstance(value, list):
        raise GovernanceError("fragment obligations must be an array")
    parsed: list[Obligation] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise GovernanceError("obligation must be an object")
        require_keys(
            dict(item),
            ("obligation_id", "kind", "payload_digest", "must_be_satisfied_before"),
            "Obligation",
        )
        if item["must_be_satisfied_before"] not in {"clearance", "permit", "commit", "outcome_close"}:
            raise GovernanceError("invalid obligation deadline")
        if not item["obligation_id"] or not item["kind"]:
            raise GovernanceError("obligation id and kind are required")
        if not str(item["payload_digest"]).startswith("sha256:"):
            raise GovernanceError("obligation payload must be digest-bound")
        parsed.append(Obligation(
            obligation_id=str(item["obligation_id"]),
            kind=str(item["kind"]),
            payload_digest=str(item["payload_digest"]),
            must_be_satisfied_before=str(item["must_be_satisfied_before"]),
        ))
    if len(parsed) != len(set(parsed)):
        raise GovernanceError("duplicate obligation is forbidden")
    return tuple(sorted(parsed))


def parse_evaluation_fragment(
    record: Mapping[str, Any],
    *,
    now: str,
    expected_subject_digest: str,
) -> EvaluationFragment:
    item = dict(record)
    required = (
        "fragment_version", "fragment_id", "evaluator_id", "evaluator_role",
        "hierarchy_level", "subject_digest", "policy_or_contract_digest", "state",
        "mandatory", "constraints", "obligations", "reason_codes", "evidence_digest",
        "evaluated_at", "expires_at", "authority_effect", "can_issue_clearance",
        "digest_profile", "fragment_digest", "signature_or_attestation",
    )
    require_keys(item, required, "AuthorityEvaluationFragment")
    if item["fragment_version"] != "authority-evaluation-fragment-0.3":
        raise GovernanceError("unsupported evaluation fragment version")
    for field in ("fragment_id", "evaluator_id", "evaluator_role"):
        if not isinstance(item[field], str) or not item[field].strip():
            raise GovernanceError(f"{field} is required")
    if item["authority_effect"] != "NO_AUTHORITY_CREATION":
        raise GovernanceError("evaluation fragment cannot create authority")
    if item["can_issue_clearance"] is not False:
        raise GovernanceError("evaluation fragment cannot issue clearance")
    if item["digest_profile"] != "rfc8785-sha256-excluding:fragment_digest":
        raise GovernanceError("unsupported fragment digest profile")
    _verify_digest(item, "fragment_digest", "AuthorityEvaluationFragment")

    if item["subject_digest"] != expected_subject_digest:
        raise GovernanceError("evaluation fragment subject mismatch")
    for field in ("subject_digest", "policy_or_contract_digest", "evidence_digest", "fragment_digest"):
        if not str(item[field]).startswith("sha256:"):
            raise GovernanceError(f"{field} must be digest-bound")

    signature = item["signature_or_attestation"]
    if not isinstance(signature, Mapping):
        raise GovernanceError("fragment signature or attestation is required")
    require_keys(dict(signature), ("scheme", "signer_id", "signed_payload_digest", "signature_digest", "verified"), "FragmentAttestation")
    if signature["verified"] is not True:
        raise GovernanceError("fragment attestation is not verified")
    if signature["signer_id"] != item["evaluator_id"]:
        raise GovernanceError("fragment evaluator and attestation signer differ")
    if not signature["scheme"]:
        raise GovernanceError("fragment attestation scheme is required")
    for field in ("signed_payload_digest", "signature_digest"):
        if not str(signature[field]).startswith("sha256:"):
            raise GovernanceError("fragment attestation must be digest-bound")

    try:
        level = Level(str(item["hierarchy_level"]))
        state = GateState(str(item["state"]))
    except ValueError as exc:
        raise GovernanceError("invalid fragment hierarchy level or state") from exc
    if not isinstance(item["mandatory"], bool):
        raise GovernanceError("fragment mandatory flag must be boolean")

    reasons = item["reason_codes"]
    if not isinstance(reasons, list) or any(not isinstance(reason, str) or not reason for reason in reasons):
        raise GovernanceError("fragment reason_codes are invalid")
    if len(reasons) != len(set(reasons)):
        raise GovernanceError("fragment reason_codes must be unique")
    if state in {GateState.FAIL, GateState.UNKNOWN, GateState.CONFLICT} and not reasons:
        raise GovernanceError("non-pass fragment requires a reason code")

    evaluated_at = parse_time(item["evaluated_at"])
    expires_at = parse_time(item["expires_at"])
    current = parse_time(now)
    if evaluated_at > current or current > expires_at or evaluated_at >= expires_at:
        raise GovernanceError("evaluation fragment is inactive")

    return EvaluationFragment(
        fragment_id=str(item["fragment_id"]),
        evaluator_id=str(item["evaluator_id"]),
        evaluator_role=str(item["evaluator_role"]),
        level=level,
        state=state,
        mandatory=item["mandatory"],
        subject_digest=str(item["subject_digest"]),
        policy_or_contract_digest=str(item["policy_or_contract_digest"]),
        constraints=_constraints(item["constraints"]),
        obligations=_obligations(item["obligations"]),
        reason_codes=tuple(sorted(reasons)),
        evidence_digest=str(item["evidence_digest"]),
        evaluated_at=str(item["evaluated_at"]),
        expires_at=str(item["expires_at"]),
        fragment_digest=str(item["fragment_digest"]),
        raw=item,
    )


def fragment_set_digest(fragments: Sequence[EvaluationFragment]) -> str:
    ordered = sorted(fragments, key=lambda item: (item.level.value, item.fragment_id))
    return digest([item.normalized_payload() for item in ordered])
