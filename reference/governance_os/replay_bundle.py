"""GovernanceReplayBundle validation helpers.

The bundle is evidence for deterministic offline verification. It never grants
clearance, permits, commit authority, recovery authority, or execution authority.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from constitutional_hierarchy import HierarchyProfile, Level

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


class ReplayIncompleteError(GovernanceError):
    """The bundle lacks evidence required for deterministic replay."""


class ReplayMismatchError(GovernanceError):
    """A supplied artifact, digest, or binding differs from reconstruction."""


class ReplayUnverifiableError(GovernanceError):
    """The evidence exists but cannot be independently verified."""


_REQUIRED_FIELDS = (
    "bundle_version",
    "decision_timestamp",
    "action_reference",
    "principal_binding",
    "agent_identity_reference",
    "delegation_chain_reference",
    "authority_grant",
    "authority_state_snapshot",
    "task_authority_materialization",
    "target_action_contracts",
    "policy_snapshots",
    "vaig_evaluation_reference",
    "authority_evaluation_fragments",
    "hierarchy_profile",
    "composition_result",
    "governance_clearance",
    "authority_transition_reference",
    "execution_artifact_references",
    "canonicalization_profile",
    "reason_code_profile",
    "proposer_signature_or_attestation",
    "governance_enforcer_signature",
    "replay_authority",
    "digest_profile",
    "bundle_digest",
)

_SNAPSHOT_FIELDS = (
    "artifact_type",
    "artifact_version",
    "artifact_digest",
    "payload",
)

_SIGNATURE_FIELDS = (
    "scheme",
    "signer_id",
    "signed_payload_digest",
    "signature_digest",
    "verified",
)

_HARD_LEVELS = (
    Level.CONSTITUTIONAL_LEGAL,
    Level.AUTHORITY_MANDATE,
    Level.PURPOSE_SEMANTIC,
    Level.RIGHTS_SAFETY,
    Level.EVIDENCE_REPRESENTATION,
    Level.CONSEQUENCE,
)


def _require_mapping(value: Any, kind: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReplayIncompleteError(f"{kind} must be an object")
    return dict(value)


def _require_sequence(value: Any, kind: str, *, non_empty: bool = False) -> list[Any]:
    if not isinstance(value, list):
        raise ReplayIncompleteError(f"{kind} must be an array")
    if non_empty and not value:
        raise ReplayIncompleteError(f"{kind} must be non-empty")
    return list(value)


def verify_record_digest(record: Mapping[str, Any], digest_field: str, kind: str) -> str:
    item = dict(record)
    if digest_field not in item:
        raise ReplayIncompleteError(f"{kind} missing {digest_field}")
    expected = digest({key: value for key, value in item.items() if key != digest_field})
    actual = str(item[digest_field])
    if actual != expected:
        raise ReplayMismatchError(f"{kind} digest mismatch")
    return expected


def verify_artifact_snapshot(value: Any, kind: str) -> dict[str, Any]:
    item = _require_mapping(value, kind)
    try:
        require_keys(item, _SNAPSHOT_FIELDS, kind)
    except GovernanceError as exc:
        raise ReplayIncompleteError(str(exc)) from exc
    if not isinstance(item["artifact_type"], str) or not item["artifact_type"].strip():
        raise ReplayIncompleteError(f"{kind} artifact_type is required")
    if not isinstance(item["artifact_version"], str) or not item["artifact_version"].strip():
        raise ReplayIncompleteError(f"{kind} artifact_version is required")
    if not isinstance(item["payload"], Mapping):
        raise ReplayIncompleteError(f"{kind} payload must be an object")
    expected = digest(item["payload"])
    if item["artifact_digest"] != expected:
        raise ReplayMismatchError(f"{kind} artifact digest mismatch")
    return deepcopy(item)


def verify_signature(value: Any, kind: str) -> dict[str, Any]:
    item = _require_mapping(value, kind)
    try:
        require_keys(item, _SIGNATURE_FIELDS, kind)
    except GovernanceError as exc:
        raise ReplayIncompleteError(str(exc)) from exc
    if not item["scheme"] or not item["signer_id"]:
        raise ReplayIncompleteError(f"{kind} scheme and signer are required")
    for field in ("signed_payload_digest", "signature_digest"):
        if not isinstance(item[field], str) or not item[field].startswith("sha256:"):
            raise ReplayUnverifiableError(f"{kind} {field} is not digest-bound")
    if item["verified"] is not True:
        raise ReplayUnverifiableError(f"{kind} is not independently verified")
    return deepcopy(item)


def hierarchy_profile_from_snapshot(snapshot: Mapping[str, Any]) -> HierarchyProfile:
    verified = verify_artifact_snapshot(snapshot, "HierarchyProfile")
    payload = dict(verified["payload"])
    try:
        require_keys(payload, ("profile_id", "version", "required_gates"), "HierarchyProfile payload")
    except GovernanceError as exc:
        raise ReplayIncompleteError(str(exc)) from exc
    if not isinstance(payload["required_gates"], Mapping):
        raise ReplayIncompleteError("HierarchyProfile required_gates must be an object")
    required: dict[Level, tuple[str, ...]] = {}
    for level_name, gate_ids in payload["required_gates"].items():
        try:
            level = Level(str(level_name))
        except ValueError as exc:
            raise ReplayUnverifiableError(f"unsupported hierarchy level: {level_name}") from exc
        values = _require_sequence(gate_ids, f"required_gates[{level_name}]")
        if any(not isinstance(gate_id, str) or not gate_id.strip() for gate_id in values):
            raise ReplayIncompleteError(f"required_gates[{level_name}] contains an invalid gate")
        if len(values) != len(set(values)):
            raise ReplayMismatchError(f"required_gates[{level_name}] contains duplicates")
        required[level] = tuple(values)
    try:
        profile = HierarchyProfile(
            profile_id=str(payload["profile_id"]),
            version=str(payload["version"]),
            required_gates=required,
        )
        profile.validate()
    except (TypeError, ValueError) as exc:
        raise ReplayUnverifiableError(f"invalid hierarchy profile: {exc}") from exc
    return profile


def prefixed_hierarchy_digest(value: str) -> str:
    return value if value.startswith("sha256:") else f"sha256:{value}"


def required_hard_gate_ids(profile: HierarchyProfile) -> set[str]:
    return {
        gate_id
        for level in _HARD_LEVELS
        for gate_id in profile.required_gates.get(level, ())
    }


def extract_revocation_state(policy_snapshots: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for snapshot in policy_snapshots:
        payload = snapshot.get("payload")
        if not isinstance(payload, Mapping):
            continue
        if snapshot.get("artifact_type") == "RevocationSnapshot":
            candidates.append(dict(payload))
        embedded = payload.get("revocation_state")
        if isinstance(embedded, Mapping):
            candidates.append(dict(embedded))
    if not candidates:
        raise ReplayUnverifiableError("target-contract revocation state is absent")
    if len(candidates) > 1:
        canonical = {digest(candidate) for candidate in candidates}
        if len(canonical) > 1:
            raise ReplayUnverifiableError("conflicting revocation states are present")
    state = candidates[0]
    try:
        require_keys(state, ("observed_at", "revoked_contract_ids"), "RevocationState")
    except GovernanceError as exc:
        raise ReplayIncompleteError(str(exc)) from exc
    revoked = _require_sequence(state["revoked_contract_ids"], "revoked_contract_ids")
    if any(not isinstance(contract_id, str) or not contract_id for contract_id in revoked):
        raise ReplayIncompleteError("revoked_contract_ids contains an invalid id")
    parse_time(str(state["observed_at"]))
    return state


def validate_bundle_envelope(value: Mapping[str, Any]) -> dict[str, Any]:
    bundle = _require_mapping(value, "GovernanceReplayBundle")
    try:
        require_keys(bundle, _REQUIRED_FIELDS, "GovernanceReplayBundle")
    except GovernanceError as exc:
        raise ReplayIncompleteError(str(exc)) from exc
    if bundle["bundle_version"] != "governance-replay-bundle-0.3":
        raise ReplayUnverifiableError("unsupported governance replay bundle version")
    if bundle["replay_authority"] != "NONE":
        raise ReplayMismatchError("replay bundle cannot carry execution authority")
    if bundle["digest_profile"] != "rfc8785-sha256-excluding:bundle_digest":
        raise ReplayUnverifiableError("unsupported governance replay digest profile")
    parse_time(str(bundle["decision_timestamp"]))
    verify_record_digest(bundle, "bundle_digest", "GovernanceReplayBundle")

    canonicalization = _require_mapping(bundle["canonicalization_profile"], "CanonicalizationProfile")
    try:
        require_keys(
            canonicalization,
            ("profile_id", "algorithm", "digest_algorithm", "profile_digest"),
            "CanonicalizationProfile",
        )
    except GovernanceError as exc:
        raise ReplayIncompleteError(str(exc)) from exc
    if canonicalization["profile_id"] != "RFC8785":
        raise ReplayUnverifiableError("unsupported canonicalization profile")
    if canonicalization["algorithm"] != "JSON Canonicalization Scheme":
        raise ReplayUnverifiableError("unsupported canonicalization algorithm")
    if canonicalization["digest_algorithm"] != "SHA-256":
        raise ReplayUnverifiableError("unsupported digest algorithm")
    if not str(canonicalization["profile_digest"]).startswith("sha256:"):
        raise ReplayUnverifiableError("canonicalization profile is not digest-bound")

    snapshot_fields = (
        "action_reference",
        "principal_binding",
        "agent_identity_reference",
        "delegation_chain_reference",
        "authority_grant",
        "vaig_evaluation_reference",
        "hierarchy_profile",
        "governance_clearance",
        "reason_code_profile",
    )
    for field in snapshot_fields:
        verify_artifact_snapshot(bundle[field], field)

    state = _require_mapping(bundle["authority_state_snapshot"], "AuthorityStateSnapshot")
    try:
        require_keys(state, ("artifact", "revision", "observed_at", "revoked"), "AuthorityStateSnapshot")
    except GovernanceError as exc:
        raise ReplayIncompleteError(str(exc)) from exc
    verify_artifact_snapshot(state["artifact"], "AuthorityStateSnapshot.artifact")
    if not isinstance(state["revision"], int) or state["revision"] < 0:
        raise ReplayIncompleteError("AuthorityStateSnapshot revision is invalid")
    parse_time(str(state["observed_at"]))
    if not isinstance(state["revoked"], bool):
        raise ReplayIncompleteError("AuthorityStateSnapshot revoked must be boolean")

    policies = _require_sequence(bundle["policy_snapshots"], "policy_snapshots", non_empty=True)
    for index, snapshot in enumerate(policies):
        verify_artifact_snapshot(snapshot, f"policy_snapshots[{index}]")
    transitions = bundle["authority_transition_reference"]
    if transitions is not None:
        verify_artifact_snapshot(transitions, "authority_transition_reference")
    executions = _require_sequence(bundle["execution_artifact_references"], "execution_artifact_references")
    for index, snapshot in enumerate(executions):
        verify_artifact_snapshot(snapshot, f"execution_artifact_references[{index}]")

    _require_sequence(bundle["target_action_contracts"], "target_action_contracts", non_empty=True)
    _require_sequence(bundle["authority_evaluation_fragments"], "authority_evaluation_fragments", non_empty=True)
    _require_mapping(bundle["task_authority_materialization"], "task_authority_materialization")
    _require_mapping(bundle["composition_result"], "composition_result")
    verify_signature(bundle["proposer_signature_or_attestation"], "ProposerSignature")
    verify_signature(bundle["governance_enforcer_signature"], "GovernanceEnforcerSignature")
    return deepcopy(bundle)
