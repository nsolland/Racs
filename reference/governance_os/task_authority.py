"""Reference validation for bounded task-authority materialization.

This module is conformance support for RACS contracts. It does not grant
clearance, mint an execution permit, or authorize a commit.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping, Sequence

_BASE_PATH = Path(__file__).parents[1] / "governance_os_v0_1.py"
_BASE_SPEC = importlib.util.spec_from_file_location("governance_os_v0_1", _BASE_PATH)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("cannot load governance_os_v0_1")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules.setdefault("governance_os_v0_1", _BASE)
_BASE_SPEC.loader.exec_module(_BASE)

GovernanceError = _BASE.GovernanceError
digest = _BASE.digest
parse_time = _BASE.parse_time
require_keys = _BASE.require_keys


_MATERIALIZATION_FIELDS = (
    "materialization_version",
    "task_authority_id",
    "principal_binding_digest",
    "agent_identity_digest",
    "parent_authority_grant_digest",
    "parent_authority_state_digest",
    "authority_state_revision",
    "delegation_chain_digest",
    "purpose_refs",
    "task_scope",
    "policy_snapshot_digests",
    "target_action_contract_digests",
    "valid_from",
    "expires_at",
    "max_action_count",
    "nonce",
    "materialized_at",
    "materializer_id",
    "self_refresh_allowed",
    "execution_authority",
    "digest_profile",
    "materialization_digest",
    "signature_or_attestation",
)

_PARENT_FIELDS = (
    "grant_id",
    "principal_binding_digest",
    "agent_identity_digest",
    "delegation_chain_digest",
    "purpose_refs",
    "allowed_action_types",
    "allowed_target_ids",
    "allowed_capabilities",
    "resource_constraints",
    "maximum_consequence_class",
    "reversibility_ceiling",
    "data_class_ceiling",
    "privilege_ceiling",
    "spend_limit",
    "max_action_count",
    "valid_from",
    "valid_until",
    "authorized_materializer_ids",
    "revoked",
)

_SCOPE_FIELDS = (
    "allowed_action_types",
    "allowed_target_ids",
    "allowed_capabilities",
    "resource_constraints",
    "maximum_consequence_class",
    "reversibility_ceiling",
    "data_class_ceiling",
    "privilege_ceiling",
    "spend_limit",
)


def _verify_digest(record: Mapping[str, Any], field: str, kind: str) -> None:
    require_keys(dict(record), (field,), kind)
    unsigned = {key: value for key, value in record.items() if key != field}
    if record[field] != digest(unsigned):
        raise GovernanceError(f"{kind} digest mismatch")


def _require_string_set(value: Any, field: str, *, non_empty: bool = True) -> set[str]:
    if not isinstance(value, list):
        raise GovernanceError(f"{field} must be an array")
    if non_empty and not value:
        raise GovernanceError(f"{field} must be non-empty")
    if any(not isinstance(item, str) or not item for item in value):
        raise GovernanceError(f"{field} contains an invalid identifier")
    if len(value) != len(set(value)):
        raise GovernanceError(f"{field} must contain unique values")
    return set(value)


def _require_subset(child: Any, parent: Any, field: str) -> None:
    child_set = _require_string_set(child, f"task {field}")
    parent_set = _require_string_set(parent, f"parent {field}")
    if not child_set.issubset(parent_set):
        raise GovernanceError(f"task {field} widens parent authority")


def _resource_is_subset(child: Any, parent: Any) -> bool:
    if isinstance(parent, Mapping):
        if not isinstance(child, Mapping):
            return False
        return set(child).issubset(parent) and all(
            _resource_is_subset(child[key], parent[key]) for key in child
        )
    if isinstance(parent, list):
        if not isinstance(child, list):
            return False
        try:
            return set(child).issubset(set(parent))
        except TypeError:
            return all(item in parent for item in child)
    return child == parent


def _money(value: Any, field: str) -> tuple[int, str]:
    if not isinstance(value, Mapping):
        raise GovernanceError(f"{field} must be an object")
    require_keys(dict(value), ("amount_minor", "currency"), field)
    try:
        amount = int(value["amount_minor"])
    except (TypeError, ValueError) as exc:
        raise GovernanceError(f"{field}.amount_minor must be an integer") from exc
    currency = value["currency"]
    if amount < 0:
        raise GovernanceError(f"{field}.amount_minor must be non-negative")
    if not isinstance(currency, str) or len(currency) != 3 or not currency.isupper():
        raise GovernanceError(f"{field}.currency must be an uppercase ISO-style code")
    return amount, currency


def reject_standing_grant_for_execution(artifact: Mapping[str, Any]) -> None:
    """Fail closed when standing authority is presented at an execution boundary.

    Passing this check never authorizes execution. A separate clearance and bounded
    execution artifact remain mandatory.
    """
    if artifact.get("standing") is True:
        raise GovernanceError("standing authority cannot be used for execution")
    if "grant_id" in artifact and "materialization_version" not in artifact:
        raise GovernanceError("authority grant cannot be used directly for execution")


def validate_task_authority_materialization(
    materialization: Mapping[str, Any],
    parent_grant: Mapping[str, Any],
    authority_state: Mapping[str, Any],
    *,
    current_policy_snapshot_digests: Sequence[str],
    target_contracts: Sequence[Mapping[str, Any]],
    now: str,
    used_nonces: Iterable[str] = (),
    maximum_state_age_seconds: int = 300,
) -> dict[str, Any]:
    """Validate a task materialization as bounded evaluation input.

    The return value is a defensive copy of the validated artifact. It is not a
    verdict, clearance, permit, token, or execution credential.
    """
    item = dict(materialization)
    parent = dict(parent_grant)
    state = dict(authority_state)
    require_keys(item, _MATERIALIZATION_FIELDS, "TaskAuthorityMaterialization")
    require_keys(parent, _PARENT_FIELDS, "AuthorityGrant")
    require_keys(state, ("grant_id", "revision", "revoked", "updated_at"), "AuthorityState")

    if item["materialization_version"] != "task-authority-materialization-0.3":
        raise GovernanceError("unsupported task authority materialization version")
    if item["digest_profile"] != "rfc8785-sha256-excluding:materialization_digest":
        raise GovernanceError("unsupported task materialization digest profile")
    _verify_digest(item, "materialization_digest", "TaskAuthorityMaterialization")

    if item["self_refresh_allowed"] is not False:
        raise GovernanceError("task authority cannot self-refresh")
    if item["execution_authority"] != "NONE":
        raise GovernanceError("task materialization cannot grant execution authority")

    has_task = bool(item.get("task_id"))
    has_segment = bool(item.get("workflow_segment_id"))
    if has_task == has_segment:
        raise GovernanceError("exactly one task_id or workflow_segment_id is required")

    signature = item["signature_or_attestation"]
    if not isinstance(signature, Mapping):
        raise GovernanceError("materializer signature or attestation is required")
    require_keys(
        dict(signature),
        ("scheme", "signer_id", "signed_payload_digest", "signature_digest", "verified"),
        "MaterializerAttestation",
    )
    if signature["verified"] is not True:
        raise GovernanceError("materializer attestation is not verified")
    if signature["signer_id"] != item["materializer_id"]:
        raise GovernanceError("materializer attestation signer mismatch")
    if not str(signature["signature_digest"]).startswith("sha256:"):
        raise GovernanceError("materializer attestation must be digest-bound")
    authorized_materializers = _require_string_set(
        parent["authorized_materializer_ids"], "authorized_materializer_ids"
    )
    if item["materializer_id"] not in authorized_materializers:
        raise GovernanceError("materializer is not authorized by the parent grant")

    if parent["revoked"] is True or state["revoked"] is True:
        raise GovernanceError("parent authority is revoked")
    if state["grant_id"] != parent["grant_id"]:
        raise GovernanceError("authority state is not bound to parent grant")
    try:
        revision = int(state["revision"])
        item_revision = int(item["authority_state_revision"])
    except (TypeError, ValueError) as exc:
        raise GovernanceError("authority revision must be an integer") from exc
    if item_revision != revision:
        raise GovernanceError("task materialization authority revision is stale")

    current = parse_time(now)
    if maximum_state_age_seconds < 0:
        raise GovernanceError("maximum_state_age_seconds must be non-negative")
    state_time = parse_time(state["updated_at"])
    if state_time > current:
        raise GovernanceError("authority state timestamp is in the future")
    if current - state_time > timedelta(seconds=maximum_state_age_seconds):
        raise GovernanceError("authority state is stale")

    if item["parent_authority_grant_digest"] != digest(parent):
        raise GovernanceError("task materialization parent grant digest mismatch")
    if item["parent_authority_state_digest"] != digest(state):
        raise GovernanceError("task materialization authority state digest mismatch")
    if item["principal_binding_digest"] != parent["principal_binding_digest"]:
        raise GovernanceError("principal binding mismatch")
    if item["agent_identity_digest"] != parent["agent_identity_digest"]:
        raise GovernanceError("agent identity mismatch")
    if item["delegation_chain_digest"] != parent["delegation_chain_digest"]:
        raise GovernanceError("delegation chain mismatch")

    child_from = parse_time(item["valid_from"])
    child_until = parse_time(item["expires_at"])
    parent_from = parse_time(parent["valid_from"])
    parent_until = parse_time(parent["valid_until"])
    materialized_at = parse_time(item["materialized_at"])
    if not (parent_from <= child_from < child_until <= parent_until):
        raise GovernanceError("task materialization widens parent time window")
    if not (child_from <= current <= child_until):
        raise GovernanceError("task materialization is inactive")
    if not (child_from <= materialized_at <= current):
        raise GovernanceError("materialization timestamp is outside the active window")

    parent_purposes = _require_string_set(parent["purpose_refs"], "parent purpose_refs")
    child_purposes = _require_string_set(item["purpose_refs"], "task purpose_refs")
    if not child_purposes.issubset(parent_purposes):
        raise GovernanceError("task purpose widens parent authority")

    scope = item["task_scope"]
    if not isinstance(scope, Mapping):
        raise GovernanceError("task_scope must be an object")
    require_keys(dict(scope), _SCOPE_FIELDS, "TaskScope")
    _require_subset(scope["allowed_action_types"], parent["allowed_action_types"], "allowed_action_types")
    _require_subset(scope["allowed_target_ids"], parent["allowed_target_ids"], "allowed_target_ids")
    _require_subset(scope["allowed_capabilities"], parent["allowed_capabilities"], "allowed_capabilities")
    if not _resource_is_subset(scope["resource_constraints"], parent["resource_constraints"]):
        raise GovernanceError("task resource constraints widen parent authority")

    for field in (
        "maximum_consequence_class",
        "reversibility_ceiling",
        "data_class_ceiling",
        "privilege_ceiling",
    ):
        if scope[field] != parent[field]:
            raise GovernanceError(
                f"{field} differs from parent; no deterministic narrowing profile was supplied"
            )

    child_amount, child_currency = _money(scope["spend_limit"], "task spend_limit")
    parent_amount, parent_currency = _money(parent["spend_limit"], "parent spend_limit")
    if child_currency != parent_currency or child_amount > parent_amount:
        raise GovernanceError("task spend limit widens parent authority")

    try:
        max_actions = int(item["max_action_count"])
        parent_max_actions = int(parent["max_action_count"])
    except (TypeError, ValueError) as exc:
        raise GovernanceError("max_action_count must be an integer") from exc
    if max_actions < 1 or max_actions > parent_max_actions:
        raise GovernanceError("task max_action_count widens parent authority")

    current_policies = set(current_policy_snapshot_digests)
    bound_policies = _require_string_set(
        item["policy_snapshot_digests"], "policy_snapshot_digests"
    )
    if bound_policies != current_policies:
        raise GovernanceError("policy snapshot binding is stale or incomplete")

    contract_digests: set[str] = set()
    for contract in target_contracts:
        require_keys(dict(contract), ("contract_digest",), "TargetActionContract")
        contract_digests.add(str(contract["contract_digest"]))
    if not contract_digests:
        raise GovernanceError("at least one target action contract is required")
    bound_contracts = _require_string_set(
        item["target_action_contract_digests"], "target_action_contract_digests"
    )
    if bound_contracts != contract_digests:
        raise GovernanceError("target action contract binding is stale or incomplete")

    nonce = item["nonce"]
    if not isinstance(nonce, str) or len(nonce) < 16:
        raise GovernanceError("materialization nonce is invalid")
    if nonce in set(used_nonces):
        raise GovernanceError("materialization nonce has already been used")

    return deepcopy(item)
