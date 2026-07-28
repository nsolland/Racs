"""Reference validation for TargetActionContract v0.3.

The contract authenticates operation semantics. It never grants principal
authority, issues a RACS decision, or authorizes execution.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping

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


_REQUIRED_FIELDS = (
    "contract_version",
    "contract_id",
    "issuer",
    "issuer_identity_digest",
    "target_system_id",
    "connector_id",
    "operation",
    "parameter_schema_digest",
    "semantic_effects",
    "side_effect_classes",
    "data_read_classes",
    "data_write_classes",
    "visibility",
    "reversibility",
    "rollback_capability",
    "financial_effect",
    "maximum_expected_cost",
    "privilege_required",
    "human_approval_requirement",
    "receipt_requirement",
    "outcome_evidence_requirement",
    "valid_from",
    "expires_at",
    "supersedes",
    "revocation_ref",
    "signature_scheme",
    "signature_digest",
    "signature_verified",
    "authority_granting",
    "digest_profile",
    "contract_digest",
)


def _verify_digest(record: Mapping[str, Any], field: str, kind: str) -> None:
    unsigned = {key: value for key, value in record.items() if key != field}
    if record[field] != digest(unsigned):
        raise GovernanceError(f"{kind} digest mismatch")


def _string_list(value: Any, field: str, *, non_empty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise GovernanceError(f"{field} must be an array")
    if non_empty and not value:
        raise GovernanceError(f"{field} must be non-empty")
    if any(not isinstance(item, str) or not item for item in value):
        raise GovernanceError(f"{field} contains an invalid value")
    if len(value) != len(set(value)):
        raise GovernanceError(f"{field} must contain unique values")
    return value


def validate_target_action_contract(
    contract: Mapping[str, Any],
    *,
    now: str,
    expected_target_system_id: str | None = None,
    expected_connector_id: str | None = None,
    expected_operation: str | None = None,
    revoked_contract_ids: Iterable[str] = (),
    consequential: bool = True,
) -> dict[str, Any]:
    """Validate authenticated target-operation semantics.

    The return value is a defensive copy of the validated contract. It is not an
    authority grant, clearance, permit, token, verdict, or execution receipt.
    """
    item = dict(contract)
    require_keys(item, _REQUIRED_FIELDS, "TargetActionContract")
    if item["contract_version"] != "target-action-contract-0.3":
        raise GovernanceError("unsupported target action contract version")
    if item["digest_profile"] != "rfc8785-sha256-excluding:contract_digest":
        raise GovernanceError("unsupported target contract digest profile")
    _verify_digest(item, "contract_digest", "TargetActionContract")

    if item["authority_granting"] is not False:
        raise GovernanceError("target action contract cannot grant principal authority")
    if item["signature_verified"] is not True:
        raise GovernanceError("target action contract signature is not verified")
    if not item["issuer"] or not item["signature_scheme"]:
        raise GovernanceError("target action contract issuer and signature scheme are required")
    for field in (
        "issuer_identity_digest",
        "parameter_schema_digest",
        "signature_digest",
        "contract_digest",
    ):
        if not str(item[field]).startswith("sha256:"):
            raise GovernanceError(f"{field} must be digest-bound")

    current = parse_time(now)
    valid_from = parse_time(item["valid_from"])
    expires_at = parse_time(item["expires_at"])
    if valid_from >= expires_at:
        raise GovernanceError("target action contract validity window is invalid")
    if not (valid_from <= current <= expires_at):
        raise GovernanceError("target action contract is inactive")
    if item["contract_id"] in set(revoked_contract_ids):
        raise GovernanceError("target action contract is revoked")
    if not item["revocation_ref"]:
        raise GovernanceError("target action contract must expose a revocation reference")

    if expected_target_system_id is not None and item["target_system_id"] != expected_target_system_id:
        raise GovernanceError("target action contract target mismatch")
    if expected_connector_id is not None and item["connector_id"] != expected_connector_id:
        raise GovernanceError("target action contract connector mismatch")
    if expected_operation is not None and item["operation"] != expected_operation:
        raise GovernanceError("target action contract operation mismatch")

    effects = item["semantic_effects"]
    if not isinstance(effects, list) or not effects:
        raise GovernanceError("semantic_effects must be non-empty")
    consequential_effect = False
    for effect in effects:
        if not isinstance(effect, Mapping):
            raise GovernanceError("semantic effect must be an object")
        require_keys(dict(effect), ("effect_class", "description", "consequential"), "SemanticEffect")
        if not effect["effect_class"] or not effect["description"]:
            raise GovernanceError("semantic effect class and description are required")
        if not isinstance(effect["consequential"], bool):
            raise GovernanceError("semantic effect consequential flag must be boolean")
        consequential_effect = consequential_effect or effect["consequential"]
    if consequential and not consequential_effect:
        raise GovernanceError("consequential operation lacks a consequential semantic effect")

    side_effects = _string_list(item["side_effect_classes"], "side_effect_classes")
    _string_list(item["data_read_classes"], "data_read_classes")
    _string_list(item["data_write_classes"], "data_write_classes")
    if consequential and not side_effects:
        raise GovernanceError("consequential operation lacks side-effect classification")

    if item["visibility"] not in {"private", "internal", "restricted", "external", "public"}:
        raise GovernanceError("invalid visibility")
    if item["reversibility"] not in {
        "reversible", "conditionally_reversible", "irreversible", "unknown"
    }:
        raise GovernanceError("invalid reversibility")
    if consequential and item["reversibility"] == "unknown":
        raise GovernanceError("consequential operation has unknown reversibility")

    rollback = item["rollback_capability"]
    if not isinstance(rollback, Mapping):
        raise GovernanceError("rollback_capability must be an object")
    require_keys(
        dict(rollback),
        ("available", "requires_separate_authority", "maximum_window_seconds"),
        "RollbackCapability",
    )
    if not isinstance(rollback["available"], bool) or not isinstance(
        rollback["requires_separate_authority"], bool
    ):
        raise GovernanceError("rollback capability flags must be boolean")
    window = rollback["maximum_window_seconds"]
    if rollback["available"]:
        if not isinstance(window, int) or window <= 0:
            raise GovernanceError("available rollback requires a positive time window")
    elif window not in (None, 0):
        raise GovernanceError("unavailable rollback cannot expose an active time window")

    if item["financial_effect"] not in {"none", "debit", "credit", "commitment", "variable"}:
        raise GovernanceError("invalid financial effect")
    cost = item["maximum_expected_cost"]
    if not isinstance(cost, Mapping):
        raise GovernanceError("maximum_expected_cost must be an object")
    require_keys(dict(cost), ("amount_minor", "currency"), "MaximumExpectedCost")
    try:
        amount = int(cost["amount_minor"])
    except (TypeError, ValueError) as exc:
        raise GovernanceError("maximum_expected_cost.amount_minor must be an integer") from exc
    currency = cost["currency"]
    if amount < 0:
        raise GovernanceError("maximum expected cost must be non-negative")
    if not isinstance(currency, str) or len(currency) != 3 or not currency.isupper():
        raise GovernanceError("maximum expected cost currency is invalid")

    if not item["privilege_required"]:
        raise GovernanceError("privilege_required must be explicit")
    if item["human_approval_requirement"] not in {
        "none", "conditional", "always", "external_policy"
    }:
        raise GovernanceError("invalid human approval requirement")

    receipts = set(_string_list(item["receipt_requirement"], "receipt_requirement", non_empty=True))
    if consequential and not {"governance_clearance", "execution_receipt"}.issubset(receipts):
        raise GovernanceError(
            "consequential operation requires governance clearance and execution receipt"
        )
    outcomes = _string_list(
        item["outcome_evidence_requirement"],
        "outcome_evidence_requirement",
        non_empty=consequential,
    )
    if consequential and not outcomes:
        raise GovernanceError("consequential operation requires outcome evidence")

    return deepcopy(item)
