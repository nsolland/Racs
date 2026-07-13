# RACS Reference Python Implementation
#
# Minimal dataclass types for the RACS protocol objects.
# This is a REFERENCE implementation — it documents the types
# and field constraints; production implementations should
# conform to the spec YAML files which are the source of truth.
#
# Constraints following SPECIFICATION.md:
# - RACS is neutral, model-agnostic — no domain assumptions
# - No hardcoded policy — policy is data in policy_context
# - Immutable evidence — evidence_package integrity is verified
# - Explicit authority chains

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


# --- Authority Context ---


@dataclass
class DelegationLink:
    """A single link in a delegation chain."""
    delegator_id: str
    delegate_id: str
    scope: str
    granted_at: Optional[str] = None
    expires_at: Optional[str] = None


@dataclass
class GovernanceScope:
    """Scope limits for an authority context."""
    action_types: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    max_risk_level: str = "high"


@dataclass
class AuthorityProof:
    """Cryptographic or documentary proof of authority."""
    type: str = ""
    value: str = ""


@dataclass
class AuthorityContext:
    """Who or what may authorize an action."""
    authority_id: str = ""
    authorizing_entity_id: str = ""
    authorizing_entity_role: str = ""
    authorizing_entity_name: Optional[str] = None
    authority_type: str = "direct"
    delegation_chain: list[DelegationLink] = field(default_factory=list)
    governance_scope: Optional[GovernanceScope] = None
    valid_from: str = ""
    valid_until: Optional[str] = None
    proof: Optional[AuthorityProof] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuthorityContext":
        scope_data = d.get("governance_scope") or {}
        scope = GovernanceScope(
            action_types=scope_data.get("action_types", []),
            domains=scope_data.get("domains", []),
            max_risk_level=scope_data.get("max_risk_level", "high"),
        )
        chain = [
            DelegationLink(**link)
            for link in (d.get("delegation_chain") or [])
        ]
        proof_data = d.get("proof")
        proof = AuthorityProof(**proof_data) if proof_data else None
        auth = d.get("authorizing_entity") or {}
        return cls(
            authority_id=d.get("authority_id", ""),
            authorizing_entity_id=auth.get("id", ""),
            authorizing_entity_role=auth.get("role", ""),
            authorizing_entity_name=auth.get("name"),
            authority_type=d.get("authority_type", "direct"),
            delegation_chain=chain,
            governance_scope=scope,
            valid_from=d.get("valid_from", ""),
            valid_until=d.get("valid_until"),
            proof=proof,
        )


# --- Evidence Package ---


@dataclass
class EvidenceItem:
    """A single piece of evidence."""
    item_id: str = ""
    fact_type: str = ""
    value: dict[str, Any] = field(default_factory=dict)
    confidence: Optional[float] = None
    source_ref: Optional[str] = None
    timestamp: Optional[str] = None
    freshness: Optional[dict[str, Any]] = None


@dataclass
class ProvenanceStep:
    """A step in evidence provenance."""
    step: str = ""
    component: str = ""
    timestamp: Optional[str] = None


@dataclass
class IntegrityMetadata:
    """Integrity and non-repudiation metadata."""
    signed_digest: str = ""
    algorithm: str = ""
    signature: Optional[str] = None
    signing_key_ref: Optional[str] = None


@dataclass
class EvidencePackage:
    """Collection of evidence supporting an action decision."""
    evidence_id: str = ""
    package_type: str = "observation"
    producer_id: str = ""
    producer_system: str = ""
    producer_version: Optional[str] = None
    items: list[EvidenceItem] = field(default_factory=list)
    provenance: list[ProvenanceStep] = field(default_factory=list)
    integrity: Optional[IntegrityMetadata] = None
    created_at: str = ""
    expires_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EvidencePackage":
        producer = d.get("producer") or {}
        items = [
            EvidenceItem(**item)
            for item in (d.get("items") or [])
        ]
        provenance = [
            ProvenanceStep(**step)
            for step in (d.get("provenance") or [])
        ]
        integrity_data = d.get("integrity")
        integrity = IntegrityMetadata(**integrity_data) if integrity_data else None
        return cls(
            evidence_id=d.get("evidence_id", ""),
            package_type=d.get("package_type", "observation"),
            producer_id=producer.get("id", ""),
            producer_system=producer.get("system", ""),
            producer_version=producer.get("version"),
            items=items,
            provenance=provenance,
            integrity=integrity,
            created_at=d.get("created_at", ""),
            expires_at=d.get("expires_at"),
        )


# --- Policy Context ---


@dataclass
class PolicyRule:
    """A single policy rule."""
    rule_id: str = ""
    description: Optional[str] = None
    effect: str = "DENY"
    conditions: Optional[dict[str, Any]] = None


@dataclass
class PolicyConstraints:
    """Constraints imposed by policy."""
    max_risk_level: Optional[str] = None
    required_authority_level: Optional[str] = None
    time_restrictions: Optional[dict[str, Any]] = None
    jurisdiction: Optional[str] = None


@dataclass
class PolicyContext:
    """Policy set and version governing an action."""
    policy_id: str = ""
    policy_set_ref: str = ""
    policy_set_version: str = ""
    rules: list[PolicyRule] = field(default_factory=list)
    constraints: Optional[PolicyConstraints] = None
    evaluation_mode: str = "strict"
    valid_from: str = ""
    valid_until: Optional[str] = None
    policy_data: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyContext":
        rules = [
            PolicyRule(**rule)
            for rule in (d.get("rules") or [])
        ]
        constraints_data = d.get("constraints")
        constraints = PolicyConstraints(**constraints_data) if constraints_data else None
        return cls(
            policy_id=d.get("policy_id", ""),
            policy_set_ref=d.get("policy_set_ref", ""),
            policy_set_version=d.get("policy_set_version", ""),
            rules=rules,
            constraints=constraints,
            evaluation_mode=d.get("evaluation_mode", "strict"),
            valid_from=d.get("valid_from", ""),
            valid_until=d.get("valid_until"),
            policy_data=d.get("policy_data"),
        )


# --- Action Envelope ---


@dataclass
class ActionEnvelope:
    """A single proposed AI-mediated action with full context."""
    racs_version: str = ""
    action_id: str = ""
    action_type: str = ""
    actor: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    requested_effect: dict[str, Any] = field(default_factory=dict)
    authority_context: Optional[AuthorityContext] = None
    policy_context: Optional[PolicyContext] = None
    evidence_package: Optional[EvidencePackage] = None
    environment_state: dict[str, Any] = field(default_factory=dict)
    risk_context: Optional[dict[str, Any]] = None
    created_at: str = ""
    expires_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ActionEnvelope":
        return cls(
            racs_version=d.get("racs_version", ""),
            action_id=d.get("action_id", ""),
            action_type=d.get("action_type", ""),
            actor=d.get("actor", {}),
            target=d.get("target", {}),
            requested_effect=d.get("requested_effect", {}),
            authority_context=AuthorityContext.from_dict(
                d.get("authority_context", {})
            ) if d.get("authority_context") else None,
            policy_context=PolicyContext.from_dict(
                d.get("policy_context", {})
            ) if d.get("policy_context") else None,
            evidence_package=EvidencePackage.from_dict(
                d.get("evidence_package", {})
            ) if d.get("evidence_package") else None,
            environment_state=d.get("environment_state", {}),
            risk_context=d.get("risk_context"),
            created_at=d.get("created_at", ""),
            expires_at=d.get("expires_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize back to a plain dict (for validation round-tripping)."""
        result: dict[str, Any] = {
            "racs_version": self.racs_version,
            "action_id": self.action_id,
            "action_type": self.action_type,
            "actor": self.actor,
            "target": self.target,
            "requested_effect": self.requested_effect,
            "environment_state": self.environment_state,
            "created_at": self.created_at,
        }
        if self.expires_at is not None:
            result["expires_at"] = self.expires_at
        if self.risk_context is not None:
            result["risk_context"] = self.risk_context
        # Nested objects serialized as plain dicts
        result["authority_context"] = _obj_to_dict(self.authority_context)
        result["policy_context"] = _obj_to_dict(self.policy_context)
        result["evidence_package"] = _obj_to_dict(self.evidence_package)
        return result


def _obj_to_dict(obj: Any) -> dict[str, Any] | None:
    """Convert a dataclass (or None) to a plain dict, excluding None values."""
    if obj is None:
        return None
    if hasattr(obj, "__dataclass_fields__"):
        d = {}
        for f_name in obj.__dataclass_fields__:
            val = getattr(obj, f_name)
            if val is not None and not (isinstance(val, list) and len(val) == 0):
                d[f_name] = val
        return d
    return obj
