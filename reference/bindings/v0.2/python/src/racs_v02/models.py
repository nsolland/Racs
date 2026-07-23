"""Typed model bindings for the RACS v0.2 contract schemas (stage 3B).

These are faithful, typed representations of the three v0.2 payload schemas:
  - GovernanceEvaluation        (spec/governance-evaluation-v0.2.schema.json)
  - AdmissibilityDetermination  (spec/admissibility-determination-v0.2.schema.json)
  - GovernanceClearance         (spec/governance-clearance.schema.json)

They are *pure data types + canonicalization helpers*. They do NOT perform
JSON-Schema validation (that is a later stage). Each model can canonicalize
itself to RFC 8785 (JCS) bytes and compute its sha256 digest, reusing the
stage-3A kernel, so that `payload_digest` fields can be derived and verified.

Enums mirror the schema `enum` constraints exactly.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .canonical import canonical_bytes
from .digest import sha256_digest


class Decision(str, Enum):
    ALLOW = "ALLOW"
    MODIFY = "MODIFY"
    DEFER = "DEFER"
    DENY = "DENY"
    STEP_UP = "STEP_UP"
    HALT = "HALT"


class Status(str, Enum):
    PRESENT_AND_VALID = "PRESENT_AND_VALID"
    PRESENT_BUT_INVALID = "PRESENT_BUT_INVALID"
    MISSING = "MISSING"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"
    REVOKED = "REVOKED"
    CONFLICTING = "CONFLICTING"


class AdmissibilityState(str, Enum):
    ADMISSIBLE = "ADMISSIBLE"
    CONDITIONALLY_ADMISSIBLE = "CONDITIONALLY_ADMISSIBLE"
    NOT_ADMISSIBLE = "NOT_ADMISSIBLE"
    INDETERMINATE = "INDETERMINATE"
    STALE = "STALE"
    REVOKED = "REVOKED"
    HALTED = "HALTED"
    REQUIRES_STEP_UP = "REQUIRES_STEP_UP"


class ConsequenceClass(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Reversibility(str, Enum):
    REVERSIBLE = "REVERSIBLE"
    COMPENSATABLE = "COMPENSATABLE"
    IRREVERSIBLE = "IRREVERSIBLE"


# Shared digest / binding sub-types -------------------------------------------


class EvaluationBinding(BaseModel):
    """Cryptographic binding to a signed GovernanceEvaluation artifact.

    `evaluation_digest` is the PAYLOAD DIGEST of the referenced, signature
    verified GovernanceEvaluation: SHA-256 over its RACS-JCS-1 canonicalized
    payload — i.e. MUST equal that artifact's `payload_digest`.
    """

    model_config = ConfigDict(extra="forbid")

    evaluation_ref: str
    evaluation_digest: str  # sha256:<64 hex>


# GovernanceEvaluation ---------------------------------------------------------


class GovernanceEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluation_id: str
    action_id: str
    action_envelope_digest: str
    tenant_id: str
    evaluator_id: str
    evaluator_version: str
    decision: Decision
    authority_status: Status
    policy_status: Status
    evidence_status: Status
    purpose_status: Status
    state_status: Status
    risk_status: Status
    reason_codes: List[str] = Field(default_factory=list)
    constraints: Optional[Dict[str, Any]] = None
    evaluated_at: str  # date-time
    valid_until: str  # date-time

    def model_canonical(self) -> bytes:
        """RFC 8785 canonical UTF-8 bytes of this payload."""
        return canonical_bytes(self.model_dump(mode="json", exclude_none=True))

    def model_digest(self) -> str:
        """sha256: digest over the canonical payload bytes."""
        return sha256_digest(self.model_dump(mode="json", exclude_none=True))


# AdmissibilityDetermination ---------------------------------------------------


class AdmissibilityDetermination(BaseModel):
    model_config = ConfigDict(extra="forbid")

    determination_id: str
    action_id: str
    action_envelope_digest: str
    tenant_id: str
    authority_digest: str
    delegation_chain_digest: str
    policy_digest: str
    evidence_digest: str
    purpose_digest: str
    state_digest: str
    evaluation_bindings: List[EvaluationBinding]
    state: AdmissibilityState
    conditions: Optional[Dict[str, Any]] = None
    reason_codes: List[str] = Field(default_factory=list)
    determined_at: str  # date-time
    valid_until: str  # date-time
    revocation_registry_ref: str

    def model_canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json", exclude_none=True))

    def model_digest(self) -> str:
        return sha256_digest(self.model_dump(mode="json", exclude_none=True))


# GovernanceClearance ----------------------------------------------------------


class GovernanceClearance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clearance_id: str
    action_id: str
    action_envelope_digest: str
    tenant_id: str
    decision: Decision
    admissibility_state: AdmissibilityState
    authority_digest: str
    delegation_chain_digest: str
    policy_digest: str
    evidence_digest: str
    purpose_digest: str
    state_digest: str
    target_digest: str
    payload_digest: str
    connector_id: str
    capability: str
    consequence_class: ConsequenceClass
    reversibility: Reversibility
    constraints: Optional[Dict[str, Any]] = None
    valid_from: str  # date-time
    valid_until: str  # date-time
    replay_nonce: str
    idempotency_key: str
    revocation_registry_ref: str
    evaluator_refs: List[str]
    admissibility_determination_ref: str
    admissibility_determination_digest: str

    def model_canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json", exclude_none=True))

    def model_digest(self) -> str:
        return sha256_digest(self.model_dump(mode="json", exclude_none=True))
