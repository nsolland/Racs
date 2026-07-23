"""RACS v0.2 canonical contract bindings.

Stage 3A — canonicalization kernel (RFC 8785 + sha256 digests).
Stage 3B — typed model bindings for the three v0.2 payload schemas.
Stage 3C — runtime conformance: schema validation (Port A) + cross-artifact
           verification (Port B) with Raw/Validated/Verified wrappers.

The canonical output of the kernel MUST be byte-for-byte identical across the
Python, Rust, and TypeScript bindings, verified by the shared JCS test vectors
under test-vectors/jcs/.
"""

from .canonical import canonical_bytes, canonical_str
from .digest import sha256_digest, verify_payload_digest
from .models import (
    AdmissibilityDetermination,
    AdmissibilityState,
    ConsequenceClass,
    Decision,
    EvaluationBinding,
    GovernanceClearance,
    GovernanceEvaluation,
    Reversibility,
    Status,
)
from .validation import (
    ARTIFACT_TYPES,
    REASON_ACCEPT,
    Raw,
    Validated,
    ValidationResult,
    Verified,
    check,
    schema_sha256,
    validate,
)
from .verification import (
    VerificationResult,
    verify_clearance_binding,
    verify_evaluation_binding,
)

__all__ = [
    "canonical_bytes",
    "canonical_str",
    "sha256_digest",
    "verify_payload_digest",
    "GovernanceEvaluation",
    "AdmissibilityDetermination",
    "GovernanceClearance",
    "EvaluationBinding",
    "Decision",
    "Status",
    "AdmissibilityState",
    "ConsequenceClass",
    "Reversibility",
    # 3C
    "ARTIFACT_TYPES",
    "REASON_ACCEPT",
    "Raw",
    "Validated",
    "Verified",
    "ValidationResult",
    "check",
    "validate",
    "schema_sha256",
    "VerificationResult",
    "verify_clearance_binding",
    "verify_evaluation_binding",
]
