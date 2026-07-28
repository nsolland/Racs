"""Register RACS v0.2 runtime-continuity schemas in the canonical validator."""
from .continuity import (
    ContinuityDecision,
    EnvironmentGovernanceProfile,
    GovernedCapabilityManifest,
    GovernedExecutionSession,
    InterventionReceipt,
    RecoveryPlan,
    RecoveryReceipt,
    RuntimeObservation,
)
from .validation import ARTIFACT_TYPES

CONTINUITY_ARTIFACT_TYPES = {
    "GovernedCapabilityManifest": (
        "governed-capability-manifest-v0.2.schema.json",
        GovernedCapabilityManifest,
    ),
    "EnvironmentGovernanceProfile": (
        "environment-governance-profile-v0.2.schema.json",
        EnvironmentGovernanceProfile,
    ),
    "GovernedExecutionSession": (
        "governed-execution-session-v0.2.schema.json",
        GovernedExecutionSession,
    ),
    "RuntimeObservation": (
        "runtime-observation-v0.2.schema.json",
        RuntimeObservation,
    ),
    "ContinuityDecision": (
        "continuity-decision-v0.2.schema.json",
        ContinuityDecision,
    ),
    "InterventionReceipt": (
        "intervention-receipt-v0.2.schema.json",
        InterventionReceipt,
    ),
    "RecoveryPlan": (
        "recovery-plan-v0.2.schema.json",
        RecoveryPlan,
    ),
    "RecoveryReceipt": (
        "recovery-receipt-v0.2.schema.json",
        RecoveryReceipt,
    ),
}

overlap = set(ARTIFACT_TYPES).intersection(CONTINUITY_ARTIFACT_TYPES)
if overlap:
    raise RuntimeError(f"duplicate RACS artifact type registration: {sorted(overlap)}")

ARTIFACT_TYPES.update(CONTINUITY_ARTIFACT_TYPES)
