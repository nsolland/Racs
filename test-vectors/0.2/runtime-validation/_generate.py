"""Generate the shared, language-agnostic Stage 3C runtime-validation vectors.

Run from repo root:
    python test-vectors/0.2/runtime-validation/_generate.py

Cross-artifact vectors may include ``verification_time``. This pins validity-window
checks to a deterministic RFC 3339 instant instead of the machine wall clock.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "test-vectors" / "0.2" / "runtime-validation"

sys.path.insert(0, str(REPO / "reference" / "bindings" / "v0.2" / "python"))
from racs_v02 import (  # noqa: E402
    AdmissibilityDetermination,
    GovernanceClearance,
    GovernanceEvaluation,
)

D = "sha256:" + "a" * 64
EV_DIGEST = "sha256:" + "e" * 64
DET_DIGEST = "sha256:" + "d" * 64
VERIFICATION_TIME = "2026-07-23T12:15:00Z"


def ev_payload() -> dict:
    return {
        "evaluation_id": "ev-001",
        "action_id": "act-001",
        "action_envelope_digest": D,
        "tenant_id": "tenant-1",
        "evaluator_id": "eval-1",
        "evaluator_version": "1.0.0",
        "decision": "ALLOW",
        "authority_status": "PRESENT_AND_VALID",
        "policy_status": "PRESENT_AND_VALID",
        "evidence_status": "PRESENT_AND_VALID",
        "purpose_status": "PRESENT_AND_VALID",
        "state_status": "PRESENT_AND_VALID",
        "risk_status": "PRESENT_AND_VALID",
        "reason_codes": ["OK"],
        "evaluated_at": "2026-07-23T12:00:00Z",
        "valid_until": "2026-07-24T12:00:00Z",
    }


def det_payload() -> dict:
    return {
        "determination_id": "det-001",
        "action_id": "act-001",
        "action_envelope_digest": D,
        "tenant_id": "tenant-1",
        "authority_digest": D,
        "delegation_chain_digest": D,
        "policy_digest": D,
        "evidence_digest": D,
        "purpose_digest": D,
        "state_digest": D,
        "evaluation_bindings": [
            {"evaluation_ref": "ev-001", "evaluation_digest": EV_DIGEST}
        ],
        "state": "ADMISSIBLE",
        "reason_codes": ["OK"],
        "determined_at": "2026-07-23T12:05:00Z",
        "valid_until": "2026-07-24T12:05:00Z",
        "revocation_registry_ref": "revreg-001",
    }


def clr_payload() -> dict:
    return {
        "clearance_id": "clr-001",
        "action_id": "act-001",
        "action_envelope_digest": D,
        "tenant_id": "tenant-1",
        "decision": "ALLOW",
        "admissibility_state": "ADMISSIBLE",
        "authority_digest": D,
        "delegation_chain_digest": D,
        "policy_digest": D,
        "evidence_digest": D,
        "purpose_digest": D,
        "state_digest": D,
        "target_digest": D,
        "payload_digest": "PLACEHOLDER",
        "connector_id": "conn-1",
        "capability": "read",
        "consequence_class": "LOW",
        "reversibility": "REVERSIBLE",
        "valid_from": "2026-07-23T12:10:00Z",
        "valid_until": "2026-07-24T12:10:00Z",
        "replay_nonce": "0123456789abcdef0123",
        "idempotency_key": "idem-001",
        "revocation_registry_ref": "revreg-001",
        "evaluator_refs": ["eval-1"],
        "admissibility_determination_ref": "det-001",
        "admissibility_determination_digest": DET_DIGEST,
    }


def write(artifact_dir: str, name: str, document: dict) -> None:
    path = VEC / artifact_dir / name
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print("wrote", path.relative_to(REPO))


write(
    "governance-evaluation",
    "ev_accept.json",
    {
        "id": "ev_accept",
        "artifact_type": "GovernanceEvaluation",
        "expected": "ACCEPT",
        "reason_code": "ACCEPT",
        "payload": ev_payload(),
    },
)

ev_bad = ev_payload()
ev_bad["decision"] = "NOT_A_DECISION"
write(
    "governance-evaluation",
    "ev_reject_bad_enum.json",
    {
        "id": "ev_reject_bad_enum",
        "artifact_type": "GovernanceEvaluation",
        "expected": "REJECT",
        "reason_code": "SCHEMA_INVALID",
        "payload": ev_bad,
    },
)

ev_bad2 = ev_payload()
del ev_bad2["evaluator_id"]
write(
    "governance-evaluation",
    "ev_reject_missing_required.json",
    {
        "id": "ev_reject_missing_required",
        "artifact_type": "GovernanceEvaluation",
        "expected": "REJECT",
        "reason_code": "SCHEMA_INVALID",
        "payload": ev_bad2,
    },
)

ev_bad3 = ev_payload()
ev_bad3["action_envelope_digest"] = "not-a-digest"
write(
    "governance-evaluation",
    "ev_reject_bad_digest_pattern.json",
    {
        "id": "ev_reject_bad_digest_pattern",
        "artifact_type": "GovernanceEvaluation",
        "expected": "REJECT",
        "reason_code": "SCHEMA_INVALID",
        "payload": ev_bad3,
    },
)

write(
    "admissibility-determination",
    "det_accept.json",
    {
        "id": "det_accept",
        "artifact_type": "AdmissibilityDetermination",
        "expected": "ACCEPT",
        "reason_code": "ACCEPT",
        "payload": det_payload(),
    },
)

det_bad = det_payload()
det_bad["evaluation_bindings"] = []
write(
    "admissibility-determination",
    "det_reject_empty_bindings.json",
    {
        "id": "det_reject_empty_bindings",
        "artifact_type": "AdmissibilityDetermination",
        "expected": "REJECT",
        "reason_code": "SCHEMA_INVALID",
        "payload": det_bad,
    },
)

det_bad2 = det_payload()
det_bad2["state"] = "WRONG_STATE"
write(
    "admissibility-determination",
    "det_reject_bad_state_enum.json",
    {
        "id": "det_reject_bad_state_enum",
        "artifact_type": "AdmissibilityDetermination",
        "expected": "REJECT",
        "reason_code": "SCHEMA_INVALID",
        "payload": det_bad2,
    },
)

_clr = clr_payload()
_clr_model = GovernanceClearance.model_validate(_clr)
_clr["payload_digest"] = _clr_model.model_digest()
write(
    "governance-clearance",
    "clr_allow_accept.json",
    {
        "id": "clr_allow_accept",
        "artifact_type": "GovernanceClearance",
        "expected": "ACCEPT",
        "reason_code": "ACCEPT",
        "payload": _clr,
    },
)

clr_bad = clr_payload()
clr_bad["constraints"] = {
    "machine_readable": True,
    "binds_exact_action": True,
    "rules": [{"id": "r1", "predicate": "max", "target": "x", "value": 5}],
}
clr_bad_model = GovernanceClearance.model_validate(clr_bad)
clr_bad["payload_digest"] = clr_bad_model.model_digest()
write(
    "governance-clearance",
    "clr_allow_with_constraints.json",
    {
        "id": "clr_allow_with_constraints",
        "artifact_type": "GovernanceClearance",
        "expected": "REJECT",
        "reason_code": "SCHEMA_INVALID",
        "payload": clr_bad,
    },
)

clr_bad2 = clr_payload()
clr_bad2["decision"] = "MODIFY"
clr_bad2["admissibility_state"] = "CONDITIONALLY_ADMISSIBLE"
clr_bad2_model = GovernanceClearance.model_validate(clr_bad2)
clr_bad2["payload_digest"] = clr_bad2_model.model_digest()
write(
    "governance-clearance",
    "clr_modify_missing_constraints.json",
    {
        "id": "clr_modify_missing_constraints",
        "artifact_type": "GovernanceClearance",
        "expected": "REJECT",
        "reason_code": "SCHEMA_INVALID",
        "payload": clr_bad2,
    },
)

clr_bad3 = clr_payload()
clr_bad3["admissibility_state"] = "CONDITIONALLY_ADMISSIBLE"
clr_bad3_model = GovernanceClearance.model_validate(clr_bad3)
clr_bad3["payload_digest"] = clr_bad3_model.model_digest()
write(
    "governance-clearance",
    "clr_allow_state_mismatch.json",
    {
        "id": "clr_allow_state_mismatch",
        "artifact_type": "GovernanceClearance",
        "expected": "REJECT",
        "reason_code": "SCHEMA_INVALID",
        "payload": clr_bad3,
    },
)

clr_bad4 = clr_payload()
clr_bad4["replay_nonce"] = "short"
write(
    "governance-clearance",
    "clr_reject_short_nonce.json",
    {
        "id": "clr_reject_short_nonce",
        "artifact_type": "GovernanceClearance",
        "expected": "REJECT",
        "reason_code": "SCHEMA_INVALID",
        "payload": clr_bad4,
    },
)

_ev_actual = GovernanceEvaluation.model_validate(ev_payload()).model_digest()
_det_chain = det_payload()
_det_chain["evaluation_bindings"] = [
    {"evaluation_ref": "ev-001", "evaluation_digest": _ev_actual}
]
_det_actual = AdmissibilityDetermination.model_validate(_det_chain).model_digest()
_clr_chain = clr_payload()
_clr_chain["admissibility_determination_digest"] = _det_actual
_clr_chain_model = GovernanceClearance.model_validate(_clr_chain)
_clr_chain["payload_digest"] = _clr_chain_model.model_digest()

write(
    "cross-artifact-bindings",
    "chain_accept.json",
    {
        "id": "chain_accept",
        "artifact_type": "GovernanceClearance",
        "expected": "ACCEPT",
        "reason_code": "ACCEPT",
        "verification_time": VERIFICATION_TIME,
        "payload": _clr_chain,
        "resolved": {
            "evaluation": ev_payload(),
            "determination": _det_chain,
        },
    },
)

_clr_m = clr_payload()
_clr_m["admissibility_determination_digest"] = DET_DIGEST
_clr_m_model = GovernanceClearance.model_validate(_clr_m)
_clr_m["payload_digest"] = _clr_m_model.model_digest()
write(
    "cross-artifact-bindings",
    "chain_reject_det_digest_mismatch.json",
    {
        "id": "chain_reject_det_digest_mismatch",
        "artifact_type": "GovernanceClearance",
        "expected": "REJECT",
        "reason_code": "CLEARANCE_DETERMINATION_DIGEST_MISMATCH",
        "payload": _clr_m,
        "resolved": {"evaluation": ev_payload(), "determination": _det_chain},
    },
)

_det_badbind = det_payload()
_det_badbind["evaluation_bindings"] = [
    {"evaluation_ref": "ev-001", "evaluation_digest": "sha256:" + "0" * 64}
]
_clr_b = clr_payload()
_clr_b["admissibility_determination_digest"] = _det_actual
_clr_b_model = GovernanceClearance.model_validate(_clr_b)
_clr_b["payload_digest"] = _clr_b_model.model_digest()
write(
    "cross-artifact-bindings",
    "chain_reject_eval_binding_mismatch.json",
    {
        "id": "chain_reject_eval_binding_mismatch",
        "artifact_type": "GovernanceClearance",
        "expected": "REJECT",
        "reason_code": "EVALUATION_BINDING_DIGEST_MISMATCH",
        "payload": _clr_b,
        "resolved": {"evaluation": ev_payload(), "determination": _det_badbind},
    },
)

print("\nAll vectors generated.")
