"""Generate RACS-JCS-1 golden vectors for P0.2 (issue #991).

Each golden payload conforms to its canonical RACS schema so it doubles as a fixture for
jsonschema validation. Canonicalization = RFC 8785 (jsoncanon). Digest = SHA-256 over
canonical bytes. Run: python3 spec/_gen_golden.py  (writes spec/golden-vectors.json)
"""
import json
import hashlib
from jsoncanon import canonicalize

ZERO = "sha256:" + "0" * 64


def digest(obj) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(obj)).hexdigest()


# 1) ActionEnvelope payload (spec/action-envelope-v0.2.schema.json)
action_envelope = {
    "action_id": "act-0001",
    "tenant_id": "tenant-abc",
    "action_type": "payment.transfer",
    "actor_ref": "did:valo:actor-7",
    "target_ref": "did:valo:vipps-acct-9",
    "target_digest": ZERO,
    "payload_digest": ZERO,
    "authority_grant_ref": "ag-1",
    "delegation_chain_ref": "dc-1",
    "policy_ref": "pol-1",
    "evidence_package_ref": "ep-1",
    "purpose_ref": "purp-1",
    "environment_state_ref": "env-1",
    "risk_context_ref": "rc-1",
    "connector_id": "connector-vipps",
    "capability": "finance.pay",
    "consequence_class": "HIGH",
    "reversibility": "COMPENSATABLE",
    "created_at": "2026-07-25T12:00:00Z",
    "expires_at": "2026-07-25T12:05:00Z",
    "replay_nonce": "abcdefghijklmnop",
    "idempotency_key": "idem-0001",
    "boundary_requirements": {
        "required_types": ["EXECUTION"],
        "policy_ref": "pol-1",
        "policy_digest": ZERO,
        "fail_closed": True,
    },
}
env_digest = digest(action_envelope)

# 2) GovernanceEvaluation (VAIG 6-verdict) — spec/governance-evaluation-v0.2
governance_evaluation = {
    "evaluation_id": "ge-1",
    "action_id": "act-0001",
    "action_envelope_digest": env_digest,
    "tenant_id": "tenant-abc",
    "evaluator_id": "vaig-aarm",
    "evaluator_version": "1.0.0",
    "decision": "ALLOW",
    "authority_status": "PRESENT_AND_VALID",
    "policy_status": "PRESENT_AND_VALID",
    "evidence_status": "PRESENT_AND_VALID",
    "purpose_status": "PRESENT_AND_VALID",
    "state_status": "PRESENT_AND_VALID",
    "risk_status": "PRESENT_AND_VALID",
    "boundary_assessment_binding": {
        "assessment_ref": "ba-1",
        "assessment_digest": ZERO,
    },
    "evaluated_at": "2026-07-25T11:59:00Z",
    "valid_until": "2026-07-25T12:04:00Z",
}
ge_digest = digest(governance_evaluation)

# 3) AdmissibilityDetermination (REHT 8-state) — spec/admissibility-determination-v0.2
admissibility = {
    "determination_id": "ad-1",
    "action_id": "act-0001",
    "action_envelope_digest": env_digest,
    "tenant_id": "tenant-abc",
    "authority_digest": ZERO,
    "delegation_chain_digest": ZERO,
    "policy_digest": ZERO,
    "evidence_digest": ZERO,
    "purpose_digest": ZERO,
    "state_digest": ZERO,
    "evaluation_bindings": [
        {"evaluation_ref": "ge-1", "evaluation_digest": ge_digest}
    ],
    "boundary_assessment_binding": {
        "assessment_ref": "ba-1",
        "assessment_digest": ZERO,
    },
    "state": "ADMISSIBLE",
    "determined_at": "2026-07-25T12:00:00Z",
    "valid_until": "2026-07-25T12:05:00Z",
    "revocation_registry_ref": "rr-1",
}
ad_digest = digest(admissibility)

# 4) ExecutionReceipt (Core proves) — spec/execution-receipt-v0.2
execution_receipt = {
    "execution_receipt_id": "er-1",
    "execution_id": "ex-1",
    "tenant_id": "tenant-abc",
    "action_id": "act-0001",
    "action_envelope_digest": env_digest,
    "clearance_id": "ad-1",
    "clearance_digest": ad_digest,
    "commit_token_id": "ct-1",
    "commit_token_digest": ZERO,
    "connector_id": "connector-vipps",
    "capability": "finance.pay",
    "target_digest": ZERO,
    "payload_digest": ZERO,
    "started_at": "2026-07-25T12:00:30Z",
    "completed_at": "2026-07-25T12:00:31Z",
    "technical_outcome": "SUCCEEDED",
    "provider_reference": "vipps-txn-xyz",
    "response_digest": ZERO,
    "reversal_status": "NOT_APPLICABLE",
    "previous_receipt_hash": ZERO,
}

vectors = {
    "racs_jcs_1": "RFC 8785",
    "digest_alg": "sha256",
    "generated_by": "P0.2 golden-vector tooling (issue #991)",
    "vectors": {
        "action_envelope_v0.2": {
            "payload": action_envelope,
            "payload_digest": env_digest,
            "schema": "action-envelope-v0.2.schema.json",
        },
        "governance_evaluation_v0.2": {
            "payload": governance_evaluation,
            "payload_digest": ge_digest,
            "schema": "governance-evaluation-v0.2.schema.json",
        },
        "admissibility_determination_v0.2": {
            "payload": admissibility,
            "payload_digest": ad_digest,
            "schema": "admissibility-determination-v0.2.schema.json",
        },
        "execution_receipt_v0.2": {
            "payload": execution_receipt,
            "payload_digest": digest(execution_receipt),
            "schema": "execution-receipt-v0.2.schema.json",
        },
    },
}

with open("spec/golden-vectors.json", "w", encoding="utf-8") as f:
    json.dump(vectors, f, indent=2, ensure_ascii=False)
    f.write("\n")

print("golden-vectors.json written")
for k, v in vectors["vectors"].items():
    print(" ", k, "->", v["payload_digest"])
