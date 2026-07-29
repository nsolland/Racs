"""CLI and conformance interface for RACS v0.2 canonical and runtime vectors."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

from .boundary_crossing import BoundaryCrossingAssessment
from .canonical import canonical_bytes
from .models import AdmissibilityDetermination, GovernanceClearance, GovernanceEvaluation
from .validation import check
from .verification import verify_clearance_binding, verify_evaluation_binding


def _emit_canonical(payload: object) -> dict[str, str]:
    canonical = canonical_bytes(payload)
    return {
        "canonical": canonical.decode("utf-8"),
        "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
    }


def _runtime_check(vector: dict[str, Any]) -> dict[str, Any]:
    artifact_type = vector["artifact_type"]
    payload = vector["payload"]
    verification_time = vector.get("verification_time")
    port_a = check(artifact_type, payload)
    decision = port_a.decision
    reason_code = port_a.reason_code

    if decision == "ACCEPT" and "resolved" in vector:
        resolved = vector["resolved"]
        verification = None

        if artifact_type == "GovernanceClearance":
            clearance = GovernanceClearance.model_validate(payload)
            determination = AdmissibilityDetermination.model_validate(
                resolved["determination"]
            )
            evaluation = GovernanceEvaluation.model_validate(resolved["evaluation"])
            assessment = BoundaryCrossingAssessment.model_validate(
                resolved["boundary_assessment"]
            )
            action_envelope = resolved["action_envelope"]

            verification = verify_evaluation_binding(
                determination,
                evaluation,
                boundary_assessment=assessment,
            )
            if verification.decision == "ACCEPT":
                verification = verify_clearance_binding(
                    clearance,
                    determination,
                    action_envelope=action_envelope,
                    verification_time=verification_time,
                    governance_evaluation=evaluation,
                    boundary_assessment=assessment,
                )
        elif artifact_type == "AdmissibilityDetermination":
            determination = AdmissibilityDetermination.model_validate(payload)
            evaluation = GovernanceEvaluation.model_validate(resolved["evaluation"])
            assessment_payload = resolved.get("boundary_assessment")
            assessment = (
                BoundaryCrossingAssessment.model_validate(assessment_payload)
                if assessment_payload is not None
                else None
            )
            verification = verify_evaluation_binding(
                determination,
                evaluation,
                boundary_assessment=assessment,
            )

        if verification is not None and verification.decision == "REJECT":
            decision = verification.decision
            reason_code = verification.reason_code

    output: dict[str, Any] = {
        "id": vector.get("id"),
        "decision": decision,
        "reason_code": reason_code,
    }
    if decision == "ACCEPT":
        if port_a.canonical_bytes is not None:
            output["canonical"] = port_a.canonical_bytes.decode("utf-8")
        if port_a.payload_digest is not None:
            output["payload_digest"] = port_a.payload_digest

    output["expected"] = vector.get("expected")
    output["expected_reason_code"] = vector.get("reason_code")
    output["match"] = (
        decision == output["expected"]
        and reason_code == output["expected_reason_code"]
    )
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="racs_v02")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="JSON file to canonicalize")
    group.add_argument("--vector", help="JCS vector file")
    group.add_argument("--check", help="runtime-validation vector to verify")
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        print(json.dumps(_emit_canonical(payload), indent=2, ensure_ascii=False))
        return 0

    if args.check:
        with open(args.check, "r", encoding="utf-8") as handle:
            vector = json.load(handle)
        output = _runtime_check(vector)
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return 0 if output["match"] else 1

    with open(args.vector, "r", encoding="utf-8") as handle:
        vector = json.load(handle)
    if "input" in vector:
        subject = vector["input"]
        expected_canonical = vector["expected_canonical"]
        expected_digest = vector["expected_digest"]
    elif "payload" in vector:
        subject = vector["payload"]
        expected_canonical = vector["canonical_payload"]
        expected_digest = vector["payload_digest"]
    else:
        print(json.dumps({"error": "vector has neither input nor payload"}))
        return 2

    output = _emit_canonical(subject)
    match = (
        output["canonical"] == expected_canonical
        and output["digest"] == expected_digest
    )
    print(
        json.dumps(
            {"got": output, "expected": vector, "match": match},
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0 if match else 1


if __name__ == "__main__":
    sys.exit(main())
