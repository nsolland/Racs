"""CLI / test interface for canonicalization and runtime conformance.

Used so CI can compare the three language bindings directly. Run:

    python -m racs_v02.cli --file <json>
    python -m racs_v02.cli --vector <jcs-vector-file>
    python -m racs_v02.cli --check <runtime-vector-file>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

from .canonical import canonical_bytes
from .models import (
    AdmissibilityDetermination,
    GovernanceClearance,
    GovernanceEvaluation,
)
from .validation import check
from .verification import verify_clearance_binding, verify_evaluation_binding


def _emit_canonical(payload: object) -> dict[str, str]:
    canon = canonical_bytes(payload)
    return {
        "canonical": canon.decode("utf-8"),
        "digest": "sha256:" + hashlib.sha256(canon).hexdigest(),
    }


def _runtime_check(vec: dict[str, Any]) -> dict[str, Any]:
    artifact_type = vec["artifact_type"]
    payload = vec["payload"]
    port_a = check(artifact_type, payload)

    decision = port_a.decision
    reason_code = port_a.reason_code

    if decision == "ACCEPT" and "resolved" in vec:
        resolved = vec["resolved"]
        verification = None

        if artifact_type == "GovernanceClearance":
            clearance = GovernanceClearance.model_validate(payload)
            determination = AdmissibilityDetermination.model_validate(
                resolved["determination"]
            )
            evaluation = GovernanceEvaluation.model_validate(resolved["evaluation"])
            verification = verify_evaluation_binding(determination, evaluation)
            if verification.decision == "ACCEPT":
                verification = verify_clearance_binding(clearance, determination)
        elif artifact_type == "AdmissibilityDetermination":
            determination = AdmissibilityDetermination.model_validate(payload)
            evaluation = GovernanceEvaluation.model_validate(resolved["evaluation"])
            verification = verify_evaluation_binding(determination, evaluation)

        if verification is not None and verification.decision == "REJECT":
            decision = verification.decision
            reason_code = verification.reason_code

    out: dict[str, Any] = {
        "id": vec.get("id"),
        "decision": decision,
        "reason_code": reason_code,
    }
    if decision == "ACCEPT":
        if port_a.canonical_bytes is not None:
            out["canonical"] = port_a.canonical_bytes.decode("utf-8")
        if port_a.payload_digest is not None:
            out["payload_digest"] = port_a.payload_digest

    expected = vec.get("expected")
    expected_reason = vec.get("reason_code")
    out["expected"] = expected
    out["expected_reason_code"] = expected_reason
    out["match"] = decision == expected and reason_code == expected_reason
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="racs_v02")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="JSON file to canonicalize")
    group.add_argument("--vector", help="JCS vector file with input/expected_*")
    group.add_argument("--check", help="runtime-validation vector to verify")
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        out = _emit_canonical(payload)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    if args.check:
        with open(args.check, "r", encoding="utf-8") as fh:
            vec = json.load(fh)
        out = _runtime_check(vec)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0 if out["match"] else 1

    with open(args.vector, "r", encoding="utf-8") as fh:
        vec = json.load(fh)
    if "input" in vec:
        subject, exp_canon, exp_digest = (
            vec["input"],
            vec["expected_canonical"],
            vec["expected_digest"],
        )
    elif "payload" in vec:
        subject, exp_canon, exp_digest = (
            vec["payload"],
            vec["canonical_payload"],
            vec["payload_digest"],
        )
    else:
        print(
            json.dumps(
                {"error": "vector has neither 'input' nor 'payload'"},
                ensure_ascii=False,
            )
        )
        return 2

    out = _emit_canonical(subject)
    ok = out["canonical"] == exp_canon and out["digest"] == exp_digest
    print(
        json.dumps(
            {"got": out, "expected": vec, "match": ok},
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
