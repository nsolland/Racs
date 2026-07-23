"""CLI / test interface: produce RFC 8785 canonical bytes and digest.

Used so CI can compare the three language bindings directly. Run:

    python -m racs_v02.cli --file <json>          # canonical bytes + digest of file
    python -m racs_v02.cli --vector <jcs-vector-file>  # check against expected
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from .canonical import canonical_bytes
from .digest import sha256_digest


def _emit_canonical(payload: object) -> dict:
    canon = canonical_bytes(payload)
    return {
        "canonical": canon.decode("utf-8"),
        "digest": "sha256:" + hashlib.sha256(canon).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="racs_v02")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="JSON file to canonicalize")
    group.add_argument("--vector", help="JCS vector file with input/expected_*")
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        out = _emit_canonical(payload)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    # vector mode: verify against expected_canonical / expected_digest
    with open(args.vector, "r", encoding="utf-8") as fh:
        vec = json.load(fh)
    # Two vector shapes are supported:
    #   official JCS:  {"input":..., "expected_canonical":..., "expected_digest":...}
    #   RACS payload:  {"payload":..., "canonical_payload":..., "payload_digest":...}
    if "input" in vec:
        subject, exp_canon, exp_digest = (
            vec["input"], vec["expected_canonical"], vec["expected_digest"])
    elif "payload" in vec:
        subject, exp_canon, exp_digest = (
            vec["payload"], vec["canonical_payload"], vec["payload_digest"])
    else:
        print(json.dumps({"error": "vector has neither 'input' nor 'payload'"},
                         ensure_ascii=False))
        return 2
    out = _emit_canonical(subject)
    ok = (
        out["canonical"] == exp_canon
        and out["digest"] == exp_digest
    )
    print(json.dumps({"got": out, "expected": vec, "match": ok}, indent=2, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
