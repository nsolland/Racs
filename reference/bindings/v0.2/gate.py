#!/usr/bin/env python3
"""Cross-language conformance gate for RACS v0.2 bindings.

Stage 3A verifies byte-identical RFC 8785 canonical bytes and SHA-256 digests.
Stage 3B verifies typed model digests against the step-2 golden.
Stage 3C verifies identical runtime ACCEPT/REJECT, normalized reason code,
canonical bytes, and payload digest across Python, Rust, and TypeScript.

Usage: python3 gate.py
Exit 0 if all checks agree, 1 otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent.parent
VECTORS = sorted(
    (REPO_ROOT / "test-vectors" / "jcs" / "official").glob("vector-*.json")
) + [
    REPO_ROOT / "test-vectors" / "jcs" / "racs-v0.2" / "governance-evaluation.json"
]
GOLDEN = REPO_ROOT / "test-vectors" / "0.2" / "governance-evaluation-golden.json"
RUNTIME_ROOT = REPO_ROOT / "test-vectors" / "0.2" / "runtime-validation"
RUNTIME_VECTORS = sorted(
    p for p in RUNTIME_ROOT.rglob("*.json") if not p.name.startswith("_")
)
STEP2_DIGEST = "sha256:58c8431515435642ee92d148a0636f2b20c5292c843fc8977a1fda3f5d94644c"


def _run(cmd: list[str], env_extra: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    out = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if out.returncode != 0:
        raise RuntimeError(
            f"{cmd} failed with exit {out.returncode}:\n"
            f"stdout:\n{out.stdout}\nstderr:\n{out.stderr}"
        )
    return json.loads(out.stdout)


def py_canon(vec_file: Path) -> dict[str, Any]:
    venv = ROOT / "python" / ".venv" / "bin" / "activate"
    return _run(
        [
            "bash",
            "-lc",
            f"source {venv} && python -m racs_v02.cli --vector {vec_file}",
        ]
    )


def rs_canon(vec_file: Path) -> dict[str, Any]:
    bin_ = ROOT / "rust" / "target" / "release" / "racs-v02-conformance"
    return _run([str(bin_), "--vector", str(vec_file)])


def ts_canon(vec_file: Path) -> dict[str, Any]:
    return _run(
        [
            "bash",
            "-lc",
            f"cd {ROOT / 'typescript'} && node dist/src/cli.js --vector {vec_file}",
        ]
    )


def py_check(vec_file: Path) -> dict[str, Any]:
    venv = ROOT / "python" / ".venv" / "bin" / "activate"
    return _run(
        [
            "bash",
            "-lc",
            f"source {venv} && python -m racs_v02.cli --check {vec_file}",
        ]
    )


def rs_check(vec_file: Path) -> dict[str, Any]:
    bin_ = ROOT / "rust" / "target" / "release" / "racs-v02-conformance"
    return _run([str(bin_), "--check", str(vec_file)])


def ts_check(vec_file: Path) -> dict[str, Any]:
    return _run(
        [
            "bash",
            "-lc",
            f"cd {ROOT / 'typescript'} && node dist/src/cli.js --check {vec_file}",
        ]
    )


def py_model_digest() -> str:
    venv = ROOT / "python" / ".venv" / "bin" / "activate"
    out = subprocess.run(
        [
            "bash",
            "-lc",
            f"source {venv} && python -c \"import json; "
            f"from racs_v02 import GovernanceEvaluation; "
            f"ev=GovernanceEvaluation(**json.load(open('{GOLDEN}'))['payload']); "
            f"print(ev.model_digest())\"",
        ],
        capture_output=True,
        text=True,
        env=dict(os.environ),
    )
    if out.returncode != 0:
        raise RuntimeError(f"py_model_digest failed: {out.stderr}")
    return out.stdout.strip()


def rs_model_digest() -> str:
    bin_ = ROOT / "rust" / "target" / "release" / "racs-v02-conformance"
    out = _run([str(bin_), "--model-digest", str(GOLDEN)])
    return out["digest"]


def ts_model_digest() -> str:
    out = subprocess.run(
        [
            "bash",
            "-lc",
            f"cd {ROOT / 'typescript'} && node -e \"import('./dist/src/index.js').then(m=>{{"
            f"const v=require('fs');const p=JSON.parse(v.readFileSync('{GOLDEN}')).payload;"
            f"const ev=Object.assign(new m.GovernanceEvaluation(), p);"
            f"console.log(ev.digest());}})\"",
        ],
        capture_output=True,
        text=True,
        env=dict(os.environ),
    )
    if out.returncode != 0:
        raise RuntimeError(f"ts_model_digest failed: {out.stderr}")
    return out.stdout.strip()


def _runtime_projection(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "decision": result.get("decision"),
        "reason_code": result.get("reason_code"),
        "canonical": result.get("canonical"),
        "payload_digest": result.get("payload_digest"),
    }


def main() -> int:
    failures = 0

    for vf in VECTORS:
        name = vf.name
        py = py_canon(vf)
        rs = rs_canon(vf)
        ts = ts_canon(vf)
        py_canonical = py["got"]["canonical"]
        py_digest = py["got"]["digest"]
        ok = (
            py_canonical == rs["got_canonical"] == ts["got_canonical"]
            and py_digest == rs["got_digest"] == ts["got_digest"]
        )
        if ok:
            print(
                f"PASS  [3A] {name}  canonical+digest byte-identical across py/rs/ts"
            )
        else:
            failures += 1
            print(f"FAIL  [3A] {name}")
            print(f"  py canonical: {py_canonical}")
            print(f"  rs canonical: {rs['got_canonical']}")
            print(f"  ts canonical: {ts['got_canonical']}")
            print(f"  py digest:    {py_digest}")
            print(f"  rs digest:    {rs['got_digest']}")
            print(f"  ts digest:    {ts['got_digest']}")

    py_d = py_model_digest()
    rs_d = rs_model_digest()
    ts_d = ts_model_digest()
    ok3b = py_d == rs_d == ts_d == STEP2_DIGEST
    if ok3b:
        print(
            "PASS  [3B] GovernanceEvaluation model digest byte-identical "
            "across py/rs/ts == step-2 golden"
        )
    else:
        failures += 1
        print("FAIL  [3B] GovernanceEvaluation model digest differs")
        print(f"  py={py_d}")
        print(f"  rs={rs_d}")
        print(f"  ts={ts_d}")
        print(f"  step2={STEP2_DIGEST}")

    for vf in RUNTIME_VECTORS:
        vector = json.loads(vf.read_text(encoding="utf-8"))
        py = py_check(vf)
        rs = rs_check(vf)
        ts = ts_check(vf)
        py_projection = _runtime_projection(py)
        rs_projection = _runtime_projection(rs)
        ts_projection = _runtime_projection(ts)
        ok = (
            py.get("match") is True
            and rs.get("match") is True
            and ts.get("match") is True
            and py_projection == rs_projection == ts_projection
            and py_projection["decision"] == vector["expected"]
            and py_projection["reason_code"] == vector["reason_code"]
        )
        if ok:
            print(
                f"PASS  [3C] {vector['id']}  decision+reason+canonical+digest "
                "identical across py/rs/ts"
            )
        else:
            failures += 1
            print(f"FAIL  [3C] {vector['id']}")
            print(f"  expected: {vector['expected']} / {vector['reason_code']}")
            print(f"  py: {json.dumps(py_projection, sort_keys=True)}")
            print(f"  rs: {json.dumps(rs_projection, sort_keys=True)}")
            print(f"  ts: {json.dumps(ts_projection, sort_keys=True)}")

    if failures == 0:
        print(
            f"\nGATE OK: {len(VECTORS)} canonical vectors (3A) + typed models "
            f"(3B) + {len(RUNTIME_VECTORS)} runtime vectors (3C) agree across "
            "py/rs/ts"
        )
        return 0

    print(f"\nGATE FAILED: {failures} check(s) differ across languages")
    return 1


if __name__ == "__main__":
    sys.exit(main())
