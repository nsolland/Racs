#!/usr/bin/env python3
"""Cross-language canonical, typed-model and runtime conformance gate."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent.parent
CANONICAL_VECTORS = sorted(
    (REPO_ROOT / "test-vectors" / "jcs" / "official").glob("vector-*.json")
) + [REPO_ROOT / "test-vectors" / "jcs" / "racs-v0.2" / "governance-evaluation.json"]
GOLDEN = REPO_ROOT / "test-vectors" / "0.2" / "governance-evaluation-golden.json"
RUNTIME_VECTORS = sorted(
    path
    for path in (REPO_ROOT / "test-vectors" / "0.2" / "runtime-validation").rglob("*.json")
    if not path.name.startswith("_")
)
STEP2_DIGEST = "sha256:532d2a571f8536890bf9b79994703c63a44c01ba40f71b4733d045674bdb3273"


def _run(command: list[str], env: dict[str, Any] | None = None) -> dict[str, Any]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env or dict(os.environ),
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{command} failed with exit {result.returncode}:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return json.loads(result.stdout)


def _python(arguments: str) -> dict[str, Any]:
    activate = ROOT / "python" / ".venv" / "bin" / "activate"
    if activate.exists():
        return _run(["bash", "-lc", f"source {activate} && python -m racs_v02.cli {arguments}"])
    # Fallback for environments without a venv: run with the repo root and the
    # python binding source on PYTHONPATH so the gate is locally reproducible.
    python_src = ROOT / "python" / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(python_src) + os.pathsep + env.get("PYTHONPATH", "")
    return _run([sys.executable, "-m", "racs_v02.cli", *arguments.split()], env=env)


def _rust(arguments: list[str]) -> dict[str, Any]:
    binary = ROOT / "rust" / "target" / "release" / "racs-v02-conformance"
    return _run([str(binary), *arguments])


def _typescript(arguments: str) -> dict[str, Any]:
    return _run(
        [
            "bash",
            "-lc",
            f"cd {ROOT / 'typescript'} && node dist/src/cli.js {arguments}",
        ]
    )


def _python_model_digest() -> str:
    activate = ROOT / "python" / ".venv" / "bin" / "activate"
    result = subprocess.run(
        [
            "bash",
            "-lc",
            f"source {activate} && python -c \"import json; "
            f"from racs_v02 import GovernanceEvaluation; "
            f"payload=json.load(open('{GOLDEN}'))['payload']; "
            f"print(GovernanceEvaluation(**payload).model_digest())\"",
        ],
        capture_output=True,
        text=True,
        env=dict(os.environ),
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout.strip()


def _rust_model_digest() -> str:
    return _rust(["--model-digest", str(GOLDEN)])["digest"]


def _typescript_model_digest() -> str:
    result = subprocess.run(
        [
            "bash",
            "-lc",
            f"cd {ROOT / 'typescript'} && node -e \"import('./dist/src/index.js').then(m=>{{"
            f"const fs=require('fs');const p=JSON.parse(fs.readFileSync('{GOLDEN}')).payload;"
            f"const ev=Object.assign(new m.GovernanceEvaluation(),p);console.log(ev.digest());}})\"",
        ],
        capture_output=True,
        text=True,
        env=dict(os.environ),
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout.strip()


def _projection(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "decision": result.get("decision"),
        "reason_code": result.get("reason_code"),
        "canonical": result.get("canonical"),
        "payload_digest": result.get("payload_digest"),
    }


def main() -> int:
    failures = 0

    for vector in CANONICAL_VECTORS:
        py = _python(f"--vector {vector}")["got"]
        rs = _rust(["--vector", str(vector)])
        ts = _typescript(f"--vector {vector}")
        match = (
            py["canonical"] == rs["got_canonical"] == ts["got_canonical"]
            and py["digest"] == rs["got_digest"] == ts["got_digest"]
        )
        print(("PASS" if match else "FAIL") + f" [3A] {vector.name}")
        failures += 0 if match else 1

    model_digests = (
        _python_model_digest(),
        _rust_model_digest(),
        _typescript_model_digest(),
    )
    model_match = model_digests[0] == model_digests[1] == model_digests[2] == STEP2_DIGEST
    print(("PASS" if model_match else "FAIL") + " [3B] GovernanceEvaluation")
    if not model_match:
        print(f"  py={model_digests[0]}\n  rs={model_digests[1]}\n  ts={model_digests[2]}\n  golden={STEP2_DIGEST}")
        failures += 1

    for vector_path in RUNTIME_VECTORS:
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        py = _python(f"--check {vector_path}")
        rs = _rust(["--check", str(vector_path)])
        ts = _typescript(f"--check {vector_path}")
        projections = (_projection(py), _projection(rs), _projection(ts))
        match = (
            py.get("match") is True
            and rs.get("match") is True
            and ts.get("match") is True
            and projections[0] == projections[1] == projections[2]
            and projections[0]["decision"] == vector["expected"]
            and projections[0]["reason_code"] == vector["reason_code"]
        )
        print(("PASS" if match else "FAIL") + f" [3C] {vector['id']}")
        if not match:
            print(f"  expected={vector['expected']}/{vector['reason_code']}")
            print(f"  py={json.dumps(projections[0], sort_keys=True)}")
            print(f"  rs={json.dumps(projections[1], sort_keys=True)}")
            print(f"  ts={json.dumps(projections[2], sort_keys=True)}")
            failures += 1

    if failures:
        print(f"\nGATE FAILED: {failures} mismatch(es)")
        return 1
    print(
        f"\nGATE OK: {len(CANONICAL_VECTORS)} canonical + "
        f"{len(RUNTIME_VECTORS)} runtime vectors agree across Python/Rust/TypeScript"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
