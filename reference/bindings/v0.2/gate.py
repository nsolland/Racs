#!/usr/bin/env python3
"""Cross-language byte-identical gate for RACS v0.2 canonical bindings.

Stage 3A: Python (rfc8785), Rust (serde_jcs), TypeScript (json-canonicalize)
MUST emit byte-identical canonical UTF-8 bytes AND identical sha256 digests
for every shared JCS vector.

Stage 3B: the typed model bindings (GovernanceEvaluation etc.) in all three
languages, when canonicalizing the same golden payload via the 3A kernel, MUST
produce the same digest — and it MUST equal the step-2 golden digest.

Usage: python3 gate.py   (from reference/bindings/v0.2/)
Exit 0 if all checks agree, 1 otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VECTORS = sorted((ROOT.parent.parent.parent / "test-vectors" / "jcs" / "official").glob("vector-*.json")) + \
    [ROOT.parent.parent.parent / "test-vectors" / "jcs" / "racs-v0.2" / "governance-evaluation.json"]
GOLDEN = ROOT.parent.parent.parent / "test-vectors" / "0.2" / "governance-evaluation-golden.json"
STEP2_DIGEST = "sha256:58c8431515435642ee92d148a0636f2b20c5292c843fc8977a1fda3f5d94644c"


def _run(cmd: list[str], env_extra: dict[str, str] | None = None) -> dict:
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    out = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if out.returncode != 0:
        raise RuntimeError(f"{cmd} failed: {out.stderr}")
    return json.loads(out.stdout)


def py_canon(vec_file: Path) -> dict:
    venv = ROOT / "python" / ".venv" / "bin" / "activate"
    return _run(
        ["bash", "-lc",
         f"source {venv} && python -m racs_v02.cli --vector {vec_file}"],
    )


def rs_canon(vec_file: Path) -> dict:
    bin_ = ROOT / "rust" / "target" / "release" / "racs-v02-conformance"
    return _run([str(bin_), "--vector", str(vec_file)])


def ts_canon(vec_file: Path) -> dict:
    return _run(
        ["bash", "-lc",
         f"cd {ROOT / 'typescript'} && node dist/src/cli.js --vector {vec_file}"],
    )


def py_model_digest(payload: dict) -> str:
    venv = ROOT / "python" / ".venv" / "bin" / "activate"
    env = dict(os.environ)
    out = subprocess.run(
        ["bash", "-lc",
         f"source {venv} && python -c \"import json; from racs_v02 import GovernanceEvaluation; "
         f"ev=GovernanceEvaluation(**json.load(open('{GOLDEN}'))['payload']); print(ev.model_digest())\""],
        capture_output=True, text=True, env=env,
    )
    if out.returncode != 0:
        raise RuntimeError(f"py_model_digest failed: {out.stderr}")
    return out.stdout.strip()


def rs_model_digest() -> str:
    bin_ = ROOT / "rust" / "target" / "release" / "racs-v02-conformance"
    out = _run([str(bin_), "--model-digest", str(GOLDEN)])
    return out["digest"]


def ts_model_digest() -> str:
    env = dict(os.environ)
    out = subprocess.run(
        ["bash", "-lc",
         f"cd {ROOT / 'typescript'} && node -e \"import('./dist/src/index.js').then(m=>{{"
         f"const v=require('fs');const p=JSON.parse(v.readFileSync('{GOLDEN}')).payload;"
         f"const ev=Object.assign(new m.GovernanceEvaluation(), p);console.log(ev.digest());}})\""],
        capture_output=True, text=True, env=env,
    )
    if out.returncode != 0:
        raise RuntimeError(f"ts_model_digest failed: {out.stderr}")
    return out.stdout.strip()


def main() -> int:
    failures = 0

    # ---- Stage 3A: raw vectors byte-identical across languages ----
    for vf in VECTORS:
        name = vf.name
        py = py_canon(vf)
        rs = rs_canon(vf)
        ts = ts_canon(vf)
        ok = (py["got"]["canonical"] == rs["got_canonical"] == ts["got_canonical"] and
              py["got"]["digest"] == rs["got_digest"] == ts["got_digest"])
        if ok:
            print(f"PASS  [3A] {name}  canonical+digest byte-identical across py/rs/ts")
        else:
            failures += 1
            print(f"FAIL  [3A] {name}")
            print(f"  py canonical: {py['got_canonical']}")
            print(f"  rs canonical: {rs['got_canonical']}")
            print(f"  ts canonical: {ts['got_canonical']}")
            print(f"  py digest:    {py['got_digest']}")
            print(f"  rs digest:    {rs['got_digest']}")
            print(f"  ts digest:    {ts['got_digest']}")

    # ---- Stage 3B: typed models digest golden identically, == step-2 ----
    py_d = py_model_digest(json.loads(GOLDEN.read_text())["payload"])
    rs_d = rs_model_digest()
    ts_d = ts_model_digest()
    ok3b = (py_d == rs_d == ts_d == STEP2_DIGEST)
    if ok3b:
        print(f"PASS  [3B] GovernanceEvaluation model digest byte-identical across py/rs/ts == step-2 golden")
    else:
        failures += 1
        print(f"FAIL  [3B] GovernanceEvaluation model digest differs")
        print(f"  py={py_d}")
        print(f"  rs={rs_d}")
        print(f"  ts={ts_d}")
        print(f"  step2={STEP2_DIGEST}")

    if failures == 0:
        print(f"\nGATE OK: all {len(VECTORS)} vectors (3A) + typed models (3B) byte-identical across py/rs/ts")
        return 0
    print(f"\nGATE FAILED: {failures} check(s) differ across languages")
    return 1


if __name__ == "__main__":
    sys.exit(main())
