#!/usr/bin/env python3
"""Cross-language byte-identical gate for RACS v0.2 canonical bindings (stage 3A).

Hard requirement: Python (rfc8785), Rust (serde_jcs), and TypeScript
(json-canonicalize) MUST emit byte-identical canonical UTF-8 bytes AND
identical sha256 digests for every shared JCS vector.

Usage: python3 gate.py   (from reference/bindings/v0.2/)
Exit 0 if all three agree on every vector, 1 otherwise.
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


def main() -> int:
    failures = 0
    for vf in VECTORS:
        name = vf.name
        py = py_canon(vf)
        rs = rs_canon(vf)
        ts = ts_canon(vf)
        ok = (py["got"]["canonical"] == rs["got_canonical"] == ts["got_canonical"] and
              py["got"]["digest"] == rs["got_digest"] == ts["got_digest"])
        if ok:
            print(f"PASS  {name}  canonical+digest byte-identical across py/rs/ts")
        else:
            failures += 1
            print(f"FAIL  {name}")
            print(f"  py canonical: {py['got_canonical']}")
            print(f"  rs canonical: {rs['got_canonical']}")
            print(f"  ts canonical: {ts['got_canonical']}")
            print(f"  py digest:    {py['got_digest']}")
            print(f"  rs digest:    {rs['got_digest']}")
            print(f"  ts digest:    {ts['got_digest']}")
    if failures == 0:
        print(f"\nGATE OK: all {len(VECTORS)} vectors byte-identical across py/rs/ts")
        return 0
    print(f"\nGATE FAILED: {failures} vector(s) differ across languages")
    return 1


if __name__ == "__main__":
    sys.exit(main())
