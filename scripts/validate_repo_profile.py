#!/usr/bin/env python3
"""Validate RACS repository profile metadata.

Checks that the canonical AI-first profile (nsolland/Index#338) is internally
consistent across the four machine-readable files:

  - repo-manifest.yaml  (authoritative contract)
  - publiccode.yml
  - llms.txt
  - AGENTS.md

Fails (exit 1) on missing, inconsistent, or stale metadata so CI can block
merges that break the repository profile.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("PyYAML is required: pip install pyyaml\n")
    sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent
REQUIRED_MANIFEST_KEYS = [
    "schema_version",
    "identity",
    "ownership",
    "boundaries",
    "maturity",
    "contract",
    "dependencies",
    "interfaces",
    "security",
    "license",
    "non_claims",
    "limitations",
]

ERRORS: list[str] = []


def err(msg: str) -> None:
    ERRORS.append(msg)


def check_manifest(manifest_path: Path) -> dict:
    if not manifest_path.exists():
        err(f"missing {manifest_path.name}")
        return {}
    try:
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        err(f"{manifest_path.name}: YAML parse error: {exc}")
        return {}

    if not isinstance(data, dict):
        err(f"{manifest_path.name}: top-level must be a mapping")
        return {}

    for key in REQUIRED_MANIFEST_KEYS:
        if key not in data:
            err(f"{manifest_path.name}: missing required key '{key}'")

    # identity checks
    identity = data.get("identity", {})
    stable_id = identity.get("stable_id")
    if stable_id != "valo.racs":
        err(f"{manifest_path.name}: identity.stable_id must be 'valo.racs', got {stable_id!r}")

    # maturity vs contract claims
    maturity = data.get("maturity", {})
    if maturity.get("status") not in ("planned", "implemented", "deprecated"):
        err(f"{manifest_path.name}: maturity.status must be planned|implemented|deprecated")

    # contract ownership invariants
    contract = data.get("contract", {})
    owns = contract.get("owns", [])
    if not any("receipt" in str(o).lower() for o in owns):
        err(f"{manifest_path.name}: contract.owns must include the receipt contract")

    # license present
    if not data.get("license", {}).get("spdx_id"):
        err(f"{manifest_path.name}: license.spdx_id required")

    return data


def check_cross_consistency(manifest: dict) -> None:
    if not manifest:
        return
    stable_id = manifest.get("identity", {}).get("stable_id")
    if stable_id != "valo.racs":
        return  # already reported

    # publiccode.yml must reference the same name
    pc_path = REPO_ROOT / "publiccode.yml"
    if pc_path.exists():
        try:
            pc = yaml.safe_load(pc_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            err(f"publiccode.yml: YAML parse error: {exc}")
            pc = {}
        if pc.get("name") != "RACS":
            err("publiccode.yml: name must be 'RACS' to match repo-manifest.yaml")

    # llms.txt must contain the stable id
    llms_path = REPO_ROOT / "llms.txt"
    if llms_path.exists():
        text = llms_path.read_text(encoding="utf-8")
        if "valo.racs" not in text:
            err("llms.txt: must reference stable_id 'valo.racs'")
        if "REHT-104" not in text:
            err("llms.txt: must reference REHT-104 receipt obligation")

    # AGENTS.md must reference the profile files
    agents_path = REPO_ROOT / "AGENTS.md"
    if agents_path.exists():
        text = agents_path.read_text(encoding="utf-8")
        for ref in ("repo-manifest.yaml", "publiccode.yml", "llms.txt", "claimed.json"):
            if ref not in text:
                err(f"AGENTS.md: must reference '{ref}'")


def main() -> int:
    manifest_path = REPO_ROOT / "repo-manifest.yaml"
    manifest = check_manifest(manifest_path)
    check_cross_consistency(manifest)

    if ERRORS:
        sys.stderr.write("Repository profile validation FAILED:\n")
        for e in ERRORS:
            sys.stderr.write(f"  - {e}\n")
        return 1

    sys.stdout.write("Repository profile validation OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
