#!/usr/bin/env python3
"""Validate RACS repository profile metadata.

Checks that the canonical AI-first profile (nsolland/Index#338) is internally
consistent across the four machine-readable files:

  - repo-manifest.yaml  (authoritative contract)
  - publiccode.yml
  - llms.txt
  - AGENTS.md

Supports both the canonical Index schema format (repository/purpose/claims) and
the legacy RACS-specific format (identity/ownership/contract). In canonical mode
the actual legacy-profile checks run against the ``legacy_profile`` subtree.

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
REQUIRED_LEGACY_KEYS = [
    "identity",
    "ownership",
    "contract",
]

ERRORS: list[str] = []


def err(msg: str) -> None:
    ERRORS.append(msg)


def _check_legacy(data: dict, fname: str) -> None:
    """Run legacy RACS-specific checks against the supplied manifest dict."""
    for key in REQUIRED_LEGACY_KEYS:
        if key not in data:
            err(f"{fname}: missing required key '{key}'")

    identity = data.get("identity", {})
    stable_id = identity.get("stable_id")
    if stable_id != "valo.racs":
        err(f"{fname}: identity.stable_id must be 'valo.racs', got {stable_id!r}")

    maturity = data.get("maturity", {})
    if maturity.get("status") not in ("planned", "implemented", "deprecated"):
        err(f"{fname}: maturity.status must be planned|implemented|deprecated")

    contract = data.get("contract", {})
    owns = contract.get("owns", [])
    if not any("receipt" in str(o).lower() for o in owns):
        err(f"{fname}: contract.owns must include the receipt contract")

    if not data.get("license", {}).get("spdx_id"):
        err(f"{fname}: license.spdx_id required")


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

    # Detect format: canonical Index schema vs legacy RACS-specific format.
    canonical = bool(data.get("repository")) and bool(data.get("purpose"))
    if canonical:
        legacy = data.get("legacy_profile")
        if not legacy:
            err(f"{manifest_path.name}: canonical format requires legacy_profile subtree")
            return data
        _check_legacy(legacy, manifest_path.name)
        return data

    _check_legacy(data, manifest_path.name)
    return data


def check_cross_consistency(manifest: dict) -> None:
    """Check cross-file consistency (publiccode.yml, llms.txt, AGENTS.md)."""
    if not manifest:
        return

    # Determine which subtree holds the stable_id.
    canonical = bool(manifest.get("repository")) and bool(manifest.get("purpose"))
    source = manifest.get("legacy_profile", {}) if canonical else manifest
    stable_id = source.get("identity", {}).get("stable_id")
    if stable_id != "valo.racs":
        return  # already reported

    pc_path = REPO_ROOT / "publiccode.yml"
    if pc_path.exists():
        try:
            pc = yaml.safe_load(pc_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            err(f"publiccode.yml: YAML parse error: {exc}")
            pc = {}
        if pc.get("name") != "RACS":
            err("publiccode.yml: name must be 'RACS' to match repo-manifest.yaml")

    llms_path = REPO_ROOT / "llms.txt"
    if llms_path.exists():
        text = llms_path.read_text(encoding="utf-8")
        if "valo.racs" not in text:
            err("llms.txt: must reference stable_id 'valo.racs'")
        if "REHT-104" not in text:
            err("llms.txt: must reference REHT-104 receipt obligation")

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
