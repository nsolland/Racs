"""Version-manifest consistency — v0.2 base vs additive v0.3 delta.

RACS ships 138 v0.2 contracts plus a small additive v0.3 delta. This pins the
versioning story: every v0.3 schema must be declared in the manifest's delta
set, and no contract family may hold both versions without being declared a
dual-version family.
"""

from __future__ import annotations

import glob
import json
import os
import re
from pathlib import Path

SPEC = Path(__file__).resolve().parents[2] / "spec"
MANIFEST = json.loads((SPEC / "version-manifest.json").read_text(encoding="utf-8"))

_FAMILY_RE = re.compile(r"(.+?)-v0\.[23]\.schema\.json$")


def _schema_files() -> list[str]:
    return [os.path.basename(path) for path in glob.glob(str(SPEC / "*.schema.json"))]


def _family(filename: str) -> str:
    match = _FAMILY_RE.match(filename)
    return match.group(1) if match else filename[: -len(".schema.json")]


def test_base_and_delta_counts_match_manifest():
    files = _schema_files()
    v03 = sorted(
        f[: -len("-v0.3.schema.json")]
        for f in files
        if f.endswith("-v0.3.schema.json")
    )
    base = len([f for f in files if not f.endswith("-v0.3.schema.json")])
    assert v03 == sorted(MANIFEST["delta_contracts"]), (
        "v0.3 schema set diverges from version-manifest.json"
    )
    assert base == MANIFEST["base_contract_count"], (
        "base (v0.2) contract count diverges from version-manifest.json"
    )


def test_no_undocumented_dual_version_family():
    files = _schema_files()
    families = {}
    for filename in files:
        families.setdefault(_family(filename), []).append(filename)
    dual = sorted(
        family
        for family, versions in families.items()
        if len(versions) >= 2
    )
    assert dual == sorted(MANIFEST["dual_version_families"]), (
        f"undocumented dual-version families: {set(dual) ^ set(MANIFEST['dual_version_families'])}"
    )


def test_delta_contracts_exist_in_spec():
    for delta in MANIFEST["delta_contracts"]:
        assert (SPEC / f"{delta}-v0.3.schema.json").exists(), (
            f"manifest lists {delta}-v0.3.schema.json but it is missing"
        )


def test_dual_version_family_has_compatibility_doc():
    assert (SPEC / "AGENTBOUND_DELTA_V0_2_V0_3_COMPATIBILITY.md").exists()
