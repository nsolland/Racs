#!/usr/bin/env python3
"""Validate the public RACS repository profile.

This validator checks only public repository metadata. It intentionally has no
private catalogue, private repository, work-claim, or portfolio-topology
dependency.
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
ERRORS: list[str] = []


def err(msg: str) -> None:
    ERRORS.append(msg)


def read_yaml(path: Path) -> dict:
    if not path.exists():
        err(f"missing {path.name}")
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        err(f"{path.name}: YAML parse error: {exc}")
        return {}
    if not isinstance(data, dict):
        err(f"{path.name}: top-level must be a mapping")
        return {}
    return data


def main() -> int:
    manifest = read_yaml(REPO_ROOT / "repo-manifest.yaml")
    repository = manifest.get("repository", {}) if manifest else {}
    if repository.get("canonical_name") != "RACS":
        err("repo-manifest.yaml: repository.canonical_name must be 'RACS'")
    if repository.get("visibility") != "public":
        err("repo-manifest.yaml: repository.visibility must be 'public'")

    publiccode = read_yaml(REPO_ROOT / "publiccode.yml")
    if publiccode and publiccode.get("name") != "RACS":
        err("publiccode.yml: name must be 'RACS'")

    for filename in ("llms.txt", "AGENTS.md"):
        path = REPO_ROOT / filename
        if not path.exists():
            err(f"missing {filename}")
            continue
        text = path.read_text(encoding="utf-8")
        if "RACS" not in text:
            err(f"{filename}: must identify RACS")

    if ERRORS:
        sys.stderr.write("Repository profile validation FAILED:\n")
        for item in ERRORS:
            sys.stderr.write(f"  - {item}\n")
        return 1

    sys.stdout.write("Repository profile validation OK\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
