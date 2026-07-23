# AGENTS.md — RACS agent operating guide

> Machine-readable orientation for AI agents lives in `llms.txt`.
> Human/agent protocol overview lives in `CLAUDE.md`.
> This file is the **agent task contract**: how to work in this repo without breaking conventions.

## Repository identity
- Stable ID: `valo.racs`
- Canonical name: **RACS** (Runtime Agent Control Standard)
- Role: owns the canonical receipt and evidence contract. Normative status.
- Public URL: https://github.com/nsolland/Racs

## What this repo is
RACS is a **protocol specification**, not a runtime. It defines the contract between
evidence layers (BARO, Speider) and action governance layers (VAIG, REHT, Core).

## Hard boundaries (do not cross)
- RACS records decisions and effects; it does **not** grant clearance or execute actions.
- Do **not** redefine REHT admissibility rules. Map RACS receipt fields to REHT-104 only.
- Do **not** bake policy into code; policy is data in `policy-context`.
- Evidence packages are immutable in transmission — never modify them.
- Authority chains must be explicit and traceable; no implicit authority.
- The specification is the source of truth. Implementations conform to it.

## Branch / PR discipline (enforced by CI)
- Terminal-coder branches use the `hermes/` prefix (e.g. `hermes/repo-profile-64`).
- One issue = one branch = one PR.
- Target `main`. Never force-push a claimed branch.
- Cross-language changes must pass the Stage 3A/3B/3C gate (`reference/bindings/v0.2/gate.py`).
- Claim work in `claimed.json` before starting; mark `merged` after merge.

## Where to work
- `spec/` — normative schemas. Changes require review + version bump.
- `reference/bindings/v0.2/` — typed bindings (python/rust/typescript), canonicalization, runtime conformance.
- `test-vectors/` — compliance and runtime vectors.
- `validators/` — compliance checkers.
- `.github/workflows/` — CI.

## Build & verify (per language)
```bash
# Python
cd reference/bindings/v0.2/python && source .venv/bin/activate && pytest
# Rust
cd reference/bindings/v0.2/rust && cargo test --release
# TypeScript
cd reference/bindings/v0.2/typescript && npm test
# Cross-language gate (3A/3B/3C)
cd reference/bindings/v0.2 && python3 gate.py
```

## Metadata contract (this profile)
This repository adopts the canonical AI-first profile (nsolland/Index#338):
- `repo-manifest.yaml` — authoritative machine-readable contract (single source of truth).
- `publiccode.yml` — publiccode standard metadata.
- `llms.txt` — AI-first entry point.
- `AGENTS.md` — this file.
- `claimed.json` — agent work registry.
These four files MUST stay mutually consistent. CI validates `repo-manifest.yaml`.

## Non-claims
- Not a runtime; not a competing receipt standard; not domain-specific policy.
- Vendor-neutral: external proof formats may be mapped but not privileged as governance authority.

## License
MIT.
