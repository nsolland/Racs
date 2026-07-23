# HANDOVER — RACS Stage 3C

## Active working stream

| Field | Value |
|---|---|
| Repo | nsolland/Racs |
| Base SHA | 7d6a7d981a6c91804b51cab6f844f7ee1b504eae (origin/main, verified) |
| Branch | hermes/bindings-runtime-3c |
| Draft PR | https://github.com/nsolland/Racs/pull/68 |
| Owner/agent | Hermes |
| Stage | 3C — runtime schema conformance and cross-artifact verification |
| Scope | runtime schema conformance + cross-artifact verification for RACS v0.2 contract schemas |
| Claimed paths | reference/bindings/v0.2/python/src/racs_v02/validation.py, verification.py, tests/test_validation.py, test-vectors/0.2/runtime-validation/ |
| Must not touch | valo-platform PRs (#879/#870/#874 etc.); 3A/3B merged schemas unless contract defect |
| Dependencies | 3B (#67) merged at base |
| Status | in_progress |
| Last verified head | ca27033 |
| Tests | reference/bindings/v0.2/python/tests/test_validation.py |
| CI run | pending on draft PR |
| Merge status | unmerged (draft) |

## Rule compliance (new working-anchor rule)
- [x] Canonical main-SHA documented (7d6a7d9)
- [x] Own branch created from that SHA (hermes/bindings-runtime-3c)
- [x] Draft PR created immediately (PR #68, before further code)
- [x] Work claimed in claimed.json
- [x] Boundary + dependencies recorded in HANDOVER.md

## Other streams (irrelevant to this branch)
- nsolland/valo-platform open PRs (#879 Vectorly/BlueBox, #870 verification-factory, #874 Leiden, #868 SkillOpt, #862/#860/#856/#853/#823/#814 drafts) are separate agents' streams. No file overlap with RACS v0.2 bindings. Do not touch.

## Note on repo location
Working copy is /home/njaal/all-repos/Racs (NOT ~/Racs). ~/Racs had a stray empty branch (hermes/runtime-conformance-3c) which was deleted locally and remotely on 2026-07-23.
