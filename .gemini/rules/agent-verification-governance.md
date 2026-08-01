# VALO Agent Verification Governance

Policy: `VALO-AVG-1`
Version: `1.0.0`
Normative body SHA-256: `f73ae98032007203584283248beca22d154f8a9e358ed48ccf72e90d27480e6d`
Canonical owner: `nsolland/Index`
Canonical path: `governance/agent-verification-governance.md`

This rule is mandatory for every mapping, implementation, review, delivery receipt, and merge-readiness statement in this repository.

## Required invariants

- No agent may independently attest its own delivery.
- Same-session or same-environment subagents are `INTERNAL_REVIEW`, never independent verification.
- GitHub and remote Git are the technical source of truth for branch identity, SHA, diff, PR state, merge state, and hosted checks.
- Missing external verification is `UNVERIFIED`.
- Local dependency or workstation failures are `LOCAL_ENVIRONMENT`, never `REPO_RED` or `PORTFOLIO_BLOCKER`.
- Historical test evidence is `HISTORICAL`, never current green.
- Tests are `CURRENT_TESTED` only when run against the exact reported commit.
- A merged, closed, superseded, abandoned, or branchless claim is `STALE_CLAIM`.
- Use `ACTIVE_BLOCKER` only for a named active delivery that is currently and reproducibly prevented from progressing.
- Use `NO_ACTIVE_BLOCKERS` rather than filling empty fields with TODOs, mocks, debt, or opportunities.

## Raw remote receipt

Run and report the output unchanged:

```bash
git fetch --prune origin
REMOTE_HEAD=$(git ls-remote origin "refs/heads/$BRANCH" | cut -f1)
BASE_HEAD=$(git ls-remote origin refs/heads/main | cut -f1)
CHANGED_FILES=$(git diff --name-only "$BASE_HEAD...$REMOTE_HEAD")
BEHIND=$(git rev-list --count "$REMOTE_HEAD..$BASE_HEAD")
AHEAD=$(git rev-list --count "$BASE_HEAD..$REMOTE_HEAD")
printf 'REMOTE_HEAD=%s\n' "$REMOTE_HEAD"
printf 'BASE_HEAD=%s\n' "$BASE_HEAD"
printf 'BEHIND=%s\n' "$BEHIND"
printf 'AHEAD=%s\n' "$AHEAD"
printf '%s\n' "$CHANGED_FILES"
```

Do not manually reproduce SHA values from memory or earlier output.

## Canonical architecture

- Speider collects.
- Baro observes.
- VAIG evaluates.
- REHT clears.
- RACS enforces the deterministic decision contract.
- The execution boundary performs the action.
- Runtime cannot authorize.

Evidence flow, authority flow, and deployment dependencies must be mapped separately.
