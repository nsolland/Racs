#!/usr/bin/env bash
# pre-push hook: block accidental direct pushes to `main` from a feature branch.
#
# Install (optional, per-clone):
#   ln -sf ../../scripts/pre-push-protect-main.sh .git/hooks/pre-push
#
# Direct pushes to `main` are discouraged (AGENTS.md: one issue = one branch =
# one PR). The hook allows the common fast-forward workflow by skipping itself
# when the local branch is already `main`.
set -euo pipefail

current_branch="$(git symbolic-ref --short HEAD 2>/dev/null || echo detached)"
target_ref="$(git rev-parse --symbolic-full-name '@{u}' 2>/dev/null || true)"

if [[ "$current_branch" == "main" ]]; then
  exit 0
fi

while read -r _local_ref _local_sha _remote_ref _remote_sha; do
  if [[ "$_remote_ref" == "refs/heads/main" ]]; then
    echo "ERROR: refusing to push branch '$current_branch' directly to 'main'." >&2
    echo "  Create a branch and open a PR instead (one issue = one branch = one PR)." >&2
    echo "  Override with: git push --no-verify" >&2
    exit 1
  fi
done

exit 0
