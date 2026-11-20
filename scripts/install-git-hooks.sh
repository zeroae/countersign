#!/usr/bin/env bash
# Points this clone at the tracked hooks in .githooks/. core.hooksPath lives in
# the clone's shared config, so one run covers every worktree, and a relative
# path makes each worktree run its own tracked copy of the hooks.
# A Claude session runs this at start (.claude/settings.json). It prints nothing
# when the hooks are already installed, and never replaces another hooks path.
set -euo pipefail

cd "$(dirname "$0")/.."
git rev-parse --git-dir >/dev/null 2>&1 || exit 0

current=$(git config --get core.hooksPath || true)
case "$current" in
  .githooks) ;;
  "")
    git config core.hooksPath .githooks
    echo "Installed the pre-commit hook: core.hooksPath is now .githooks."
    ;;
  *)
    echo "core.hooksPath is already '$current', so the pre-commit hook in .githooks/ is not installed. To use it: git config core.hooksPath .githooks" >&2
    ;;
esac
