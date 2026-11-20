#!/usr/bin/env bash
# Points this clone at the tracked hooks in .githooks/. core.hooksPath lives in
# the clone's shared config, so one run covers every worktree, and a relative
# path makes each worktree run its own tracked copy of the hooks.
# A Claude session runs this at start (.claude/settings.json). It prints nothing
# when the hooks are already installed. It never replaces another hooks path,
# and never hides hooks already in the clone's hooks folder, which core.hooksPath
# would stop running.
set -euo pipefail

cd "$(dirname "$0")/.."
git rev-parse --git-dir >/dev/null 2>&1 || exit 0

current=$(git config --get core.hooksPath || true)
case "$current" in
  .githooks) ;;
  "")
    hooks=$(git rev-parse --path-format=absolute --git-common-dir)/hooks
    existing=$(find "$hooks" -maxdepth 1 ! -type d ! -name '*.sample' -exec basename {} \; 2>/dev/null | sort | tr '\n' ' ')
    if [ -n "$existing" ]; then
      echo "$hooks holds hooks (${existing% }) that core.hooksPath would stop running, so the pre-commit hook in .githooks/ is not installed. Move them into .githooks/ or elsewhere, then run scripts/install-git-hooks.sh." >&2
      exit 0
    fi
    git config core.hooksPath .githooks
    echo "Installed the pre-commit hook: core.hooksPath is now .githooks."
    ;;
  *)
    echo "core.hooksPath is already '$current', so the pre-commit hook in .githooks/ is not installed. To use it: git config core.hooksPath .githooks" >&2
    ;;
esac
