#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
existing=$(git config --get core.hooksPath || true)
if [[ -n "$existing" && "$existing" != ".githooks" ]]; then
  printf 'Existing hooksPath is %s; reconcile it before installing AMDN hooks.\n' "$existing" >&2
  exit 1
fi
git config --local core.hooksPath .githooks
chmod +x .githooks/pre-commit .githooks/pre-push
printf 'Installed versioned AMDN Git hooks.\n'
