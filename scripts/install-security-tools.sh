#!/usr/bin/env bash
# Install only the reviewed Linux x86_64 CI toolchain; never run an unverified archive.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  printf 'Pinned security tools currently support Linux x86_64 only.\n' >&2
  exit 1
fi
mkdir -p .tools
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT

curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 --retry 2 \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
  --output "$archive"
printf '%s  %s\n' 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb "$archive" | sha256sum --check --status
tar -xOf "$archive" gitleaks > .tools/gitleaks
chmod 0755 .tools/gitleaks

curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 --retry 2 \
  https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz \
  --output "$archive"
printf '%s  %s\n' 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 "$archive" | sha256sum --check --status
tar -xOf "$archive" actionlint > .tools/actionlint
chmod 0755 .tools/actionlint
printf 'Installed checksum-verified Gitleaks 8.30.1 and actionlint 1.7.12.\n'
