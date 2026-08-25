#!/usr/bin/env bash
set -euo pipefail

# Structural checks for the one-command bounded local smoke gate. Kept offline
# and cheap; the live gate itself needs a working Ferrocrate build and
# registry access and is run per change, not in this test.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gate="$repo_root/scripts/local-smoke-gate.sh"
e2e="$repo_root/scripts/e2e-cli.sh"

bash -n "$gate"
bash -n "$e2e"

# The gate must bound every invocation.
grep -Fq 'timeout --foreground --kill-after=10s 60s' "$gate"
grep -Fq 'timeout --foreground --kill-after=15s "${timeout_seconds}s"' "$gate"
grep -Fq 'FERROCRATE_SMOKE_GATE_TIMEOUT_SECONDS:-600' "$gate"

# The gate must run the doctor and the e2e corpus.
grep -Fq 'bash scripts/verify-rootless.sh' "$gate"
grep -Fq 'bash scripts/e2e-cli.sh' "$gate"

# The gate must fail on leftover processes.
grep -Fq 'pgrep -x ferro-cli' "$gate"

# The e2e corpus must cover binary, volumes, and cleanup.
grep -Fq '"${BIN}" --version' "$e2e"
grep -Fq 'volume create "${VOLUME_NAME}"' "$e2e"
grep -Fq 'volume rm "${VOLUME_NAME}"' "$e2e"
grep -Fq 'containers: no entries' "$e2e"
grep -Fq 'FERROCRATE_BIN:-' "$e2e"

# Usage and argument validation.
bash "$gate" --help | grep -Fq 'Usage: local-smoke-gate.sh'
if bash "$gate" --timeout notanumber 2>/dev/null; then
  echo "expected --timeout validation to reject a non-integer" >&2
  exit 1
fi

tmp="$(mktemp -d /tmp/ferrocrate-desktop-smoke.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
printf '#!/bin/sh\nexit 0\n' >"$tmp/ferro-desktop"
printf '#!/bin/sh\nexit 0\n' >"$tmp/ferrocrate"
chmod 0755 "$tmp/ferro-desktop" "$tmp/ferrocrate"
FERROCRATE_SMOKE_PLATFORM=desktop \
  FERROCRATE_DESKTOP_BIN="$tmp/ferro-desktop" \
  FERROCRATE_BIN="$tmp/ferrocrate" \
  bash "$gate" | grep -Fq 'local desktop package smoke gate passed'

printf '%s\n' 'local-smoke-gate=pass'
