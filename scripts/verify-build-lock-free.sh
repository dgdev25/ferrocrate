#!/bin/bash
# FU-001 regression guard: ferro-net/build.rs must not need the rustup lock.
#
# The build once ran `rustup component list` on every invocation, which took the
# rustup lock and failed whenever another cargo or rustup process held it. This
# holds the lock and rebuilds; the build must finish while it is held.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
LOCK="${RUSTUP_HOME:-$HOME/.rustup}/.lock"
touch "$LOCK" || { echo "cannot create $LOCK" >&2; exit 2; }

cargo build -p ferro-net >/dev/null 2>&1 || { echo "baseline build failed" >&2; exit 1; }

flock "$LOCK" -c "sleep 60" &
holder=$!
sleep 2
touch ferro-net/build.rs
timeout 120 cargo build -p ferro-net
code=$?
kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null

if [ $code -eq 0 ]; then
  echo "PASS: ferro-net rebuilt while the rustup lock was held"
else
  echo "FAIL: ferro-net rebuild exited $code with the rustup lock held" >&2
fi
exit $code
