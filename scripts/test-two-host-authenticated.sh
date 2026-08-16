#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"

if [[ "$(id -u)" != "0" ]]; then
  echo "authenticated two-host qualification requires root" >&2
  exit 1
fi

cargo test -p ferro-mgr --test real_two_host_qualification \
  --offline -- --ignored --nocapture
