#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
script="$repo_root/scripts/fleet-demo.sh"

bash -n "$script"
help="$($script --help)"
grep -Fq 'fleet-demo.sh [up|down|--status|verify]' <<<"$help"
grep -Fq 'FLEET_DEMO_STATE_DIR' <<<"$help"
