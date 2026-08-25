#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
script="$repo_root/scripts/fleet-demo.sh"

bash -n "$script"
help="$($script --help)"
grep -Fq 'fleet-demo.sh [up|down|--status|verify]' <<<"$help"
grep -Fq 'FLEET_DEMO_STATE_DIR' <<<"$help"

# The demo must not inherit a host's pre-existing rootless runtime.  Apart
# from making the run non-reproducible, a stale file where a runtime directory
# belongs makes every fleet command fail before it reaches the container.
grep -Fq 'FERROCRATE_HOME=\$HOME/$remote_state/runtime' "$script"
grep -Fq 'FERROCRATE_RUNTIME_DIR=\$HOME/$remote_state/runtime' "$script"
grep -Fq 'FERROCRATE_HOME=\$HOME/$arm_state/runtime' "$script"
grep -Fq 'FERROCRATE_RUNTIME_DIR=\$HOME/$arm_state/runtime' "$script"

# A re-run must refresh the one-time Fleet UI credentials once their short
# TTL has elapsed instead of printing a URL that cannot be logged into.
grep -Fq 'Fleet UI login expired; restarting it' "$script"
grep -Fq 'wait_for_pid_exit' "$script"
grep -Fq 'setsid env' "$script"

# Re-runs keep the already staged matching guest binaries.  The guest has a
# deliberately small disk, so copying a byte-identical release again is both
# unnecessary and can make an otherwise healthy demo fail for lack of space.
grep -Fq 'ship_guest_binary()' "$script"
grep -Fq 'sha256sum' "$script"

# `fleet` invokes ferro-cli for commands, so the remote release build must
# explicitly emit the CLI alongside the aarch64 agent.
grep -Fq -- '-p ferro-cli --bin ferro-cli' "$script"
