#!/bin/bash
# The single gate every merge to main passes through. Replaces four separate
# checks that were remembered individually and therefore sometimes skipped.
#
# usage: scripts/merge-gate.sh [--quick]
#   --quick skips conformance (slow); use only for docs/bench-only changes.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
QUICK=0; [ "${1:-}" = "--quick" ] && QUICK=1
fail=0
note() { printf '%-42s %s\n' "$1" "$2"; }

# 1. Ticket statuses must never move backward.
if bash scripts/check-ticket-regressions.sh >/dev/null 2>&1; then
  note "ticket status regressions" "clean"
else
  note "ticket status regressions" "FAILED"; fail=1
fi

# 2. Result files must not implausibly shrink. An emptied BuildKit result was
#    nearly merged on 2026-08-27 after a corrupted run wiped 489 records to 0.
shrunk=0
# Compare against the pre-merge state. This gate runs AFTER `git merge`, so
# `--cached` saw nothing; compare HEAD to its first parent, plus anything
# staged but not yet committed.
BASE="HEAD^1"; git rev-parse -q --verify "$BASE" >/dev/null 2>&1 || BASE="HEAD"
for f in $( { git diff --name-only "$BASE" HEAD 2>/dev/null; git diff --cached --name-only 2>/dev/null; } | grep 'bench/results/.*\.jsonl$' | sort -u || true); do
  [ -f "$f" ] || continue
  new=$(wc -l < "$f" 2>/dev/null); new=${new:-0}
  old=$(git show "$BASE:$f" 2>/dev/null | wc -l); old=${old:-0}
  if [ "$old" -gt 50 ] && [ "$new" -lt $((old / 2)) ]; then
    note "result shrank: $(basename $f)" "$old -> $new records, REFUSED"; shrunk=1
  fi
done
[ "$shrunk" -eq 1 ] && fail=1
[ "$shrunk" -eq 0 ] && note "result file sizes" "no implausible shrinkage"

# 3. Workspace tests. Only the explicitly audited concurrent-load flakes are
#    non-blocking. A new single-test failure is still a regression until it is
#    isolated and understood; never let the failure count alone waive it.
run_workspace_tests() {
  # --no-fail-fast: a fail-fast run stops at the first failing binary, which
  # loses the rest of the suite and has repeatedly produced misleading
  # partial counts under load (2026-08-29/30). Every binary must report.
  timeout 2400 cargo test --workspace --no-fail-fast 2>&1
}
out=$(run_workspace_tests)
p=$(echo "$out" | grep -E "^test result: (ok|FAILED)" | awk '{p+=$4} END {print p+0}')
f=$(echo "$out" | grep -E "^test result: (ok|FAILED)" | awk '{f+=$6} END {print f+0}')
# A test binary aborted under concurrent host load reports as a partial run
# (hundreds of tests missing plus a handful of "failures" that pass alone).
# Seen three times on 2026-08-29 (504 tests missing each time); solo reruns
# were clean each time. Retry once; only a run that counted a full suite may
# decide pass/fail.
if [ $((p + f)) -lt 2000 ]; then
  note "workspace tests" "partial run ($((p+f)) of ~2305 counted, likely aborted under load) — retrying once"
  out=$(run_workspace_tests)
  p=$(echo "$out" | grep -E "^test result: (ok|FAILED)" | awk '{p+=$4} END {print p+0}')
  f=$(echo "$out" | grep -E "^test result: (ok|FAILED)" | awk '{f+=$6} END {print f+0}')
  if [ $((p + f)) -lt 2000 ]; then
    note "workspace tests" "ABORTED twice ($((p+f)) counted) — treat as infra failure, not a regression verdict"
    fail=1
    aborted=1
  fi
fi
if [ "${aborted:-0}" -eq 1 ]; then
  : # verdict block below must not relabel an infra abort as test failures
elif [ "$f" -eq 0 ]; then
  note "workspace tests" "$p passed, 0 failed"
elif [ "$f" -eq 1 ]; then
  name=$(echo "$out" | grep -E "^test .+ \.\.\. FAILED$" | head -1 | awk '{print $2}')
  case "$name" in
    docker_compat_auto_remove_preserves_wait_exit_result|runtime::tests::slirp_reaper_leaves_a_recorded_container_helper_alone|runtime::tests::ephemeral_sentinel_host_port_is_resolved_at_start|linux_cli::tests::buildkit_filesync_preserves_relative_symlink_records)
      note "workspace tests" "$p passed, 1 failed ($name) — audited load flake, not blocking"
      ;;
    *)
      note "workspace tests" "$p passed, 1 FAILED ($name) — not on audited flake allowlist"
      fail=1
      ;;
  esac
else
  names=$(echo "$out" | grep -E "^test .+ \.\.\. FAILED$" | awk '{print $2}' | head -4 | tr '\n' ' ')
  note "workspace tests" "$p passed, $f FAILED (${names:-names unavailable})"; fail=1
fi

# 4. Conformance, both modes.
if [ "$QUICK" -eq 0 ]; then
  for mode in buildkit classic; do
    if [ "$mode" = classic ]; then export DOCKER_BUILDKIT=0; else unset DOCKER_BUILDKIT; fi
    r=$(timeout 2400 bash scripts/docker-client-conformance.sh 2>&1 | tail -1)
    if echo "$r" | grep -qE "FAIL=0( |$)"; then note "conformance ($mode)" "$r"
    else note "conformance ($mode)" "$r  FAILED"; fail=1; fi
  done
  unset DOCKER_BUILDKIT
else
  note "conformance" "skipped (--quick)"
fi

echo
[ "$fail" -eq 0 ] && echo "MERGE GATE: PASS" || echo "MERGE GATE: FAIL"
exit "$fail"
