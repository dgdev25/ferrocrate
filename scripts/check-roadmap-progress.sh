#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
roadmap="${1:-$repo_root/docs/ROADMAP.md}"
if [[ ! -f "$roadmap" ]]; then
  echo "roadmap not found: $roadmap" >&2
  exit 2
fi

count_matches() {
  local pattern="$1" path="$2"
  if command -v rg >/dev/null 2>&1; then
    rg -c "$pattern" "$path" || true
  else
    # Keep the release gate usable under sudo/systemd PATHs that omit the
    # optional ripgrep binary.  awk is part of the base toolchain and preserves
    # the same anchored checklist semantics.
    case "$pattern" in
      '^\s*- \[x\] ') awk '/^[[:space:]]*- \[x\] / { count++ } END { print count + 0 }' "$path" ;;
      '^\s*- \[ \] ') awk '/^[[:space:]]*- \[ \] / { count++ } END { print count + 0 }' "$path" ;;
      '^### [0-9]+\.') awk '/^### [0-9]+\./ { count++ } END { print count + 0 }' "$path" ;;
      *) echo "unsupported roadmap count pattern: $pattern" >&2; return 2 ;;
    esac
  fi
}

completed=$(count_matches '^\s*- \[x\] ' "$roadmap")
open=$(count_matches '^\s*- \[ \] ' "$roadmap")
completed="${completed:-0}"
open="${open:-0}"
total=$((completed + open))
if (( total == 0 )); then
  echo "roadmap progress failed: no checklist rows found" >&2
  exit 1
fi

printf 'roadmap progress: %d complete / %d open / %d total (%d%% complete)\n' \
  "$completed" "$open" "$total" "$((completed * 100 / total))"

expected_total="${FERROCRATE_ROADMAP_EXPECTED_TOTAL:-27}"
if [[ "$expected_total" =~ ^[0-9]+$ ]] && (( total != expected_total )); then
  echo "roadmap progress failed: expected $expected_total checklist rows, found $total" >&2
  exit 1
fi

if [[ "${FERROCRATE_SKIP_BENCHMARK_REGISTER:-0}" != "1" ]]; then
  bash "$repo_root/scripts/perf/check-benchmark-register.sh" \
    "$repo_root/docs/evidence/performance/benchmark-register.md"
fi
