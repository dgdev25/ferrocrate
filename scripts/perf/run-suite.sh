#!/usr/bin/env bash
# Run non-privileged performance fixtures with hard per-fixture bounds.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${FERROCRATE_PERF_SUITE_TIMEOUT_SECONDS:-45}"
OUTPUT=""
STRICT=0
LIST_ONLY=0
DRY_RUN=0

declare -a SELECTED=()
declare -A SCRIPT=(
  [startup]="scripts/perf/startup.sh"
  [pull]="scripts/perf/pull.sh"
  [build]="scripts/perf/build.sh"
  [binary-size]="scripts/perf/binary-size.sh"
  [idle-daemon]="scripts/perf/idle-daemon.sh"
  [per-container]="scripts/perf/per-container.sh"
  [docker-api]="scripts/perf/docker-api-compat.sh"
  [oci-image]="scripts/perf/oci-compat.sh"
  [oci-distribution]="scripts/perf/oci-distribution-compat.sh"
  [oci-runtime]="scripts/perf/oci-runtime-compat.sh"
  [ai-latency]="scripts/perf/ai-latency.sh"
)

usage() {
  cat <<'USAGE'
Usage: scripts/perf/run-suite.sh [options] [benchmark ...]

Runs selected local fixtures with a hard timeout and writes a Markdown report.
With no names, all non-privileged fixtures run.

Options:
  --list                 List benchmark names and exit
  --dry-run              Print selected commands without running them
  --timeout <seconds>    Per-fixture timeout (default: 45)
  --output <path>        Markdown report path (default: stdout)
  --strict               Exit non-zero when any fixture is skipped or fails
  -h, --help             Show this help

The runner requires an existing target/release/ferro-cli for fixtures that use
it. It never performs an implicit cargo build and never invokes sudo.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) LIST_ONLY=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --strict) STRICT=1; shift ;;
    --timeout) TIMEOUT_SECONDS="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) SELECTED+=("$1"); shift ;;
  esac
done

if ! [[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--timeout must be a positive integer" >&2
  exit 2
fi

if (( LIST_ONLY )); then
  printf '%s\n' "${!SCRIPT[@]}" | sort
  exit 0
fi

if ((${#SELECTED[@]} == 0)); then
  mapfile -t SELECTED < <(printf '%s\n' "${!SCRIPT[@]}" | sort)
fi
for name in "${SELECTED[@]}"; do
  if [[ -z "${SCRIPT[$name]+present}" ]]; then
    echo "unknown benchmark: $name" >&2
    exit 2
  fi
done

if [[ -n "$OUTPUT" ]]; then
  mkdir -p "$(dirname "$OUTPUT")"
  report_tmp="$(mktemp "${OUTPUT}.tmp.XXXXXX")"
  trap 'rm -f "${report_tmp:-}"' EXIT
else
  report_tmp="$(mktemp)"
  trap 'rm -f "${report_tmp:-}"' EXIT
fi

commit="unknown"
if git -C "$ROOT_DIR" rev-parse --short HEAD >/dev/null 2>&1; then
  commit="$(git -C "$ROOT_DIR" rev-parse --short HEAD)"
fi
{
  echo "# Ferrocrate local benchmark suite"
  echo
  echo "- Commit: \`$commit\`"
  echo "- Host: \`$(uname -srmo)\`"
  echo "- Fixture timeout: ${TIMEOUT_SECONDS}s"
  echo "- Privileged probes: not run"
  echo "- Implicit builds: not run"
  echo
  echo "| Benchmark | Status | Duration | Evidence |"
  echo "|---|---|---:|---|"
} >"$report_tmp"

failures=0
for name in "${SELECTED[@]}"; do
  script="${ROOT_DIR}/${SCRIPT[$name]}"
  started="$(date +%s%N)"
  if [[ ! -x "$script" ]]; then
    echo "| $name | skipped | — | fixture missing: \`${SCRIPT[$name]}\` |" >>"$report_tmp"
    failures=$((failures + 1))
    continue
  fi
  if [[ "$name" != "ai-latency" && ! -x "$ROOT_DIR/target/release/ferro-cli" ]]; then
    echo "| $name | skipped | — | target/release/ferro-cli is not built |" >>"$report_tmp"
    failures=$((failures + 1))
    continue
  fi
  if (( DRY_RUN )); then
    echo "| $name | planned | — | \`${SCRIPT[$name]}\` |" >>"$report_tmp"
    continue
  fi
  log_file="$(mktemp)"
  if FERROCRATE_PERF_ENFORCE=0 FERROCRATE_PERF_ALLOW_SKIP=1 \
      timeout --signal=TERM --kill-after=5s "$TIMEOUT_SECONDS" \
      bash "$script" >"$log_file" 2>&1; then
    status="passed"
  else
    status="skipped/failed"
    failures=$((failures + 1))
  fi
  finished="$(date +%s%N)"
  duration_ms=$(( (finished - started) / 1000000 ))
  evidence="$(grep -E '^perf\.[A-Za-z0-9_.-]+=' "$log_file" || true)"
  evidence="$(printf '%s' "$evidence" | tr '\n' ';' | sed 's/|/\\|/g' | cut -c1-240)"
  [[ -n "$evidence" ]] || evidence="$(tail -n 1 "$log_file" | tr '|' '/')"
  echo "| $name | $status | ${duration_ms}ms | $evidence |" >>"$report_tmp"
  rm -f "$log_file"
done

if [[ -n "$OUTPUT" ]]; then
  mv "$report_tmp" "$OUTPUT"
  trap - EXIT
  cat "$OUTPUT"
else
  cat "$report_tmp"
fi
if (( STRICT && failures > 0 )); then
  exit 1
fi
