#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d /tmp/ferrocrate-docker-comparison-gate.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
report="$tmp/report.md"
printf '%s\n' \
  '| Feature | Docker median (ms) | Ferrocrate median (ms) | Difference (Ferrocrate-Docker) | Relative vs Docker | Notes |' \
  '|---|---:|---:|---:|---:|---|' \
  '| image pull (warm) | 100 | 200 | 100 | +100.0%% | test |' \
  '| container run/exit | 100 | 100 | 0 | +0.0%% | test |' \
  '| Dockerfile build | 100 | 100 | 0 | +0.0%% | test |' \
  '| image list | 100 | 100 | 0 | +0.0%% | test |' \
  '| network create/remove | 100 | 100 | 0 | +0.0%% | test |' \
  '| volume create/remove | 100 | 100 | 0 | +0.0%% | test |' \
  '| network list | 100 | 100 | 0 | +0.0%% | test |' \
  '| API ping | 100 | 100 | 0 | +0.0%% | test |' \
  '| API version | 100 | 100 | 0 | +0.0%% | test |' \
  '| API info | 100 | 100 | 0 | +0.0%% | test |' >"$report"

bash scripts/perf/check-docker-comparison.sh "$report" >/dev/null
if FERROCRATE_DOCKER_MAX_REGRESSION_PCT=50 bash scripts/perf/check-docker-comparison.sh "$report" >/dev/null 2>&1; then
  echo "expected regression rejection did not occur" >&2
  exit 1
fi
sed -i 's/| 100 | 200 |/| 100 | 100 |/' "$report"
bash scripts/perf/check-docker-comparison.sh "$report" >/dev/null
echo "docker comparison regression gate checks passed"
