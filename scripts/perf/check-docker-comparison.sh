#!/usr/bin/env bash
set -euo pipefail

# Enforce the minimum shape and latency guard for the ten-feature Docker
# comparison. This never rewrites a benchmark and never treats an unsupported
# operation as a successful sample.
report="${1:-}"
max_regression="${FERROCRATE_DOCKER_MAX_REGRESSION_PCT:-100}"
run_exit_max="${FERROCRATE_DOCKER_RUN_EXIT_MAX_REGRESSION_PCT:-$max_regression}"
pull_max="${FERROCRATE_DOCKER_PULL_MAX_REGRESSION_PCT:-$max_regression}"
api_max="${FERROCRATE_DOCKER_API_MAX_REGRESSION_PCT:-$max_regression}"
if [[ -z "$report" || ! -f "$report" ]]; then
  echo "usage: $0 REPORT.md" >&2
  exit 2
fi
for threshold_name in max_regression run_exit_max pull_max api_max; do
  threshold_value="${!threshold_name}"
  if [[ ! "$threshold_value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Docker comparison thresholds must be non-negative numbers" >&2
    exit 2
  fi
done

expected='container run/exit|Dockerfile build|image list|network create/remove|volume create/remove|network list|API ping|API version|API info|image pull (warm)'
result="$(awk -F'|' \
  -v expected="$expected" \
  -v default_ceiling="$max_regression" \
  -v run_exit_ceiling="$run_exit_max" \
  -v pull_ceiling="$pull_max" \
  -v api_ceiling="$api_max" '
  function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
  function fail(msg) { print "benchmark gate failed: " msg > "/dev/stderr"; bad=1 }
  function threshold(name) {
    if (name == "container run/exit") return run_exit_ceiling
    if (name == "image pull (warm)") return pull_ceiling
    if (name == "API ping" || name == "API version" || name == "API info") return api_ceiling
    return default_ceiling
  }
  index($0, "|") == 1 {
    name=trim($2); docker=trim($3); ferro=trim($4)
    if (name == "Feature" || name ~ /^-+$/ || docker ~ /^-+$/) next
    if (name == "") next
    seen[name]++
    rows++
    if (docker == "SKIP" || ferro == "SKIP") fail(name " contains SKIP")
    if (docker !~ /^[0-9]+([.][0-9]+)?$/ || ferro !~ /^[0-9]+([.][0-9]+)?$/) {
      fail(name " has a non-numeric median")
      next
    }
    limit=threshold(name)
    if (docker > 0 && ((ferro - docker) * 100 / docker) > limit)
      fail(name " exceeds +" limit "% regression (Docker=" docker " Ferrocrate=" ferro ")")
  }
  END {
    n=split(expected, names, "|")
    for (i=1; i<=n; i++) if (!(names[i] in seen)) fail("missing feature: " names[i])
    for (name in seen) if (seen[name] != 1) fail("duplicate feature: " name)
    if (rows != n) fail("expected " n " feature rows, found " rows)
    if (bad) exit 1
    print "benchmark gate passed: " n " features, no SKIP rows, per-feature regression thresholds enforced"
  }
' "$report")"
printf '%s\n' "$result"
