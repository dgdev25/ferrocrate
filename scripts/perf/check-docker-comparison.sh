#!/usr/bin/env bash
set -euo pipefail

# Enforce the minimum shape and latency guard for the ten-feature Docker
# comparison. This never rewrites a benchmark and never treats an unsupported
# operation as a successful sample.
report="${1:-}"
max_regression="${FERROCRATE_DOCKER_MAX_REGRESSION_PCT:-500}"
if [[ -z "$report" || ! -f "$report" ]]; then
  echo "usage: $0 REPORT.md" >&2
  exit 2
fi
if [[ ! "$max_regression" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "FERROCRATE_DOCKER_MAX_REGRESSION_PCT must be a non-negative number" >&2
  exit 2
fi

expected='container run/exit|Dockerfile build|image list|network create/remove|volume create/remove|network list|API ping|API version|API info|image pull (warm)'
result="$(awk -F'|' -v expected="$expected" -v ceiling="$max_regression" '
  function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
  function fail(msg) { print "benchmark gate failed: " msg > "/dev/stderr"; bad=1 }
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
    if (docker > 0 && ((ferro - docker) * 100 / docker) > ceiling)
      fail(name " exceeds +" ceiling "% regression (Docker=" docker " Ferrocrate=" ferro ")")
  }
  END {
    n=split(expected, names, "|")
    for (i=1; i<=n; i++) if (!(names[i] in seen)) fail("missing feature: " names[i])
    for (name in seen) if (seen[name] != 1) fail("duplicate feature: " name)
    if (rows != n) fail("expected " n " feature rows, found " rows)
    if (bad) exit 1
    print "benchmark gate passed: " n " features, no SKIP rows, regression ceiling +" ceiling "%"
  }
' "$report")"
printf '%s\n' "$result"
