#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"

for package in ferro-core ferro-compose; do
  graph="$(cargo tree --offline -p "$package" --edges normal 2>&1)"
  if grep -Eiq '(^|[[:space:]])(sled|fxhash|instant)( v|$)' <<<"$graph"; then
    printf 'default dependency graph contains a legacy advisory crate for %s:\n%s\n' \
      "$package" "$graph" >&2
    exit 1
  fi
done

printf '%s\n' 'default dependency graph: no sled/fxhash/instant'
