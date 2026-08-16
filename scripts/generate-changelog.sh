#!/usr/bin/env bash
set -euo pipefail

usage() { printf 'Usage: %s [--from REF] [--to REF] [--output PATH]\n' "$0" >&2; }
from_ref=""
to_ref="HEAD"
output=""
while (($#)); do
  case "$1" in
    --from) [[ $# -ge 2 ]] || { usage; exit 2; }; from_ref="$2"; shift 2 ;;
    --to) [[ $# -ge 2 ]] || { usage; exit 2; }; to_ref="$2"; shift 2 ;;
    --output) [[ $# -ge 2 ]] || { usage; exit 2; }; output="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

git rev-parse --verify "$to_ref^{commit}" >/dev/null
if [[ -n "$from_ref" ]]; then
  git rev-parse --verify "$from_ref^{commit}" >/dev/null
  range="$from_ref..$to_ref"
else
  range="$to_ref"
fi

version="${FERROCRATE_RELEASE_VERSION:-Unreleased}"
timestamp="$(date -u +%Y-%m-%d)"
[[ -n "$output" ]] || output="CHANGELOG-${version}.md"
mkdir -p "$(dirname -- "$output")"
temporary="${output}.tmp"
{
  printf '# Ferrocrate %s\n\n' "$version"
  printf '_Generated %s from `%s`._\n\n' "$timestamp" "$range"
  for section in Features Fixes Security Documentation Maintenance; do
    case "$section" in
      Features) pattern='feat' ;;
      Fixes) pattern='fix|bug|perf' ;;
      Security) pattern='security|sec' ;;
      Documentation) pattern='docs|doc' ;;
      Maintenance) pattern='chore|refactor|test|build|ci|style' ;;
    esac
    entries="$(git log --no-merges --format='%h%x09%s' "$range" | awk -F '\t' -v pattern="$pattern" 'BEGIN { IGNORECASE=1 } $2 ~ "^(" pattern ")(\\([^)]*\\))?!?:" { print "- " $2 " (" $1 ")" }' || true)"
    if [[ -n "$entries" ]]; then
      printf '## %s\n\n%s\n\n' "$section" "$entries"
    fi
  done
  other="$(git log --no-merges --format='%h%x09%s' "$range" | awk -F '\t' 'BEGIN { IGNORECASE=1 } $2 !~ /^(feat|fix|bug|perf|security|sec|docs|doc|chore|refactor|test|build|ci|style)(\([^)]*\))?!?:/ { print "- " $2 " (" $1 ")" }' || true)"
  if [[ -n "$other" ]]; then
    printf '## Other\n\n%s\n\n' "$other"
  fi
} >"$temporary"
mv -- "$temporary" "$output"
printf 'changelog generated: %s\n' "$output"
