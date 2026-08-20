#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE' >&2
Usage: next-release-version.sh [--from vMAJOR.MINOR.PATCH] [--major|--minor|--patch]

Prints the next stable release tag. Without --from, the highest v-prefixed
semantic-version tag reachable in the current Git repository is used.
USAGE
}

from=""
bump=""
while (($#)); do
  case "$1" in
    --from)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      from="$2"
      shift 2
      ;;
    --major|--minor|--patch)
      [[ -z "$bump" ]] || { echo "choose exactly one bump selector" >&2; exit 2; }
      bump="${1#--}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -n "$bump" ]] || bump=patch
semver_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
awk_semver_re='^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$'

if [[ -z "$from" ]]; then
  from="$(git tag --list 'v*' | awk -v re="$awk_semver_re" '$0 ~ re' | sort -V | tail -n 1)"
fi
if [[ -z "$from" ]]; then
  echo "no stable v-prefixed semantic-version tag found; pass --from vMAJOR.MINOR.PATCH" >&2
  exit 1
fi
if [[ ! "$from" =~ $semver_re ]]; then
  echo "invalid base version: $from (expected vMAJOR.MINOR.PATCH)" >&2
  exit 1
fi

major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
patch="${BASH_REMATCH[3]}"
case "$bump" in
  major) major=$((major + 1)); minor=0; patch=0 ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  patch) patch=$((patch + 1)) ;;
  *) echo "unsupported bump selector: $bump" >&2; exit 2 ;;
esac
printf 'v%s.%s.%s\n' "$major" "$minor" "$patch"
