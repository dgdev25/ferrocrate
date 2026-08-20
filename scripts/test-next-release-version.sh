#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
utility="$repo_root/scripts/next-release-version.sh"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

git -C "$tmp" init -q
git -C "$tmp" config user.email test@example.invalid
git -C "$tmp" config user.name test
touch "$tmp/file"
git -C "$tmp" add file
git -C "$tmp" commit -qm initial
git -C "$tmp" tag v1.2.3
git -C "$tmp" tag v1.10.0

test "$(cd "$tmp" && "$utility" --patch)" = v1.10.1
if ! (cd "$tmp" && "$utility" --patch 2>"$tmp/stderr") >/dev/null; then
  echo "patch version calculation unexpectedly failed" >&2
  exit 1
fi
if [[ -s "$tmp/stderr" ]]; then
  echo "next release version emitted warnings:" >&2
  cat "$tmp/stderr" >&2
  exit 1
fi
test "$(cd "$tmp" && "$utility" --minor)" = v1.11.0
test "$(cd "$tmp" && "$utility" --major)" = v2.0.0
test "$(cd "$tmp" && "$utility" --from v3.4.5 --patch)" = v3.4.6

if (cd "$tmp" && "$utility" --patch --minor) >/dev/null 2>&1; then
  echo "multiple bump selectors unexpectedly succeeded" >&2
  exit 1
fi
if (cd "$tmp" && "$utility" --from v1.2 --patch) >/dev/null 2>&1; then
  echo "invalid base version unexpectedly succeeded" >&2
  exit 1
fi

echo "next release version regression checks passed"
