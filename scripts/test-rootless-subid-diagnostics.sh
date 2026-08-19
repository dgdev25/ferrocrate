#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

printf '%s:200000:65536\n' "$(id -u)" >"$tmp_dir/subuid"
printf '%s:200000:65536\n' "$(id -g)" >"$tmp_dir/subgid"
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$tmp_dir/runtime}"
mkdir -p "$XDG_RUNTIME_DIR"

output="$tmp_dir/output"
FERROCRATE_ROOTLESS_SUBUID_FILE="$tmp_dir/subuid" \
FERROCRATE_ROOTLESS_SUBGID_FILE="$tmp_dir/subgid" \
XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
FERROCRATE_ROOTLESS_STRICT=0 \
bash "$repo_root/scripts/verify-rootless.sh" >"$output" 2>&1

grep -q '^rootless.subuid=pass$' "$output"
grep -q '^rootless.subgid=pass$' "$output"
echo "rootless numeric subid diagnostic regression passed"

# Hermetic strict-mode negative control: make the operational probes pass with
# command stubs, then provide empty subordinate-ID files. Strict diagnostics
# must fail closed and report both missing mappings.
strict_bin="$tmp_dir/strict-bin"
mkdir -p "$strict_bin"
for helper in unshare bwrap newuidmap newgidmap slirp4netns; do
  printf '#!/bin/sh\nexit 0\n' >"$strict_bin/$helper"
  chmod 0755 "$strict_bin/$helper"
done
printf '#!/bin/sh\nexit 0\n' >"$strict_bin/bwrap-target"
chmod 0755 "$strict_bin/bwrap-target"
rm -f -- "$strict_bin/bwrap"
ln -s bwrap-target "$strict_bin/bwrap"
: >"$tmp_dir/empty-subuid"
: >"$tmp_dir/empty-subgid"
strict_output="$tmp_dir/strict-output"
set +e
PATH="$strict_bin:$PATH" \
FERROCRATE_ROOTLESS_SUBUID_FILE="$tmp_dir/empty-subuid" \
FERROCRATE_ROOTLESS_SUBGID_FILE="$tmp_dir/empty-subgid" \
XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
FERROCRATE_ROOTLESS_STRICT=1 \
bash "$repo_root/scripts/verify-rootless.sh" >"$strict_output" 2>&1
strict_rc=$?
set -e
[[ "$strict_rc" -eq 1 ]]
grep -q '^rootless.subuid=missing$' "$strict_output"
grep -q '^rootless.subgid=missing$' "$strict_output"
grep -q '^rootless.newuidmap=missing-or-untrusted$' "$strict_output"
grep -q '^rootless.slirp4netns=missing-or-untrusted$' "$strict_output"
grep -q '^rootless.bwrap=missing-or-untrusted$' "$strict_output"
echo "rootless strict missing-subid regression passed"

# The documented command-line strict switch must have the same fail-closed
# behavior as the environment switch; otherwise an invocation can silently
# downgrade to non-strict diagnostics.
set +e
PATH="$strict_bin:$PATH" \
FERROCRATE_ROOTLESS_SUBUID_FILE="$tmp_dir/empty-subuid" \
FERROCRATE_ROOTLESS_SUBGID_FILE="$tmp_dir/empty-subgid" \
XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
bash "$repo_root/scripts/verify-rootless.sh" --strict >"$strict_output" 2>&1
flag_rc=$?
set -e
[[ "$flag_rc" -eq 1 ]]
grep -q '^rootless.subuid=missing$' "$strict_output"
grep -q '^rootless.subgid=missing$' "$strict_output"
echo "rootless --strict flag regression passed"

printf '%s:not-a-number:0\n' "$(id -u)" >"$tmp_dir/malformed-subuid"
printf '%s:200000:not-a-range\n' "$(id -g)" >"$tmp_dir/malformed-subgid"
set +e
PATH="$strict_bin:$PATH" \
FERROCRATE_ROOTLESS_SUBUID_FILE="$tmp_dir/malformed-subuid" \
FERROCRATE_ROOTLESS_SUBGID_FILE="$tmp_dir/malformed-subgid" \
XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
FERROCRATE_ROOTLESS_STRICT=1 \
bash "$repo_root/scripts/verify-rootless.sh" >"$strict_output" 2>&1
malformed_rc=$?
set -e
[[ "$malformed_rc" -eq 1 ]]
grep -q '^rootless.subuid=missing$' "$strict_output"
grep -q '^rootless.subgid=missing$' "$strict_output"
echo "rootless strict malformed-subid regression passed"
