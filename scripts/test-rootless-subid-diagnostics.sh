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
grep -q '^rootless.cgroup_delegation=' "$output"
grep -Eq '^rootless.peer_pidfd=(pass|missing)$' "$output"
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
grep -q '^rootless.cgroup_delegation=' "$strict_output"
grep -Eq '^rootless.peer_pidfd=(pass|missing)$' "$strict_output"
# Helper trust is deliberately not asserted here: the release gate may run as
# root, in which case the hermetic stubs are root-owned and pass the ownership
# check. The invariant under test is the strict failure caused by missing
# subordinate-ID mappings, independent of helper ownership.
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
grep -q '^rootless.cgroup_delegation=' "$strict_output"
grep -Eq '^rootless.peer_pidfd=(pass|missing)$' "$strict_output"
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

# A denied namespace operation must retain a bounded, actionable reason rather
# than collapsing to an unexplained boolean prerequisite failure.
reason_bin="$tmp_dir/reason-bin"
mkdir -p "$reason_bin"
cat >"$reason_bin/unshare" <<'EOF'
#!/bin/sh
echo 'unshare: unshare failed: Operation not permitted' >&2
exit 1
EOF
cat >"$reason_bin/bwrap" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$reason_bin/unshare" "$reason_bin/bwrap"
reason_output="$tmp_dir/reason-output"
PATH="$reason_bin:$PATH" \
FERROCRATE_ROOTLESS_SUBUID_FILE="$tmp_dir/subuid" \
FERROCRATE_ROOTLESS_SUBGID_FILE="$tmp_dir/subgid" \
XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
bash "$repo_root/scripts/verify-rootless.sh" >"$reason_output" 2>&1
grep -q '^rootless.userns_mount=missing$' "$reason_output"
grep -q '^rootless.userns_mount_reason=unshare: unshare failed: Operation not permitted$' "$reason_output"
echo "rootless namespace failure reason regression passed"

# The workstation doctor must report kernel, AppArmor, and socket state
# before any mutation, independent of pass/fail prerequisites.
grep -Eq '^rootless.kernel=(pass|unknown) version=' "$output"
grep -Eq '^rootless.apparmor=(enabled|disabled-or-unavailable)$' "$output"
grep -Eq '^rootless.socket=(found path=|none$)' "$output"
echo "rootless kernel/apparmor/socket diagnostics regression passed"
