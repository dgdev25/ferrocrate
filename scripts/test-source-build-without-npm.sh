#!/usr/bin/env bash
set -euo pipefail

# This deliberately uses a separate checkout: a source archive or host-matrix
# worker must build ferro-cli even when the generated frontend is absent and
# Node/npm is unavailable.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checkout="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-source-build.XXXXXX")"
tool_path="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-no-node-path.XXXXXX")"

cleanup() {
    git -C "$repo_root" worktree remove --force "$checkout" 2>/dev/null || true
    rmdir "$tool_path" 2>/dev/null || true
}
trap cleanup EXIT
rmdir "$checkout"
git -C "$repo_root" worktree add --detach "$checkout" HEAD >/dev/null
rm -rf "$checkout/apps/ferro-desktop-ui/dist"

# Cargo/rustc need a linker, but this PATH intentionally has no node or npm.
for tool in cc c++ ar as ld nm objcopy ranlib strip; do
    ln -s "$(command -v "$tool")" "$tool_path/$tool"
done

PATH="$HOME/.cargo/bin:$tool_path" \
    CARGO_BUILD_JOBS=6 \
    cargo build -p ferro-cli --manifest-path "$checkout/Cargo.toml"

set +e
output="$(PATH="$HOME/.cargo/bin:$tool_path" "$checkout/target/debug/ferro-cli" dashboard 2>&1)"
status=$?
set -e
if [[ $status -ne 2 ]]; then
    echo "expected placeholder dashboard to exit 2, got $status" >&2
    echo "$output" >&2
    exit 1
fi
if [[ "$output" != *"dashboard UI was not bundled in this build"* ]]; then
    echo "placeholder dashboard did not explain how to rebuild" >&2
    echo "$output" >&2
    exit 1
fi
