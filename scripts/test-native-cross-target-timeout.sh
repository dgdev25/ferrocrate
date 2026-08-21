#!/usr/bin/env bash
set -euo pipefail

# Regression for outer-timeout cleanup: a fake Cargo process creates a long-
# lived child, then the cross-target runner is terminated before its internal
# deadline. The child must not survive the runner.
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d /tmp/ferrocrate-cross-timeout-test.XXXXXX)"
trap 'find "$tmp" -depth -delete 2>/dev/null || true' EXIT
mkdir -p "$tmp/bin"

cat >"$tmp/bin/rustup" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"--installed"* ]]; then
  printf '%s\n' x86_64-pc-windows-gnu
  exit 0
fi
exit 0
EOF
cat >"$tmp/bin/cargo" <<EOF
#!/usr/bin/env bash
sleep 60 &
printf '%s\n' "\$!" >"$tmp/child.pid"
wait
EOF
chmod 0755 "$tmp/bin/rustup" "$tmp/bin/cargo"

set +e
PATH="$tmp/bin:$PATH" FERROCRATE_CROSS_TIMEOUT_SECONDS=60 \
  timeout --foreground --signal=TERM --kill-after=2s 1s \
  bash "$repo_root/scripts/test-native-cross-target.sh" x86_64-pc-windows-gnu
rc=$?
set -e
[[ "$rc" -eq 124 || "$rc" -eq 143 ]] || {
  echo "expected outer timeout, got exit=$rc" >&2
  exit 1
}

if [[ -s "$tmp/child.pid" ]]; then
  child_pid="$(<"$tmp/child.pid")"
  if kill -0 "$child_pid" 2>/dev/null; then
    echo "cross-target timeout leaked fake Cargo child $child_pid" >&2
    kill -KILL "$child_pid" 2>/dev/null || true
    exit 1
  fi
fi
echo "native cross-target outer-timeout cleanup regression passed"
