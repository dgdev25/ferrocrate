#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

fake_bin="$tmp_dir/bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/systemd-run" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
seen=()
while (($#)); do
  if [[ "$1" == "--" ]]; then
    shift
    break
  fi
  seen+=("$1")
  shift
done
printf '%s\n' "${seen[@]}" >"${FERROCRATE_TEST_SYSTEMD_ARGS:?}"
exec "$@"
EOF
chmod 0755 "$fake_bin/systemd-run"

args="$tmp_dir/args"
PATH="$fake_bin:$PATH" FERROCRATE_TEST_SYSTEMD_ARGS="$args" \
  bash "$repo_root/scripts/run-rootless-delegated.sh" /bin/sh -c 'exit 0'
grep -Fxq -- '--user' "$args"
grep -Fxq -- '--scope' "$args"
grep -Fxq -- '-p' "$args"
grep -Fxq -- 'Delegate=yes' "$args"
if grep -Eq -- '^--(wait|pipe)$' "$args"; then
  echo "scope wrapper unexpectedly passed incompatible wait/pipe option" >&2
  exit 1
fi

echo "rootless delegated-scope wrapper regression passed"
