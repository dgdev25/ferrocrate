#!/usr/bin/env bash
set -euo pipefail

# Install a per-user FerroCrate Docker-compatible daemon. This script never
# writes outside the invoking user's home directory and never requires sudo.
# It intentionally reports missing host prerequisites instead of silently
# installing privileged helpers.

usage() {
  cat <<'EOF'
Usage: rootless-install.sh [--binary PATH] [--socket PATH] [--enable] [--dry-run]

Installs ~/.local/bin/ferrocrate and a systemd user unit. --enable starts the
unit immediately when systemd --user is available. Use --dry-run to inspect
the plan without writing files.
EOF
}

binary=""
socket="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/ferrocrate.sock"
enable=0
dry_run=0
while (($#)); do
  case "$1" in
    --binary) binary="${2:?missing path after --binary}"; shift 2 ;;
    --socket) socket="${2:?missing path after --socket}"; shift 2 ;;
    --enable) enable=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$binary" ]]; then
  binary="$(command -v ferrocrate || true)"
fi
if [[ -z "$binary" ]]; then
  candidate="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/release/ferrocrate"
  [[ -x "$candidate" ]] && binary="$candidate"
fi
if [[ -z "$binary" || ! -x "$binary" ]]; then
  echo "rootless-install: executable ferrocrate not found; pass --binary PATH" >&2
  exit 1
fi
if [[ "$socket" != /* ]]; then
  echo "rootless-install: socket must be an absolute path" >&2
  exit 1
fi

uid="$(id -u)"
user="$(id -un)"
echo "rootless.install.user=$user"
echo "rootless.install.uid=$uid"
echo "rootless.install.binary=$binary"
echo "rootless.install.socket=$socket"

for helper in newuidmap newgidmap slirp4netns; do
  if command -v "$helper" >/dev/null 2>&1; then
    echo "rootless.install.$helper=pass"
  else
    echo "rootless.install.$helper=missing"
  fi
done

unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit_path="$unit_dir/ferrocrate.service"
unit_content="[Unit]
Description=FerroCrate rootless Docker-compatible daemon
After=default.target

[Service]
ExecStart=$binary daemon --socket $socket --docker-compat
Restart=on-failure
RestartSec=2
Environment=FERROCRATE_RUNTIME_DIR=%h/.local/share/ferrocrate

[Install]
WantedBy=default.target
"

if ((dry_run)); then
  echo "rootless.install.dry_run=pass"
  printf '%s' "$unit_content"
  exit 0
fi

install -D -m 0755 "$binary" "$HOME/.local/bin/ferrocrate"
install -D -m 0644 <(printf '%s' "$unit_content") "$unit_path"
echo "rootless.install.binary_path=$HOME/.local/bin/ferrocrate"
echo "rootless.install.unit_path=$unit_path"

if ((enable)); then
  if ! command -v systemctl >/dev/null 2>&1 || ! systemctl --user daemon-reload; then
    echo "rootless-install: --enable requested but systemd --user is unavailable" >&2
    exit 1
  fi
  systemctl --user enable --now ferrocrate.service
  echo "rootless.install.service=enabled"
else
  echo "rootless-install: run 'systemctl --user enable --now ferrocrate.service' to start"
fi
