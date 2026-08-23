#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
unit="$repo_root/packaging/systemd/ferrocrate.service"
installer="$repo_root/scripts/install-managed-overlay-services.sh"
operations_doc="$repo_root/docs/operations/managed-overlays.md"

test -f "$unit"
grep -qx '\[Unit\]' "$unit"
grep -qx 'After=network.target' "$unit"
grep -qx '\[Service\]' "$unit"
grep -qx 'Type=simple' "$unit"
grep -qx 'ExecStart=/usr/local/bin/ferrocrate daemon --docker-compat' "$unit"
grep -qx 'Restart=on-failure' "$unit"
grep -qx '\[Install\]' "$unit"
grep -qx 'WantedBy=multi-user.target' "$unit"

# The privileged-system packaging installer is the deployment path for units
# under packaging/systemd; ensure it installs the container daemon too.
grep -Eq 'for unit in .*ferrocrate' "$installer"
# The operator instructions must name every binary the installer now requires.
grep -Fq 'On each prepared Linux host, install the four built binaries into `/usr/local/bin`, then run `sudo scripts/install-managed-overlay-services.sh`.' "$operations_doc"

if command -v systemd-analyze >/dev/null 2>&1; then
  stage_root="$(mktemp -d)"
  trap 'rm -rf -- "$stage_root"' EXIT
  install -d -m 0755 "$stage_root/etc/systemd/system" "$stage_root/usr/local/bin"
  install -m 0644 "$unit" "$stage_root/etc/systemd/system/ferrocrate.service"
  install -m 0755 /bin/true "$stage_root/usr/local/bin/ferrocrate"
  # `verify --root` still loads its default sysinit dependency; provide the
  # minimal target so this validates the staged package rather than the host.
  printf '[Unit]\nDescription=Stub sysinit target\n' >"$stage_root/etc/systemd/system/sysinit.target"
  systemd-analyze verify --root="$stage_root" /etc/systemd/system/ferrocrate.service
fi

echo "container daemon systemd unit regression checks passed"
