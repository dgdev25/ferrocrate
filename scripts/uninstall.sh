#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: uninstall.sh [--dry-run]

Removes the per-user Ferrocrate binary and systemd user unit. Runtime state is
preserved by default so an uninstall is recoverable; remove state separately
only after taking an operator-approved backup.
EOF
}

dry_run=0
while (($#)); do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

install_dir="${FERROCRATE_INSTALL_DIR:-${HOME}/.local/bin}"
config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
target="$install_dir/ferrocrate"
unit_path="$config_home/systemd/user/ferrocrate.service"

case "$install_dir" in
  "$HOME"/*) ;;
  *) echo "refusing to remove outside the user install directory: $install_dir" >&2; exit 1 ;;
esac
case "$config_home" in
  "$HOME"/*) ;;
  *) echo "refusing to remove outside the user config directory: $config_home" >&2; exit 1 ;;
esac

echo "ferrocrate.uninstall.binary=$target"
echo "ferrocrate.uninstall.unit=$unit_path"
echo "ferrocrate.uninstall.state=preserved"
if ((dry_run)); then
  echo "ferrocrate.uninstall.dry_run=pass"
  exit 0
fi

if [[ "${FERROCRATE_SKIP_SYSTEMCTL:-0}" != "1" ]] && command -v systemctl >/dev/null 2>&1; then
  # A missing user bus is not fatal during uninstall; the unit is still
  # removed, preventing a later user session from resurrecting it.
  systemctl --user disable --now ferrocrate.service >/dev/null 2>&1 || true
fi

if [[ -L "$target" || -f "$target" ]]; then
  rm -f -- "$target"
  echo "Removed $target"
else
  echo "Ferrocrate binary not installed at $target"
fi
if [[ -L "$unit_path" || -f "$unit_path" ]]; then
  rm -f -- "$unit_path"
  echo "Removed $unit_path"
else
  echo "Ferrocrate user unit not installed at $unit_path"
fi
echo "Ferrocrate runtime state was preserved; remove it only through an explicit state-management workflow."
