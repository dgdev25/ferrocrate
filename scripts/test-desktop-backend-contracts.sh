#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
windows="$root/scripts/install-windows.ps1"
macos="$root/scripts/install-macos.sh"
real_daemon="$root/scripts/test-desktop-real-daemon.sh"

require_text() {
  local file="$1" pattern="$2" label="$3"
  if ! grep -Eq -- "$pattern" "$file"; then
    printf 'missing %s contract in %s\n' "$label" "$file" >&2
    exit 1
  fi
}

require_text "$windows" 'Microsoft-Windows-Subsystem-Linux' 'WSL optional feature'
require_text "$windows" 'VirtualMachinePlatform' 'virtual machine platform feature'
require_text "$windows" '\[string\]\$WslDistro = .Ubuntu.' 'shared Ubuntu distro default'
require_text "$windows" 'wsl(\.exe)? --install.*\$Distro' 'selected distro installation'
require_text "$windows" 'systemctl --user|ferrocrate-daemon\.pid' 'guest daemon supervisor fallback'
require_text "$windows" 'apt-get install -y[^\n]*socat' 'guest socket transport dependency'
require_text "$windows" 'ferrocrate daemon --socket' 'guest daemon socket'
require_text "$windows" '--pipe-name' 'named pipe relay'
require_text "$windows" '--wsl-distro[^\n]*\$Distro' 'direct named-pipe WSL routing'

require_text "$macos" 'vfkit' 'vfkit-first launcher'
require_text "$macos" 'qemu-system-' 'QEMU fallback'
require_text "$macos" 'virtiofs' 'virtiofs share'
require_text "$macos" 'ssh' 'SSH execution'
require_text "$macos" 'LocalForward|-[[:space:]]*L' 'daemon socket forwarding'
require_text "$macos" 'nested virtualization|kern\.hv_support' 'virtualization diagnosis'
require_text "$macos" 'dhcpd_leases' 'vfkit guest address discovery'
require_text "$macos" 'socat.*TCP-LISTEN.*VM_SSH_PORT|TCP-LISTEN.*VM_SSH_PORT.*socat' 'vfkit SSH host forwarding'
require_text "$macos" 'FERROCRATE_CONFIG_DIR=.*\.ferrocrate' 'shared config root'
require_text "$macos" 'VM_STATE_FILE=.*desktop-vm\.json' 'shared VM state path'
require_text "$macos" 'VM_GUEST_USER=.*ferro' 'shared guest user'
require_text "$macos" 'desktop_vm_ed25519' 'shared SSH key'
require_text "$macos" 'FERROCRATE_DESKTOP_VM_STATE' 'runtime VM state override'
require_text "$macos" 'FERROCRATE_VM_GUEST_USER' 'runtime guest user override'
require_text "$macos" 'FERROCRATE_VM_SSH_KEY' 'runtime SSH key override'
require_text "$macos" 'ferrocrate daemon --socket' 'guest daemon socket'
require_text "$macos" 'systemctl.*enable.*--now|enable --now.*ferrocrate' 'guest daemon supervision'
require_text "$macos" 'qemu-tcg-' 'software QEMU acceleration fallback'
require_text "$macos" 'vm[[:space:]]+\\?[^\n]*init|vm.*init' 'persisted VM initialization'
require_text "$macos" '--vfkit-kernel-path' 'persisted vfkit kernel configuration'
require_text "$macos" 'qemu-img convert -O raw' 'vfkit raw disk artifact'
if grep -Fq 'ferrocrate-desktop-relay' "$macos"; then
  printf 'obsolete macOS relay executable contract remains in %s\n' "$macos" >&2
  exit 1
fi

require_text "$real_daemon" 'host_os=.*uname' 'host/backend selection'
require_text "$real_daemon" 'SKIP.*requires.*host' 'unavailable backend skip row'
require_text "$real_daemon" 'selected backend .* does not match host backend' 'mismatched backend guard'
require_text "$real_daemon" 'desktop-real-daemon-test' 'scoped desktop test entitlement'
require_text "$real_daemon" 'run_wsl2_backend_smoke' 'WSL2 selected-backend smoke path'
require_text "$real_daemon" 'run_macos_backend_smoke' 'macOS selected-backend smoke path'
require_text "$real_daemon" 'backend-smoke --start --json' 'selected-backend start/status/request command'

printf 'desktop backend provisioning contracts passed\n'
