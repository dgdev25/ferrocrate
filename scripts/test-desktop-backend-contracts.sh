#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
windows="$root/scripts/install-windows.ps1"
macos="$root/scripts/install-macos.sh"

require_text() {
  local file="$1" pattern="$2" label="$3"
  if ! grep -Eq -- "$pattern" "$file"; then
    printf 'missing %s contract in %s\n' "$label" "$file" >&2
    exit 1
  fi
}

require_text "$windows" 'Microsoft-Windows-Subsystem-Linux' 'WSL optional feature'
require_text "$windows" 'VirtualMachinePlatform' 'virtual machine platform feature'
require_text "$windows" 'wsl(\.exe)? --install.*Ubuntu' 'Ubuntu distro installation'
require_text "$windows" 'systemctl --user|ferrocrate-daemon\.pid' 'guest daemon supervisor fallback'
require_text "$windows" '--pipe-name' 'named pipe relay'
require_text "$windows" '127\.0\.0\.1' 'loopback-only relay'

require_text "$macos" 'vfkit' 'vfkit-first launcher'
require_text "$macos" 'qemu-system-' 'QEMU fallback'
require_text "$macos" 'virtiofs' 'virtiofs share'
require_text "$macos" 'ssh' 'SSH execution'
require_text "$macos" 'LocalForward|-[[:space:]]*L' 'daemon socket forwarding'
require_text "$macos" 'nested virtualization|kern\.hv_support' 'virtualization diagnosis'

printf 'desktop backend provisioning contracts passed\n'
