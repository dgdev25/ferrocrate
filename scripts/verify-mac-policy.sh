#!/usr/bin/env bash
set -euo pipefail

output_file="${1:-}"
strict="${FERROCRATE_MAC_STRICT:-0}"
enabled_apparmor="${FERROCRATE_APPARMOR:-0}"
enabled_selinux="${FERROCRATE_SELINUX:-0}"

has() { command -v "$1" >/dev/null 2>&1; }
truthy() { [[ "$1" == "1" || "$1" =~ ^([Tt][Rr][Uu][Ee]|[Yy][Ee][Ss])$ ]]; }

apparmor_tools=0
if has apparmor_parser && has aa-exec; then apparmor_tools=1; fi
apparmor_loaded=unknown
if has aa-status; then
  if aa-status --enabled >/dev/null 2>&1; then apparmor_loaded=enabled; else apparmor_loaded=disabled; fi
fi

selinux_tools=0
if has runcon; then selinux_tools=1; fi
selinux_mode=unknown
if has getenforce; then selinux_mode="$(getenforce 2>/dev/null || printf unknown)"; fi

lines=(
  "apparmor.tools=$apparmor_tools"
  "apparmor.status=$apparmor_loaded"
  "apparmor.enabled=$(truthy "$enabled_apparmor" && echo yes || echo no)"
  "selinux.runcon=$selinux_tools"
  "selinux.mode=$selinux_mode"
  "selinux.enabled=$(truthy "$enabled_selinux" && echo yes || echo no)"
  "mac.strict=$strict"
)

if [[ -n "$output_file" ]]; then
  mkdir -p "$(dirname -- "$output_file")"
  printf '%s\n' "${lines[@]}" >"$output_file"
else
  printf '%s\n' "${lines[@]}"
fi

if [[ "$strict" == 1 ]]; then
  if truthy "$enabled_apparmor" && (( apparmor_tools == 0 )); then
    echo "strict MAC check failed: AppArmor is enabled but apparmor_parser/aa-exec are unavailable" >&2
    exit 1
  fi
  if truthy "$enabled_selinux"; then
    if (( selinux_tools == 0 )); then
      echo "strict MAC check failed: SELinux is enabled but runcon is unavailable" >&2
      exit 1
    fi
    case "${selinux_mode,,}" in
      enforcing|permissive) ;;
      *)
        echo "strict MAC check failed: SELinux is enabled but enforcement state is ${selinux_mode}" >&2
        exit 1
        ;;
    esac
  fi
fi

echo "MAC policy prerequisites recorded"
