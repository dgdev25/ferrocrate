#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"

# Network mutation is the security-sensitive boundary covered by the
# inventory.  All production process execution in these crates must flow
# through ferro-net::executor; executor.rs itself is the one intentional
# implementation of that boundary.  Test fixtures and build scripts are not
# runtime mutation paths and are deliberately outside this scan.
scan_roots=("$repo_root/ferro-net/src" "$repo_root/ferro-netd/src")
violations=()

while IFS= read -r match; do
  [[ -z "$match" ]] && continue
  file="${match%%:*}"
  case "$file" in
    */ferro-net/src/executor.rs) ;;
    *) violations+=("$match") ;;
  esac
done < <(
  rg -n --no-heading --glob '*.rs' \
    'Command::new|std::process::Command|(^|[[:space:]])(sh|bash)[[:space:]]+-c' \
    "${scan_roots[@]}" || true
)

if ((${#violations[@]} != 0)); then
  printf '%s\n' 'shell-out audit: fail' >&2
  printf '%s\n' "${violations[@]}" >&2
  exit 1
fi

printf '%s\n' 'shell-out audit: pass'
