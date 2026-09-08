#!/usr/bin/env bash
# Administrative integration test: load only a uniquely named temporary profile.
# Do not edit installed profiles, sysctls, subordinate IDs, or existing workloads.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
proof_user="${FERROCRATE_PROOF_USER:-${SUDO_USER:-}}"
if [[ "$(id -u)" != 0 ]]; then
  echo 'AppArmor bwrap inheritance test requires root to load a temporary profile' >&2
  exit 77
fi
if [[ -z "$proof_user" || "$proof_user" == root ]] || ! id "$proof_user" >/dev/null 2>&1; then
  echo 'Set FERROCRATE_PROOF_USER to an existing non-root user with subordinate IDs' >&2
  exit 77
fi
for tool in apparmor_parser aa-exec aa-status bwrap unshare runuser python3; do
  command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 77; }
done
aa-status --enabled >/dev/null 2>&1 || { echo 'AppArmor must be enabled' >&2; exit 77; }
proof_uid="$(id -u "$proof_user")"
proof_gid="$(id -g "$proof_user")"
[[ "$proof_uid" != 0 ]] || { echo 'Proof user must not be root' >&2; exit 77; }
tmp="$(mktemp -d /tmp/ferrocrate-bwrap-inheritance.XXXXXX)"
profile_name="ferrocrate-bwrap-inheritance-$$"
loaded=0
cleanup() {
  if (( loaded )); then apparmor_parser -R "$tmp/profile"; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
chmod 0711 "$tmp"
install -d -m 0700 -o "$proof_uid" -g "$proof_gid" "$tmp/work"
python3 - "$repo_root/packaging/apparmor/usr.local.bin.ferrocrate" "$tmp/profile" "$profile_name" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
source = source.replace('profile usr.local.bin.ferrocrate /usr/local/bin/ferrocrate ', f'profile {sys.argv[3]} ')
# Test the shipped rules, not machine-local overrides.
source = source.replace('  #include if exists <local/usr.local.bin.ferrocrate>', '')
Path(sys.argv[2]).write_text(source)
PY
apparmor_parser -QK "$tmp/profile"
apparmor_parser -aK "$tmp/profile"
loaded=1
runuser -u "$proof_user" -- touch "$tmp/work/probe"
# The host tree is read-only; only a disposable test directory is writable.
# --map-auto uses already configured subordinate IDs; it does not allocate them.
runuser -u "$proof_user" -- aa-exec -p "$profile_name" -- \
  unshare --user --map-root-user --map-auto -- \
  bwrap --ro-bind / / --proc /proc --dev /dev --bind "$tmp/work" "$tmp/work" -- \
  /bin/sh -eu -c '
    label=$(cat /proc/self/attr/current)
    printf "workload.profile=%s\n" "$label"
    case "$label" in *unpriv_bwrap*) echo "Workload inherited restricted bwrap profile" >&2; exit 1;; esac
    case "$label" in *"$1"*) ;; *) echo "Workload lost candidate profile" >&2; exit 1;; esac
    python3 -c '\''from pathlib import Path; s=Path("/proc/self/status").read_text(); cap=int(next(x.split()[1] for x in s.splitlines() if x.startswith("CapEff:")),16); assert cap & 1, "CAP_CHOWN missing"'\''
    chown 1:1 "$2/probe"
    test "$(stat -c %u:%g "$2/probe")" = 1:1
    echo "mapped-volume.chown=pass"
  ' proof "$profile_name" "$tmp/work"
echo 'AppArmor bwrap inheritance integration passed'
