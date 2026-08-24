#!/usr/bin/env bash
set -euo pipefail

# Stage a named revision in one of the local libvirt guests, run that
# revision's host-matrix row as root, and copy its witness back to this checkout.
# The default source is `main`: this driver deliberately does not merge main
# into the caller's branch merely to obtain the qualification harness.

usage() {
  echo "usage: $0 ROW_ID [--dry-run]" >&2
}

row_id="${1:-}"
dry_run="${2:-}"
[[ -n "$row_id" ]] || { usage; exit 2; }
[[ "$row_id" != *[!a-zA-Z0-9._-]* ]] || { echo "invalid row id: $row_id" >&2; exit 2; }
[[ -z "$dry_run" || "$dry_run" == "--dry-run" ]] || { usage; exit 2; }

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
source_ref="${FERROCRATE_MATRIX_SOURCE_REF:-main}"
guest_user="${FERROCRATE_MATRIX_GUEST_USER:-lyle}"
guest_port="${FERROCRATE_MATRIX_GUEST_PORT:-22}"
ssh_key="${FERROCRATE_MATRIX_SSH_KEY:-}"
remote_root="${FERROCRATE_MATRIX_REMOTE_ROOT:-/tmp/ferrocrate-host-matrix-${row_id}}"
evidence_root="${FERROCRATE_MATRIX_EVIDENCE_ROOT:-$repo_root/docs/evidence/host-matrix}"
[[ "$remote_root" == /* && "$remote_root" != *[!a-zA-Z0-9._/-]* ]] || {
  echo "FERROCRATE_MATRIX_REMOTE_ROOT must be an absolute safe path" >&2
  exit 2
}

case "$row_id" in
  ubuntu-24.04-*|ubuntu-26.04-*) domain="ferro-ubuntu-01"; address="192.168.122.9" ;;
  debian-*) domain="ferro-debian-01"; address="192.168.122.20" ;;
  fedora-*) domain="ferro-fedora-01"; address="192.168.122.254" ;;
  rocky-*) domain="ferro-rocky-01"; address="192.168.122.56" ;;
  ubuntu-20.04-*) domain="ferro-ubuntu2004-01"; address="192.168.122.247" ;;
  alpine-*) domain="ferro-alpine322-01"; address="192.168.122.128" ;;
  aarch64-*) echo "row $row_id requires aarch64 hardware and remains a candidate" >&2; exit 77 ;;
  *) echo "no libvirt guest mapping for row: $row_id" >&2; exit 2 ;;
esac

address="${FERROCRATE_MATRIX_GUEST_ADDRESS:-$address}"
commit="$(git -C "$repo_root" rev-parse --verify "${source_ref}^{commit}")"
ssh_args=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -p "$guest_port")
[[ -z "$ssh_key" ]] || ssh_args+=(-i "$ssh_key")
remote="${guest_user}@${address}"

run() {
  if [[ "$dry_run" == "--dry-run" ]]; then
    printf '+ '
    printf '%q ' "$@"
    printf '\n'
  else
    "$@"
  fi
}

if [[ "$dry_run" == "--dry-run" ]]; then
  printf 'row=%s domain=%s address=%s source=%s commit=%s\n' \
    "$row_id" "$domain" "$address" "$source_ref" "$commit"
  printf 'would archive %s, build it in %s, run its row as root, and copy docs/evidence/host-matrix/%s back to %s\n' \
    "$source_ref" "$remote_root" "$row_id" "$evidence_root"
  exit 0
fi

state="$(virsh -c qemu:///system domstate "$domain" | tr -d '\r' | xargs)"
if [[ "$state" == "shut off" ]]; then
  run virsh -c qemu:///system start "$domain"
elif [[ "$state" != "running" ]]; then
  echo "guest $domain is not runnable (state: $state)" >&2
  exit 1
fi

deadline=$((SECONDS + ${FERROCRATE_MATRIX_SSH_TIMEOUT_SECS:-90}))
until ssh_error="$(ssh "${ssh_args[@]}" "$remote" true 2>&1)"; do
  if [[ "$ssh_error" == *"Permission denied"* ]]; then
    printf 'SSH authentication failed for %s. Set FERROCRATE_MATRIX_SSH_KEY to a key authorized for the guest.\n' "$remote" >&2
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    printf 'guest %s did not accept SSH at %s within timeout: %s\n' \
      "$domain" "$address" "$ssh_error" >&2
    exit 1
  fi
  sleep 2
done

# Stage a real git checkout: the conformance harness resolves the source
# commit with `git rev-parse HEAD`, which a bare archive cannot satisfy.
git -C "$repo_root" bundle create - "$source_ref" | \
  ssh "${ssh_args[@]}" "$remote" "set -eu; sudo -n rm -rf -- '$remote_root'; cat > '${remote_root}.bundle'; git clone -q '${remote_root}.bundle' '$remote_root'; git -C '$remote_root' checkout -q '$commit'; rm -f '${remote_root}.bundle'"

ssh "${ssh_args[@]}" "$remote" "set -eu; export PATH=\"\$HOME/.cargo/bin:\$PATH:/usr/sbin:/sbin\"; export CARGO_HOME=\"\$HOME/.cargo\" RUSTUP_HOME=\"\$HOME/.rustup\"; cd '$remote_root'; cargo build --locked --workspace; sudo -n env PATH=\"\$PATH\" CARGO_HOME=\"\$CARGO_HOME\" RUSTUP_HOME=\"\$RUSTUP_HOME\" FERROCRATE_REPO_ROOT='$remote_root' bash scripts/run-host-matrix-row.sh '$row_id'"

mkdir -p "$evidence_root"
ssh "${ssh_args[@]}" "$remote" "tar -C '$remote_root/docs/evidence/host-matrix' -cf - '$row_id'" | \
  tar -C "$evidence_root" -xf -

printf 'host-matrix libvirt row completed: row=%s guest=%s commit=%s evidence=%s/%s\n' \
  "$row_id" "$domain" "$commit" "$evidence_root" "$row_id"
