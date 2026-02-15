#!/usr/bin/env bash
set -euo pipefail

# Build a minimal qcow2 image for FerroCrate desktop VM workflows.
# This is a scaffold script for Phase 1; it creates/refreshes a base disk and
# optionally injects runtime dependencies when libguestfs tools are available.

OUT_IMAGE="${1:-./tmp/ferrocrate-desktop.qcow2}"
SIZE_GB="${2:-20}"
ARCH_NAME="$(uname -m)"
case "$ARCH_NAME" in
  arm64|aarch64) ARCH_TAG="arm64" ;;
  x86_64|amd64) ARCH_TAG="amd64" ;;
  *) echo "unsupported architecture: $ARCH_NAME" >&2; exit 1 ;;
esac
BASE_IMAGE_URL="${BASE_IMAGE_URL:-https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-${ARCH_TAG}.img}"
CACHE_DIR="${CACHE_DIR:-./tmp/vm-cache}"
BASE_IMAGE="${CACHE_DIR}/base-cloudimg.qcow2"
BASE_IMAGE_SHA256="${BASE_IMAGE_SHA256:-}"
MANIFEST_PATH="${MANIFEST_PATH:-${OUT_IMAGE}.manifest.txt}"

mkdir -p "$(dirname "$OUT_IMAGE")" "$CACHE_DIR"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    exit 1
  }
}

require curl
require qemu-img
if command -v sha256sum >/dev/null 2>&1; then
  SHA256SUM_BIN="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA256SUM_BIN="shasum -a 256"
else
  echo "missing required tool: sha256sum (or shasum -a 256)" >&2
  exit 1
fi

if [[ ! -f "$BASE_IMAGE" ]]; then
  echo "Downloading base cloud image..."
  curl -fL "$BASE_IMAGE_URL" -o "$BASE_IMAGE"
fi

if [[ -n "$BASE_IMAGE_SHA256" ]]; then
  echo "Verifying base image checksum..."
  actual_sha="$($SHA256SUM_BIN "$BASE_IMAGE" | awk '{print $1}')"
  if [[ "$actual_sha" != "$BASE_IMAGE_SHA256" ]]; then
    echo "base image checksum mismatch: expected=$BASE_IMAGE_SHA256 actual=$actual_sha" >&2
    exit 1
  fi
fi

echo "Preparing output image: $OUT_IMAGE"
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OUT_IMAGE" "${SIZE_GB}G" >/dev/null

if command -v virt-customize >/dev/null 2>&1; then
  echo "Customizing image with runtime dependencies..."
  virt-customize -a "$OUT_IMAGE" \
    --run-command 'apt-get update' \
    --install 'iproute2,nftables,slirp4netns,fuse-overlayfs,ca-certificates' \
    --run-command 'mkdir -p /opt/ferrocrate/bin'
  if [[ -f ./target/release/ferro-cli ]]; then
    virt-copy-in -a "$OUT_IMAGE" ./target/release/ferro-cli /opt/ferrocrate/bin/
  fi
else
  echo "virt-customize not found; skipping package customization"
fi

out_sha="$(sha256sum "$OUT_IMAGE" | awk '{print $1}')"
cat >"$MANIFEST_PATH" <<EOF
ferrocrate_desktop_vm_manifest_v1
source_url=$BASE_IMAGE_URL
source_sha256=${BASE_IMAGE_SHA256:-unverified}
output_image=$OUT_IMAGE
output_sha256=$out_sha
size_gb=$SIZE_GB
built_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

echo "Desktop VM image scaffold ready: $OUT_IMAGE"
echo "Manifest written: $MANIFEST_PATH"
