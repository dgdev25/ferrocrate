#!/usr/bin/env bash
set -euo pipefail

# Build a minimal qcow2 image for FerroCrate desktop VM workflows.
# This is a scaffold script for Phase 1; it creates/refreshes a base disk and
# optionally injects runtime dependencies when libguestfs tools are available.

OUT_IMAGE="${1:-./tmp/ferrocrate-desktop.qcow2}"
SIZE_GB="${2:-20}"
BASE_IMAGE_URL="${BASE_IMAGE_URL:-https://cloud-images.ubuntu.com/minimal/releases/24.04/release/ubuntu-24.04-minimal-cloudimg-amd64.img}"
CACHE_DIR="${CACHE_DIR:-./tmp/vm-cache}"
BASE_IMAGE="${CACHE_DIR}/base-cloudimg.qcow2"

mkdir -p "$(dirname "$OUT_IMAGE")" "$CACHE_DIR"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    exit 1
  }
}

require curl
require qemu-img

if [[ ! -f "$BASE_IMAGE" ]]; then
  echo "Downloading base cloud image..."
  curl -L "$BASE_IMAGE_URL" -o "$BASE_IMAGE"
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

echo "Desktop VM image scaffold ready: $OUT_IMAGE"
