#!/bin/bash
# FerroCrate Universal Installer
# Downloads and verifies the latest FerroCrate binary for your platform
# Usage: curl -fsSL https://ferrocrate.sh/install.sh | bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO="dgtise25/ferrocrate"
RELEASE_API="https://api.github.com/repos/${REPO}/releases/latest"
GITHUB_RELEASE_BASE="https://github.com/${REPO}/releases/download"
INSTALL_DIR="${HOME}/.local/bin"

# Functions
log_info() {
  echo -e "${GREEN}✓${NC} $1"
}

log_error() {
  echo -e "${RED}✗${NC} $1" >&2
}

log_warn() {
  echo -e "${YELLOW}⚠${NC} $1"
}

detect_os_arch() {
  local os arch

  os=$(uname -s)
  arch=$(uname -m)

  case "$os" in
    Linux*)
      echo "linux"
      ;;
    Darwin*)
      echo "macos"
      ;;
    MINGW* | CYGWIN* | MSYS*)
      echo "windows"
      ;;
    *)
      log_error "Unsupported OS: $os"
      exit 1
      ;;
  esac
}

detect_arch() {
  local arch
  arch=$(uname -m)

  case "$arch" in
    x86_64 | amd64)
      echo "x86_64"
      ;;
    aarch64 | arm64)
      echo "arm64"
      ;;
    *)
      log_error "Unsupported architecture: $arch"
      exit 1
      ;;
  esac
}

get_latest_version() {
  if command -v jq &> /dev/null; then
    curl -s "${RELEASE_API}" | jq -r '.tag_name' 2>/dev/null || echo "latest"
  else
    # Fallback without jq - extract version from release page
    curl -s "https://github.com/${REPO}/releases/latest" | grep -oP 'href="/[^/]*/ferrocrate/releases/tag/\K[^"]+' | head -1 || echo "latest"
  fi
}

verify_checksum() {
  local file checksum_file expected_checksum actual_checksum

  file="$1"
  checksum_file="${file}.sha256"

  if [ ! -f "$checksum_file" ]; then
    log_warn "Checksum file not found, skipping verification"
    return 0
  fi

  log_info "Verifying checksum..."
  expected_checksum=$(cat "$checksum_file" | cut -d' ' -f1)

  if command -v sha256sum &> /dev/null; then
    actual_checksum=$(sha256sum "$file" | cut -d' ' -f1)
  elif command -v shasum &> /dev/null; then
    actual_checksum=$(shasum -a 256 "$file" | cut -d' ' -f1)
  else
    log_warn "No checksum tool available, skipping verification"
    return 0
  fi

  if [ "$expected_checksum" != "$actual_checksum" ]; then
    log_error "Checksum mismatch!"
    log_error "Expected: $expected_checksum"
    log_error "Got:      $actual_checksum"
    rm -f "$file"
    exit 1
  fi

  log_info "Checksum verified"
}

download_binary() {
  local os arch version binary_name download_url file

  os="$1"
  arch="$2"
  version="$3"

  # Determine binary name based on platform
  case "$os" in
    linux)
      binary_name="ferrocrate-${version}-${arch}.AppImage"
      ;;
    macos)
      binary_name="ferrocrate-${version}-universal.dmg"
      ;;
    windows)
      binary_name="ferrocrate-${version}-x64-portable.exe"
      ;;
  esac

  download_url="${GITHUB_RELEASE_BASE}/${version}/${binary_name}"
  file=$(mktemp)

  log_info "Downloading ${binary_name}..."
  if ! curl -fsSL -o "$file" "$download_url"; then
    log_error "Failed to download binary from $download_url"
    rm -f "$file"
    exit 1
  fi

  # Try to download checksum
  if curl -fsSL -o "${file}.sha256" "${download_url}.sha256" 2>/dev/null; then
    verify_checksum "$file"
  else
    log_warn "Checksum not available"
  fi

  echo "$file"
}

install_binary() {
  local os file install_path

  os="$1"
  file="$2"

  case "$os" in
    linux)
      log_info "Installing AppImage..."
      mkdir -p "$INSTALL_DIR"
      chmod +x "$file"
      mv "$file" "$INSTALL_DIR/ferrocrate"
      log_info "Installed to $INSTALL_DIR/ferrocrate"
      ;;
    macos)
      log_info "Opening disk image (.dmg)..."
      hdiutil attach "$file" -quiet
      # Note: User interaction required for macOS
      log_info "Mounted at /Volumes/FerroCrate. Drag FerroCrate.app to Applications folder."
      ;;
    windows)
      log_info "Running Windows installer..."
      chmod +x "$file"
      "$file"
      ;;
  esac
}

main() {
  local os arch version file

  log_info "FerroCrate Installer"

  os=$(detect_os_arch)
  arch=$(detect_arch)
  version=$(get_latest_version)

  log_info "Detected platform: $os/$arch"
  log_info "Latest version: $version"

  # Ensure install directory exists (Linux only)
  if [ "$os" = "linux" ]; then
    mkdir -p "$INSTALL_DIR"
    if [ ":$PATH:" != *":$INSTALL_DIR:"* ]; then
      log_warn "$INSTALL_DIR is not in PATH"
      log_info "Add this to your ~/.bashrc or ~/.zshrc:"
      echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
  fi

  file=$(download_binary "$os" "$arch" "$version")
  install_binary "$os" "$file"

  log_info "FerroCrate installation complete!"
  log_info "Run 'ferrocrate --help' to get started"
}

main "$@"
