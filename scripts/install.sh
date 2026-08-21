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
REPO="dgdev25/ferrocrate"
RELEASE_API="https://api.github.com/repos/${REPO}/releases/latest"
GITHUB_RELEASE_BASE="https://github.com/${REPO}/releases/download"
INSTALL_DIR="${HOME}/.local/bin"
FERROCRATE_VERSION="${FERROCRATE_VERSION:-}"

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

detect_linux_libc() {
  local requested="${FERROCRATE_LINUX_LIBC:-auto}"
  case "$requested" in
    gnu|musl)
      printf '%s\n' "$requested"
      return
      ;;
    auto) ;;
    *)
      log_error "Unsupported FERROCRATE_LINUX_LIBC: $requested (expected auto, gnu, or musl)"
      exit 1
      ;;
  esac
  if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    printf 'musl\n'
  else
    printf 'gnu\n'
  fi
}

get_latest_version() {
  if [ -n "$FERROCRATE_VERSION" ]; then
    printf '%s\n' "$FERROCRATE_VERSION"
    return
  fi
  if command -v jq &> /dev/null; then
    curl -s "${RELEASE_API}" | jq -r '.tag_name' 2>/dev/null || echo "latest"
  else
    # Fallback without jq - extract version from release page
    curl -s "https://github.com/${REPO}/releases/latest" | grep -oP 'href="/[^/]*/ferrocrate/releases/tag/\K[^"]+' | head -1 || echo "latest"
  fi
}

validate_version() {
  local version="$1"
  if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    log_error "Invalid release version: $version"
    exit 1
  fi
}

verify_checksum() {
  local file checksum_file expected_checksum actual_checksum entries listed_file

  file="$1"
  checksum_file="${2:-${file}.sha256}"

  if [ ! -f "$checksum_file" ]; then
    log_error "Checksum file not found: $checksum_file"
    return 1
  fi

  log_info "Verifying checksum..."
  entries=$(awk 'NF && $1 !~ /^#/ {count += 1} END {print count + 0}' "$checksum_file")
  if [ "$entries" != "1" ]; then
    log_error "Checksum manifest must contain exactly one artifact entry"
    return 1
  fi
  expected_checksum=$(awk 'NF && $1 !~ /^#/ {print $1; exit}' "$checksum_file")
  listed_file=$(awk 'NF && $1 !~ /^#/ {name=$2; sub(/^\*/, "", name); print name; exit}' "$checksum_file")
  if [[ ! "$expected_checksum" =~ ^[[:xdigit:]]{64}$ ]]; then
    log_error "Checksum manifest contains an invalid SHA-256 digest"
    return 1
  fi
  if [ "$listed_file" != "$(basename "$file")" ] ||
    [[ "$listed_file" == */* || "$listed_file" == -* || "$listed_file" == .* ]]; then
    log_error "Checksum manifest is not bound to the downloaded artifact"
    return 1
  fi

  if command -v sha256sum &> /dev/null; then
    (cd "$(dirname "$file")" && sha256sum --strict -c "$(basename "$checksum_file")") || {
      log_error "Checksum mismatch!"
      rm -f "$file"
      return 1
    }
  elif command -v shasum &> /dev/null; then
    actual_checksum=$(shasum -a 256 "$file" | cut -d' ' -f1)
    if [ "$expected_checksum" != "$actual_checksum" ]; then
      log_error "Checksum mismatch!"
      rm -f "$file"
      return 1
    fi
  else
    log_error "No checksum tool available; refusing unverified release"
    return 1
  fi

  log_info "Checksum verified"
}

download_linux_release() {
  local arch version artifact_dir libc archive_suffix archive checksum_file provenance_file
  arch="$1"
  version="$2"
  artifact_dir="$3"
  libc="${4:-$(detect_linux_libc)}"
  case "$libc" in
    gnu) archive_suffix="" ;;
    musl) archive_suffix="-musl" ;;
    *) log_error "Unsupported Linux libc: $libc"; exit 1 ;;
  esac
  [[ "$arch" == "arm64" ]] && arch="aarch64"
  archive="ferrocrate-${version}-linux-${arch}${archive_suffix}.tar.gz"
  checksum_file="ferrocrate-${version}-checksums.txt"
  provenance_file="${archive}.provenance.json"
  mkdir -p "$artifact_dir"

  log_info "Downloading ${archive}..." >&2
  curl -fsSL -o "$artifact_dir/$archive" "${GITHUB_RELEASE_BASE}/${version}/${archive}"
  curl -fsSL -o "$artifact_dir/$checksum_file" "${GITHUB_RELEASE_BASE}/${version}/${checksum_file}"
  curl -fsSL -o "$artifact_dir/$provenance_file" "${GITHUB_RELEASE_BASE}/${version}/${provenance_file}"

  verify_checksum "$artifact_dir/$archive" "$artifact_dir/$checksum_file" >&2 || {
    log_error "Release checksum verification failed"
    exit 1
  }
  python3 - "$artifact_dir/$provenance_file" "$artifact_dir/$archive" "$version" "$libc" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
archive_path = Path(sys.argv[2])
version = sys.argv[3]
libc = sys.argv[4]
data = json.loads(manifest_path.read_text(encoding="utf-8"))
if data.get("schema") != "ferrocrate-release-provenance-v1":
    raise SystemExit("unsupported release provenance schema")
if data.get("version") != version or data.get("archive") != archive_path.name:
    raise SystemExit("release provenance identity mismatch")
if data.get("target_libc") != libc:
    raise SystemExit("release provenance libc mismatch")
if data.get("sha256") != hashlib.sha256(archive_path.read_bytes()).hexdigest():
    raise SystemExit("release provenance digest mismatch")
PY
  printf '%s\n' "$artifact_dir/$archive"
}

install_linux_release() {
  local archive="$1" install_dir="$2" stage backup backup_security
  stage="$(mktemp -d)"
  backup=""
  backup_security=""
  cleanup() {
    rm -rf "$stage"
    if [ -n "$backup" ] && [ ! -e "$install_dir/ferrocrate" ]; then
      mv "$backup" "$install_dir/ferrocrate" 2>/dev/null || true
    fi
    if [ -n "$backup_security" ] && [ ! -e "$install_dir/ferro-security.o" ]; then
      mv "$backup_security" "$install_dir/ferro-security.o" 2>/dev/null || true
    fi
  }
  trap cleanup RETURN
  tar -xzf "$archive" -C "$stage"
  if [ ! -f "$stage/ferrocrate/ferrocrate" ]; then
    log_error "Release archive does not contain ferrocrate CLI"
    return 1
  fi
  chmod 0755 "$stage/ferrocrate/ferrocrate"
  mkdir -p "$install_dir"
  if [ -e "$install_dir/ferrocrate" ]; then
    backup="$install_dir/.ferrocrate.previous.$$"
    mv "$install_dir/ferrocrate" "$backup"
  fi
  if ! mv "$stage/ferrocrate/ferrocrate" "$install_dir/ferrocrate"; then
    log_error "Unable to install ferrocrate; restoring previous binary"
    return 1
  fi
  if [ -f "$stage/ferrocrate/ferro-security.o" ]; then
    chmod 0644 "$stage/ferrocrate/ferro-security.o"
    if [ -e "$install_dir/ferro-security.o" ]; then
      backup_security="$install_dir/.ferrocrate-security.previous.$$"
      mv "$install_dir/ferro-security.o" "$backup_security"
    fi
    if ! mv "$stage/ferrocrate/ferro-security.o" "$install_dir/ferro-security.o"; then
      log_error "Unable to install security eBPF object; restoring previous files"
      return 1
    fi
  fi
  if [ -n "$backup" ]; then
    rm -f "$backup"
  fi
  if [ -n "$backup_security" ]; then
    rm -f "$backup_security"
  fi
  backup=""
  backup_security=""
  log_info "Installed to $install_dir/ferrocrate"
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
    log_error "Checksum not available; refusing unverified release"
    rm -f "$file" "${file}.sha256"
    exit 1
  fi

  echo "$file"
}

platform_archive_name() {
  local os="$1" arch="$2" version="$3"
  [[ "$arch" == "arm64" ]] && arch="aarch64"
  case "$os" in
    macos) printf 'ferrocrate-%s-macos-%s.tar.gz\n' "$version" "$arch" ;;
    windows) printf 'ferrocrate-%s-windows-%s.zip\n' "$version" "$arch" ;;
    *) log_error "Unsupported archive platform: $os"; exit 1 ;;
  esac
}

download_platform_release() {
  local os="$1" arch="$2" version="$3" artifact_dir="$4"
  local archive checksum_file provenance_file
  archive="$(platform_archive_name "$os" "$arch" "$version")"
  checksum_file="ferrocrate-${version}-checksums.txt"
  provenance_file="${archive}.provenance.json"
  mkdir -p "$artifact_dir"
  log_info "Downloading ${archive}..." >&2
  curl -fsSL -o "$artifact_dir/$archive" "${GITHUB_RELEASE_BASE}/${version}/${archive}"
  curl -fsSL -o "$artifact_dir/$checksum_file" "${GITHUB_RELEASE_BASE}/${version}/${checksum_file}"
  curl -fsSL -o "$artifact_dir/$provenance_file" "${GITHUB_RELEASE_BASE}/${version}/${provenance_file}"
  verify_checksum "$artifact_dir/$archive" "$artifact_dir/$checksum_file" >&2 || {
    log_error "Release checksum verification failed"
    exit 1
  }
  python3 - "$artifact_dir/$provenance_file" "$artifact_dir/$archive" "$version" "$os" "$arch" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
archive_path = Path(sys.argv[2])
version, target_os, target_arch = sys.argv[3:6]
if target_arch == "arm64":
    target_arch = "aarch64"
data = json.loads(manifest_path.read_text(encoding="utf-8"))
if data.get("schema") != "ferrocrate-release-provenance-v1":
    raise SystemExit("unsupported release provenance schema")
if data.get("version") != version or data.get("archive") != archive_path.name:
    raise SystemExit("release provenance identity mismatch")
if data.get("target_os") != target_os or data.get("target_arch") != target_arch:
    raise SystemExit("release provenance target mismatch")
if data.get("target_libc") != "gnu":
    raise SystemExit("release provenance libc mismatch")
if data.get("sha256") != hashlib.sha256(archive_path.read_bytes()).hexdigest():
    raise SystemExit("release provenance digest mismatch")
PY
  printf '%s\n' "$artifact_dir/$archive"
}

install_platform_archive() {
  local os="$1" archive="$2" install_dir="$3"
  local stage binary_name="" backup=""
  stage="$(mktemp -d)"
  cleanup_platform_archive() {
    find "$stage" -depth -delete 2>/dev/null || true
    if [[ -n "$backup" && -n "$binary_name" && ! -e "$install_dir/$binary_name" ]]; then
      mv "$backup" "$install_dir/$binary_name" 2>/dev/null || true
    fi
  }
  trap cleanup_platform_archive RETURN
  if [[ "$archive" == *.tar.gz ]]; then
    tar -xzf "$archive" -C "$stage"
    binary_name="ferrocrate"
  elif [[ "$archive" == *.zip ]]; then
    command -v unzip >/dev/null 2>&1 || { log_error "unzip is required for Windows release archives"; return 1; }
    unzip -q "$archive" -d "$stage"
    binary_name="ferrocrate.exe"
  else
    log_error "unsupported platform archive: $archive"
    return 1
  fi
  [[ -f "$stage/ferrocrate/$binary_name" ]] || {
    log_error "Release archive does not contain $binary_name"
    return 1
  }
  mkdir -p "$install_dir"
  if [[ -e "$install_dir/$binary_name" ]]; then
    backup="$install_dir/.${binary_name}.previous.$$"
    mv "$install_dir/$binary_name" "$backup"
  fi
  if ! mv "$stage/ferrocrate/$binary_name" "$install_dir/$binary_name"; then
    log_error "Unable to install $binary_name; restoring previous binary"
    return 1
  fi
  chmod 0755 "$install_dir/$binary_name" 2>/dev/null || true
  [[ -z "$backup" ]] || rm -f "$backup"
  backup=""
  log_info "Installed to $install_dir/$binary_name"
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
  local os arch version file download_dir libc

  log_info "FerroCrate Installer"

  os=$(detect_os_arch)
  arch=$(detect_arch)
  version=$(get_latest_version)
  validate_version "$version"

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

  if [ "$os" = "linux" ]; then
    command -v python3 >/dev/null 2>&1 || { log_error "python3 is required for release provenance verification"; exit 1; }
    command -v sha256sum >/dev/null 2>&1 || { log_error "sha256sum is required for release verification"; exit 1; }
    download_dir=$(mktemp -d)
    trap 'rm -rf "$download_dir"' EXIT
    libc="$(detect_linux_libc)"
    log_info "Selected Linux libc: $libc"
    file=$(download_linux_release "$arch" "$version" "$download_dir" "$libc")
    install_linux_release "$file" "$INSTALL_DIR"
  else
    download_dir=$(mktemp -d)
    trap 'rm -rf "$download_dir"' EXIT
    file=$(download_platform_release "$os" "$arch" "$version" "$download_dir")
    install_platform_archive "$os" "$file" "$INSTALL_DIR"
  fi

  log_info "FerroCrate installation complete!"
  log_info "Run 'ferrocrate --help' to get started"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
