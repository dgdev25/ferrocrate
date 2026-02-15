#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-}"
CHANNEL="${CHANNEL:-public}"
OUTPUT_DIR="${OUTPUT_DIR:-dist/release}"
TARGET_OS="${TARGET_OS:-}"
TARGET_ARCH="${TARGET_ARCH:-}"

usage() {
  cat <<USAGE
Usage: build-release-artifacts.sh --version <tag> [options]

Options:
  --version <tag>            Release tag (for example: v0.1.0)
  --channel <public|paid>    Artifact channel (default: public)
  --output-dir <path>        Output directory (default: dist/release)
  --target-os <os>           Override detected OS (linux|macos|windows)
  --target-arch <arch>       Override detected arch (x86_64|aarch64)
  -h, --help                 Show this help

Notes:
  - public channel packages CLI only.
  - paid channel packages CLI and desktop binary if available.
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)
        VERSION="${2:-}"
        shift 2
        ;;
      --channel)
        CHANNEL="${2:-}"
        shift 2
        ;;
      --output-dir)
        OUTPUT_DIR="${2:-}"
        shift 2
        ;;
      --target-os)
        TARGET_OS="${2:-}"
        shift 2
        ;;
      --target-arch)
        TARGET_ARCH="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "unknown option: $1" >&2
        usage
        exit 1
        ;;
    esac
  done
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

write_sha256_file() {
  local input_file="$1"
  local output_file="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$input_file" > "$output_file"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$input_file" > "$output_file"
    return
  fi
  echo "missing required command: sha256sum or shasum" >&2
  exit 1
}

resolve_os() {
  if [[ -n "$TARGET_OS" ]]; then
    echo "$TARGET_OS"
    return
  fi
  case "$(uname -s)" in
    Linux) echo "linux" ;;
    Darwin) echo "macos" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *)
      echo "unsupported host OS: $(uname -s)" >&2
      exit 1
      ;;
  esac
}

resolve_arch() {
  if [[ -n "$TARGET_ARCH" ]]; then
    echo "$TARGET_ARCH"
    return
  fi
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    arm64|aarch64) echo "aarch64" ;;
    *)
      echo "unsupported host architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

binary_name() {
  local crate_name="$1"
  local os="$2"
  if [[ "$os" == "windows" ]]; then
    echo "${crate_name}.exe"
  else
    echo "$crate_name"
  fi
}

main() {
  parse_args "$@"

  if [[ -z "$VERSION" ]]; then
    echo "--version is required" >&2
    exit 1
  fi
  if [[ "$CHANNEL" != "public" && "$CHANNEL" != "paid" ]]; then
    echo "invalid --channel: $CHANNEL (expected public or paid)" >&2
    exit 1
  fi

  require_cmd cargo
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "missing required command: sha256sum or shasum" >&2
    exit 1
  fi

  local os arch archive_name checksum_name tmpdir package_dir
  os="$(resolve_os)"
  arch="$(resolve_arch)"

  mkdir -p "$OUTPUT_DIR"
  tmpdir="$(mktemp -d)"
  trap '[[ -n "${tmpdir:-}" ]] && rm -rf "$tmpdir"' EXIT

  local build_packages=( -p ferro-cli )
  if [[ "$CHANNEL" == "paid" ]]; then
    build_packages+=( -p ferro-desktop )
  fi

  echo "building release binaries (channel=$CHANNEL os=$os arch=$arch)..."
  cargo build --release "${build_packages[@]}"

  package_dir="$tmpdir/ferrocrate"
  mkdir -p "$package_dir"

  local cli_bin desktop_bin
  cli_bin="target/release/$(binary_name ferro-cli "$os")"
  desktop_bin="target/release/$(binary_name ferro-desktop "$os")"

  if [[ ! -f "$cli_bin" ]]; then
    echo "missing built CLI binary: $cli_bin" >&2
    exit 1
  fi

  cp "$cli_bin" "$package_dir/$(binary_name ferrocrate "$os")"

  if [[ "$CHANNEL" == "paid" ]]; then
    if [[ -f "$desktop_bin" ]]; then
      cp "$desktop_bin" "$package_dir/$(binary_name ferro-desktop "$os")"
    else
      echo "paid channel requested but desktop binary was not produced: $desktop_bin" >&2
      exit 1
    fi
  fi

  if [[ "$os" == "windows" ]]; then
    archive_name="ferrocrate-${VERSION}-${os}-${arch}.zip"
    (cd "$tmpdir" && zip -qr "$OUTPUT_DIR/$archive_name" ferrocrate)
  else
    archive_name="ferrocrate-${VERSION}-${os}-${arch}.tar.gz"
    tar -czf "$OUTPUT_DIR/$archive_name" -C "$tmpdir" ferrocrate
  fi

  checksum_name="ferrocrate-${VERSION}-checksums.txt"
  if [[ "$CHANNEL" == "paid" ]]; then
    checksum_name="ferrocrate-${VERSION}-paid-checksums.txt"
  fi
  (cd "$OUTPUT_DIR" && write_sha256_file "$archive_name" "$checksum_name")

  echo "created artifact: $OUTPUT_DIR/$archive_name"
  echo "created checksums: $OUTPUT_DIR/$checksum_name"
}

main "$@"
