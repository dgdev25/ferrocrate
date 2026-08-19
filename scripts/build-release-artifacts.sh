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

validate_version() {
  # Require a v-prefixed semantic version with no leading-zero numeric parts.
  if [[ ! "$VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    echo "invalid --version: $VERSION (expected vMAJOR.MINOR.PATCH[-prerelease][+build])" >&2
    exit 1
  fi
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
  validate_version
  if [[ "$CHANNEL" != "public" && "$CHANNEL" != "paid" ]]; then
    echo "invalid --channel: $CHANNEL (expected public or paid)" >&2
    exit 1
  fi

  require_cmd cargo
  require_cmd python3
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

  if [[ "$os" == "linux" && -n "${FERROCRATE_LINUX_GLIBC_BASELINE:-}" ]]; then
    bash "$(dirname -- "$0")/check-linux-binary-compat.sh" \
      "$cli_bin" "$FERROCRATE_LINUX_GLIBC_BASELINE"
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

  local provenance_name="${archive_name}.provenance.json"
  local archive_digest git_commit rustc_version
  archive_digest="$(awk 'NF >= 1 {print $1; exit}' "$OUTPUT_DIR/$checksum_name")"
  if ! git_commit="$(git rev-parse --verify HEAD 2>/dev/null)" ||
    [[ ! "$git_commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "release provenance requires a Git checkout with a verified HEAD commit" >&2
    echo "build from the tagged checkout; staging/source archives are not release inputs" >&2
    exit 1
  fi
  rustc_version="$(rustc --version 2>/dev/null || echo unknown)"
  PROVENANCE_PATH="$OUTPUT_DIR/$provenance_name" \
    PROVENANCE_VERSION="$VERSION" \
    PROVENANCE_CHANNEL="$CHANNEL" \
    PROVENANCE_ARCHIVE="$archive_name" \
    PROVENANCE_DIGEST="$archive_digest" \
    PROVENANCE_OS="$os" \
    PROVENANCE_ARCH="$arch" \
    PROVENANCE_COMMIT="$git_commit" \
    PROVENANCE_RUSTC="$rustc_version" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

payload = {
    "schema": "ferrocrate-release-provenance-v1",
    "version": os.environ["PROVENANCE_VERSION"],
    "channel": os.environ["PROVENANCE_CHANNEL"],
    "archive": os.environ["PROVENANCE_ARCHIVE"],
    "sha256": os.environ["PROVENANCE_DIGEST"],
    "target_os": os.environ["PROVENANCE_OS"],
    "target_arch": os.environ["PROVENANCE_ARCH"],
    "git_commit": os.environ["PROVENANCE_COMMIT"],
    "rustc": os.environ["PROVENANCE_RUSTC"],
}
path = Path(os.environ["PROVENANCE_PATH"])
temporary = path.with_suffix(path.suffix + ".tmp")
temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
temporary.replace(path)
PY

  echo "created artifact: $OUTPUT_DIR/$archive_name"
  echo "created checksums: $OUTPUT_DIR/$checksum_name"
  echo "created provenance: $OUTPUT_DIR/$provenance_name"
}

main "$@"
