#!/usr/bin/env bash
set -euo pipefail

CHANNEL="${CHANNEL:-}"
VERSION="${VERSION:-}"
ARTIFACT_DIR="${ARTIFACT_DIR:-dist/release}"

usage() {
  cat <<USAGE
Usage: verify-release-channel-artifacts.sh --channel <public|paid> --version <tag> [--artifact-dir <path>]

Checks:
  - Expected checksum file exists and contains the packaged archive
  - Public channel archive contains CLI but not desktop binary
  - Paid channel archive contains both CLI and desktop binaries
USAGE
}

validate_version() {
  if [[ ! "$VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    echo "invalid --version: $VERSION (expected vMAJOR.MINOR.PATCH[-prerelease][+build])" >&2
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --channel)
        CHANNEL="${2:-}"
        shift 2
        ;;
      --version)
        VERSION="${2:-}"
        shift 2
        ;;
      --artifact-dir)
        ARTIFACT_DIR="${2:-}"
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

list_archive_entries() {
  local archive="$1"
  if [[ "$archive" == *.tar.gz ]]; then
    tar -tzf "$archive"
    return
  fi
  if [[ "$archive" == *.zip ]]; then
    if command -v unzip >/dev/null 2>&1; then
      unzip -Z -1 "$archive"
      return
    fi
    if command -v bsdtar >/dev/null 2>&1; then
      bsdtar -tf "$archive"
      return
    fi
    echo "zip archive inspection requires unzip or bsdtar" >&2
    exit 1
  fi
  echo "unsupported archive format: $archive" >&2
  exit 1
}

main() {
  parse_args "$@"

  if [[ "$CHANNEL" != "public" && "$CHANNEL" != "paid" ]]; then
    echo "invalid --channel: $CHANNEL (expected public or paid)" >&2
    exit 1
  fi
  if [[ -z "$VERSION" ]]; then
    echo "--version is required" >&2
    exit 1
  fi
  validate_version

  local checksum_file
  if [[ "$CHANNEL" == "public" ]]; then
    checksum_file="${ARTIFACT_DIR}/ferrocrate-${VERSION}-checksums.txt"
  else
    checksum_file="${ARTIFACT_DIR}/ferrocrate-${VERSION}-paid-checksums.txt"
  fi

  [[ -f "$checksum_file" ]] || {
    echo "missing checksum file: $checksum_file" >&2
    exit 1
  }

  local archive
  archive="$(awk 'NF >= 2 {print $2; exit}' "$checksum_file")"
  [[ -n "$archive" ]] || {
    echo "checksum file has no artifact entry: $checksum_file" >&2
    exit 1
  }

  local archive_path="${ARTIFACT_DIR}/${archive}"
  [[ -f "$archive_path" ]] || {
    echo "artifact listed in checksum file is missing: $archive_path" >&2
    exit 1
  }

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$ARTIFACT_DIR" && sha256sum --ignore-missing -c "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$ARTIFACT_DIR" && shasum -a 256 -c "$(basename "$checksum_file")")
  else
    echo "checksum verification requires sha256sum or shasum" >&2
    exit 1
  fi

  local entries
  entries="$(list_archive_entries "$archive_path")"

  echo "$entries" | grep -Eq '(^|/)ferrocrate(\.exe)?$' || {
    echo "artifact does not contain ferrocrate binary: $archive_path" >&2
    exit 1
  }

  if [[ "$CHANNEL" == "public" ]]; then
    if echo "$entries" | grep -Eq '(^|/)ferro-desktop(\.exe)?$'; then
      echo "public artifact must not contain ferro-desktop: $archive_path" >&2
      exit 1
    fi
  else
    echo "$entries" | grep -Eq '(^|/)ferro-desktop(\.exe)?$' || {
      echo "paid artifact must include ferro-desktop: $archive_path" >&2
      exit 1
    }
  fi

  echo "release artifact verification passed (channel=${CHANNEL}, version=${VERSION})"
}

main "$@"
