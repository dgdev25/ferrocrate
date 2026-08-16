#!/usr/bin/env bash
set -euo pipefail

CHANNEL="${CHANNEL:-}"
VERSION="${VERSION:-}"
ARTIFACT_DIR="${ARTIFACT_DIR:-dist/release}"
REQUIRE_SIGNATURES=0

usage() {
  cat <<USAGE
Usage: verify-release-channel-artifacts.sh --channel <public|paid> --version <tag> [--artifact-dir <path>] [--require-signatures]

Checks:
  - Expected checksum file exists and contains the packaged archive
  - Archive-bound provenance manifest matches the channel, version, archive, target, and digest
  - --require-signatures additionally verifies a detached GPG signature for the archive
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
      --require-signatures)
        REQUIRE_SIGNATURES=1
        shift
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

  local provenance_path="${archive_path}.provenance.json"
  [[ -f "$provenance_path" ]] || {
    echo "missing provenance manifest: $provenance_path" >&2
    exit 1
  }
  command -v python3 >/dev/null 2>&1 || {
    echo "release provenance verification requires python3" >&2
    exit 1
  }
  PROVENANCE_PATH="$provenance_path" \
    PROVENANCE_ARCHIVE="$archive" \
    PROVENANCE_VERSION="$VERSION" \
    PROVENANCE_CHANNEL="$CHANNEL" \
    PROVENANCE_ARTIFACT="$archive_path" \
    python3 - <<'PY'
import hashlib
import json
import os
import sys

path = os.environ["PROVENANCE_PATH"]
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, ValueError) as error:
    raise SystemExit(f"invalid provenance manifest: {error}")

expected = {
    "schema": "ferrocrate-release-provenance-v1",
    "archive": os.environ["PROVENANCE_ARCHIVE"],
    "version": os.environ["PROVENANCE_VERSION"],
    "channel": os.environ["PROVENANCE_CHANNEL"],
}
for key, value in expected.items():
    if data.get(key) != value:
        raise SystemExit(f"provenance mismatch for {key}: {data.get(key)!r} != {value!r}")
for key in ("target_os", "target_arch", "git_commit", "rustc"):
    if not isinstance(data.get(key), str) or not data[key]:
        raise SystemExit(f"provenance field is missing or empty: {key}")
if not isinstance(data.get("sha256"), str) or len(data["sha256"]) != 64:
    raise SystemExit("provenance sha256 must be a 64-character hexadecimal digest")
try:
    int(data["sha256"], 16)
except ValueError:
    raise SystemExit("provenance sha256 is not hexadecimal")

digest = hashlib.sha256()
with open(os.environ["PROVENANCE_ARTIFACT"], "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != data["sha256"]:
    raise SystemExit("provenance sha256 does not match archive bytes")
PY

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$ARTIFACT_DIR" && sha256sum --ignore-missing -c "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$ARTIFACT_DIR" && shasum -a 256 -c "$(basename "$checksum_file")")
  else
    echo "checksum verification requires sha256sum or shasum" >&2
    exit 1
  fi

  if ((REQUIRE_SIGNATURES)); then
    command -v gpg >/dev/null 2>&1 || {
      echo "--require-signatures needs gpg" >&2
      exit 1
    }
    [[ -f "${archive_path}.asc" ]] || {
      echo "missing detached signature: ${archive_path}.asc" >&2
      exit 1
    }
    gpg --verify "${archive_path}.asc" "$archive_path" >/dev/null || {
      echo "detached signature verification failed: ${archive_path}.asc" >&2
      exit 1
    }
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

  echo "release artifact verification passed (channel=${CHANNEL}, version=${VERSION}, signatures=${REQUIRE_SIGNATURES})"
}

main "$@"
