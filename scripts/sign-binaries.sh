#!/bin/bash
# FerroCrate Binary Signing Script
# Signs release binaries with GPG and generates checksums
# Prerequisites: GPG installed and configured with a signing key

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
  echo -e "${GREEN}✓${NC} $1"
}

log_error() {
  echo -e "${RED}✗${NC} $1" >&2
}

log_warn() {
  echo -e "${YELLOW}⚠${NC} $1"
}

# Check prerequisites
check_tools() {
  local missing_tools=()

  if ! command -v gpg &> /dev/null && ! command -v gpg2 &> /dev/null; then
    missing_tools+=("gpg")
  fi

  if ! command -v sha256sum &> /dev/null && ! command -v shasum &> /dev/null; then
    missing_tools+=("sha256sum")
  fi

  if [ ${#missing_tools[@]} -gt 0 ]; then
    log_error "Missing required tools: ${missing_tools[*]}"
    exit 1
  fi

  log_info "All required tools found"
}

# Get GPG key ID from environment or user input
get_gpg_key() {
  local key_id

  if [ -n "${FERROCRATE_GPG_KEY_ID:-}" ]; then
    key_id="$FERROCRATE_GPG_KEY_ID"
    log_info "Using GPG key from environment: $key_id" >&2
  else
    log_warn "No GPG_KEY_ID in environment. Available keys:" >&2
    gpg --list-secret-keys --keyid-format short

    echo ""
    read -p "Enter GPG key ID to use for signing: " key_id

    if [ -z "$key_id" ]; then
      log_error "No key ID provided"
      exit 1
    fi
  fi

  echo "$key_id"
}

# Verify GPG key exists and is usable
verify_gpg_key() {
  local key_id="$1"

  if ! gpg --list-secret-keys "$key_id" &> /dev/null; then
    log_error "GPG key not found: $key_id"
    exit 1
  fi

  log_info "GPG key verified: $key_id"
}

# Sign a single binary
sign_binary() {
  local binary key_id

  binary="$1"
  key_id="$2"

  if [ ! -f "$binary" ]; then
    log_error "Binary not found: $binary"
    return 1
  fi

  log_info "Signing: $binary"

  # Create detached signature
  if ! gpg --batch --yes --default-key "$key_id" --detach-sign --armor "$binary"; then
    log_error "Failed to sign: $binary"
    return 1
  fi

  if [ -f "${binary}.asc" ]; then
    log_info "Signature created: ${binary}.asc"
  else
    log_error "Signature file not created"
    return 1
  fi
}

# Generate checksums for all files
generate_checksums() {
  local artifact_dir checksum_file

  artifact_dir="$1"

  if [ ! -d "$artifact_dir" ]; then
    log_error "Artifact directory not found: $artifact_dir"
    exit 1
  fi

  checksum_file="${artifact_dir}/CHECKSUMS.txt"

  log_info "Generating checksums..."

  # Generate SHA256 checksums for payloads and detached signatures, excluding
  # the checksum file itself so it is deterministic and never self-referential.
  cd "$artifact_dir"

  local files=() file
  for file in *; do
    if [ -f "$file" ] && [ "$file" != "CHECKSUMS.txt" ]; then
      files+=("$file")
    fi
  done
  if [ "${#files[@]}" -eq 0 ]; then
    log_error "No artifact payloads found in $artifact_dir"
    return 1
  fi
  if command -v sha256sum &> /dev/null; then
    sha256sum "${files[@]}" > "$checksum_file"
  else
    shasum -a 256 "${files[@]}" > "$checksum_file"
  fi

  cd - > /dev/null

  log_info "Checksums written to: $checksum_file"
  cat "$checksum_file"
}

# Verify signatures (for testing)
verify_signatures() {
  local artifact_dir

  artifact_dir="$1"

  log_info "Verifying signatures..."

  cd "$artifact_dir"
  local found=0 failed=0 sig_file binary
  shopt -s nullglob
  for sig_file in *.asc; do
    found=1
    binary="${sig_file%.asc}"
    if gpg --verify "$sig_file" "$binary" >/dev/null 2>&1; then
      log_info "✓ Signature valid: $sig_file"
    else
      log_error "✗ Signature invalid: $sig_file"
      failed=1
    fi
  done
  shopt -u nullglob
  cd - > /dev/null
  if [ "$found" -eq 0 ]; then
    log_error "No detached signatures found in $artifact_dir"
    return 1
  fi
  return "$failed"
}

# Main flow
main() {
  local artifact_dir key_id

  if [ $# -lt 1 ]; then
    echo "Usage: $0 <artifact-directory> [--verify-only]"
    echo ""
    echo "Examples:"
    echo "  $0 ./release-artifacts"
    echo "  $0 ./release-artifacts --verify-only"
    echo ""
    echo "Environment variables:"
    echo "  FERROCRATE_GPG_KEY_ID - GPG key ID to use for signing"
    exit 1
  fi

  artifact_dir="$1"
  verify_only="${2:-}"

  check_tools

  if [ "$verify_only" = "--verify-only" ]; then
    verify_signatures "$artifact_dir"
    exit 0
  fi

  key_id=$(get_gpg_key)
  verify_gpg_key "$key_id"

  # Sign every payload (except signatures and checksums). A signing failure is
  # fatal; release automation must never publish a partially signed channel.
  cd "$artifact_dir"
  for file in *; do
    if [ ! -f "$file" ] || [ "$file" = "CHECKSUMS.txt" ] || [[ "$file" == *.asc ]]; then
      continue
    fi
    sign_binary "$file" "$key_id"
  done
  cd - > /dev/null

  generate_checksums "$artifact_dir"

  log_info "Signing complete!"
  log_info "Artifacts in: $artifact_dir"
  log_info ""
  log_info "To verify signatures later, run:"
  echo "  $0 $artifact_dir --verify-only"
}

main "$@"
