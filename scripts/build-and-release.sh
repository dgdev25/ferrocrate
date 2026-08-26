#!/bin/bash
# FerroCrate Local Build & Release Script
# Builds, tests, signs, and releases binaries to GitHub Release
# Usage: ./scripts/build-and-release.sh <version>
# Example: ./scripts/build-and-release.sh v0.1.0

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_section() {
  echo -e "\n${BLUE}═══ $1 ═══${NC}\n"
}

# Check prerequisites
check_tools() {
  local missing_tools=()

  if ! command -v cargo &> /dev/null; then
    missing_tools+=(cargo)
  fi

  if ! command -v gh &> /dev/null; then
    missing_tools+=(gh)
  fi

  if ! command -v gpg &> /dev/null && ! command -v gpg2 &> /dev/null; then
    missing_tools+=(gpg)
  fi

  if ! command -v git &> /dev/null; then
    missing_tools+=(git)
  fi

  if [ ${#missing_tools[@]} -gt 0 ]; then
    log_error "Missing required tools: ${missing_tools[*]}"
    log_error "Install them and try again"
    exit 1
  fi

  log_info "All required tools found"
}

# Verify we're in the right directory
check_project_root() {
  if [ ! -f "Cargo.toml" ] || [ ! -d ".github/workflows" ]; then
    log_error "Not in ferrocrate root directory"
    exit 1
  fi
  log_info "In ferrocrate root directory"
}

# Validate version format
validate_version() {
  local version="$1"

  if ! [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]]; then
    log_error "Invalid version format: $version"
    log_error "Expected: v<major>.<minor>.<patch>[-prerelease]"
    exit 1
  fi

  log_info "Version format valid: $version"
}

# Run cargo fmt check
run_fmt_check() {
  log_section "Running cargo fmt check"

  if ! cargo fmt --all -- --check; then
    log_error "Code formatting issues found"
    log_warn "Run 'cargo fmt --all' to fix"
    exit 1
  fi

  log_info "Code formatting OK"
}

# Run clippy
run_clippy() {
  log_section "Running cargo clippy"

  if ! cargo clippy --all -- -D warnings; then
    log_error "Clippy warnings found"
    exit 1
  fi

  log_info "Clippy checks passed"
}

# Run tests
run_tests() {
  log_section "Running cargo test"

  if ! cargo test --all; then
    log_error "Tests failed"
    exit 1
  fi

  log_info "All tests passed"
}

# Build release artifacts
build_release() {
  log_section "Building release artifacts"

  rm -rf target/release/*.d target/release/deps/*.d

  if ! cargo build --release; then
    log_error "Build failed"
    exit 1
  fi

  log_info "Build succeeded"
}

# Create release artifacts directory
prepare_artifacts() {
  log_section "Preparing artifacts"

  local artifact_dir="release-artifacts"

  rm -rf "$artifact_dir"
  mkdir -p "$artifact_dir"

  # Copy binaries (or try, don't fail if not all exist)
  cp target/release/ferro-cli "$artifact_dir/" 2>/dev/null || true
  cp target/release/ferro-mind "$artifact_dir/" 2>/dev/null || true

  if [ -f "apps/ferro-desktop-ui/src-tauri/target/release/ferrocrate" ]; then
    cp "apps/ferro-desktop-ui/src-tauri/target/release/ferrocrate" "$artifact_dir/"
  fi

  local file_count=$(find "$artifact_dir" -type f | wc -l)

  if [ "$file_count" -eq 0 ]; then
    log_error "No binaries found in release artifacts"
    exit 1
  fi

  log_info "Found $file_count binary artifacts"
  ls -lh "$artifact_dir"
}

# Sign binaries
sign_artifacts() {
  log_section "Signing artifacts"

  local artifact_dir="release-artifacts"

  if [ -z "${FERROCRATE_GPG_KEY_ID:-}" ]; then
    log_warn "FERROCRATE_GPG_KEY_ID not set in environment"
    log_warn "Available GPG keys:"
    gpg --list-secret-keys --keyid-format short

    read -p "Enter GPG key ID to use for signing (or press Enter to skip): " key_id

    if [ -z "$key_id" ]; then
      log_warn "Skipping GPG signing"
      return 0
    fi
  else
    key_id="$FERROCRATE_GPG_KEY_ID"
  fi

  # Verify key exists
  if ! gpg --list-secret-keys "$key_id" &> /dev/null; then
    log_error "GPG key not found: $key_id"
    exit 1
  fi

  log_info "Signing with key: $key_id"

  cd "$artifact_dir"

  for file in *; do
    if [ -f "$file" ] && [ ! -f "${file}.asc" ]; then
      if gpg --default-key "$key_id" --detach-sign --armor "$file"; then
        log_info "Signed: $file"
      else
        log_error "Failed to sign: $file"
        cd - > /dev/null
        exit 1
      fi
    fi
  done

  cd - > /dev/null
}

# Generate checksums
generate_checksums() {
  log_section "Generating checksums"

  local artifact_dir="release-artifacts"
  cd "$artifact_dir"

  if command -v sha256sum &> /dev/null; then
    sha256sum * > SHA256SUMS.txt
  else
    shasum -a 256 * > SHA256SUMS.txt
  fi

  log_info "Checksums written to: SHA256SUMS.txt"
  cat SHA256SUMS.txt

  cd - > /dev/null
}

# Create git tag
create_tag() {
  local version="$1"

  log_section "Creating git tag"

  if git rev-parse "$version" &> /dev/null; then
    log_warn "Tag already exists: $version"
    return 0
  fi

  if ! git tag -a "$version" -m "Release $version"; then
    log_error "Failed to create tag"
    exit 1
  fi

  log_info "Tag created: $version"
}

# Push tag to GitHub
push_tag() {
  local version="$1"

  log_section "Pushing tag to GitHub"

  if ! git push origin "$version"; then
    log_error "Failed to push tag"
    exit 1
  fi

  log_info "Tag pushed: $version"
}

# Release to GitHub
release_to_github() {
  local version="$1"

  log_section "Creating GitHub Release"

  local artifact_dir="release-artifacts"

  if ! gh release view "$version" &> /dev/null; then
    if ! gh release create "$version" \
      --title "FerroCrate $version" \
      --notes "Release: $version" \
      "$artifact_dir"/*; then
      log_error "Failed to create GitHub release"
      exit 1
    fi
  else
    log_info "Release already exists: $version"
  fi

  log_info "GitHub release created/updated: $version"
}

# Main flow
main() {
  if [ $# -lt 1 ]; then
    echo "Usage: $0 <version>"
    echo ""
    echo "Example: $0 v0.1.0"
    echo ""
    echo "Environment variables (optional):"
    echo "  FERROCRATE_GPG_KEY_ID - GPG key ID for signing"
    exit 1
  fi

  local version="$1"

  log_section "FerroCrate Build & Release Pipeline"
  log_info "Version: $version"

  check_tools
  check_project_root
  validate_version "$version"

  run_fmt_check
  run_clippy
  run_tests
  build_release
  prepare_artifacts
  sign_artifacts
  generate_checksums
  create_tag "$version"

  log_section "Build Complete"
  log_info "Release artifacts ready in: release-artifacts/"
  log_info "Next: Review artifacts, then run: git push origin $version"
  log_info "Then: gh release view $version to see GitHub release"
}

main "$@"
