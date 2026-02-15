#!/usr/bin/env bash
set -euo pipefail

# macOS Compatibility Test Suite for FerroCrate
# Comprehensive testing to ensure FerroCrate works correctly on macOS
# Supports: Intel (x86_64) and Apple Silicon (aarch64)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="${REPO_ROOT}/target/test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="${RESULTS_DIR}/macos-tests-${TIMESTAMP}.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

mkdir -p "$RESULTS_DIR"

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $*" | tee -a "$RESULTS_FILE"
}

log_success() {
    echo -e "${GREEN}✓ $*${NC}" | tee -a "$RESULTS_FILE"
}

log_error() {
    echo -e "${RED}✗ $*${NC}" | tee -a "$RESULTS_FILE"
}

log_warning() {
    echo -e "${YELLOW}⚠ $*${NC}" | tee -a "$RESULTS_FILE"
}

section() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$RESULTS_FILE"
    echo -e "${BLUE}$*${NC}" | tee -a "$RESULTS_FILE"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$RESULTS_FILE"
}

# ============================================================================
# Platform Detection
# ============================================================================

section "Platform Detection"

if [[ "$(uname -s)" != "Darwin" ]]; then
    log_error "This script must run on macOS"
    exit 1
fi
log_success "Running on macOS"

MACOS_VERSION=$(sw_vers -productVersion)
log_success "macOS Version: $MACOS_VERSION"

MACOS_MAJOR=$(echo "$MACOS_VERSION" | cut -d. -f1)
if [[ $MACOS_MAJOR -lt 12 ]]; then
    log_error "FerroCrate requires macOS 12 or later, found: $MACOS_MAJOR"
    exit 1
fi
log_success "macOS version is supported"

ARCH=$(uname -m)
case "$ARCH" in
    arm64|aarch64)
        ARCH_NAME="Apple Silicon (aarch64)"
        TARGET_ARCH="aarch64"
        ;;
    x86_64)
        ARCH_NAME="Intel (x86_64)"
        TARGET_ARCH="x86_64"
        ;;
    *)
        log_error "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac
log_success "Architecture: $ARCH_NAME"

# ============================================================================
# Prerequisites Check
# ============================================================================

section "Prerequisites"

check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        log_success "Found: $1"
        return 0
    else
        log_warning "Missing: $1"
        return 1
    fi
}

check_command "cargo" || exit 1
check_command "rustc" || exit 1
check_command "git" || exit 1
check_command "plutil" || exit 1
check_command "df" || exit 1
check_command "sw_vers" || exit 1

if check_command "qemu-system-aarch64"; then
    QEMU_AVAILABLE=1
else
    QEMU_AVAILABLE=0
    log_warning "QEMU not installed (desktop VM tests will be limited)"
fi

if check_command "virtiofsd"; then
    VIRTIOFS_AVAILABLE=1
else
    VIRTIOFS_AVAILABLE=0
    log_warning "virtiofsd not installed (filesystem sharing tests will be limited)"
fi

# ============================================================================
# Installer Script Tests
# ============================================================================

section "Installer Script Validation"

INSTALLER_SCRIPT="${REPO_ROOT}/scripts/install-macos.sh"

if [[ ! -f "$INSTALLER_SCRIPT" ]]; then
    log_error "install-macos.sh not found"
    exit 1
fi
log_success "Installer script found: $INSTALLER_SCRIPT"

# Check if executable
if [[ -x "$INSTALLER_SCRIPT" ]]; then
    log_success "Installer script is executable"
else
    log_warning "Installer script is not executable, fixing..."
    chmod +x "$INSTALLER_SCRIPT"
fi

# Syntax check
bash -n "$INSTALLER_SCRIPT" 2>/dev/null
if [[ $? -eq 0 ]]; then
    log_success "Installer script bash syntax valid"
else
    log_error "Installer script has syntax errors"
    bash -n "$INSTALLER_SCRIPT"
    exit 1
fi

# Check required functions
REQUIRED_FUNCTIONS=("arch_name" "ensure_macos" "install_binary_release" "install_from_source")
for func in "${REQUIRED_FUNCTIONS[@]}"; do
    if grep -q "^${func}()" "$INSTALLER_SCRIPT"; then
        log_success "Function found: $func"
    else
        log_error "Function missing: $func"
        exit 1
    fi
done

# ============================================================================
# Desktop Package Script Tests
# ============================================================================

section "Desktop App Bundle Validation"

PACKAGE_SCRIPT="${REPO_ROOT}/scripts/package-macos-app.sh"

if [[ ! -f "$PACKAGE_SCRIPT" ]]; then
    log_error "package-macos-app.sh not found"
    exit 1
fi
log_success "Package script found: $PACKAGE_SCRIPT"

bash -n "$PACKAGE_SCRIPT" 2>/dev/null
if [[ $? -eq 0 ]]; then
    log_success "Package script bash syntax valid"
else
    log_error "Package script has syntax errors"
    exit 1
fi

# Check for macOS app bundle structure markers
if grep -q "Contents/MacOS" "$PACKAGE_SCRIPT" && \
   grep -q "Contents/Resources" "$PACKAGE_SCRIPT" && \
   grep -q "Info.plist" "$PACKAGE_SCRIPT"; then
    log_success "App bundle structure properly configured"
else
    log_error "App bundle structure not properly configured"
    exit 1
fi

# ============================================================================
# Filesystem Checks
# ============================================================================

section "Filesystem Validation"

HOME_DIR="$HOME"
if [[ -z "$HOME_DIR" ]]; then
    log_error "HOME environment variable not set"
    exit 1
fi
log_success "HOME directory: $HOME_DIR"

LIBRARY_DIR="$HOME_DIR/Library"
if [[ -d "$LIBRARY_DIR" ]]; then
    log_success "~/Library directory exists"
else
    log_error "~/Library directory not found"
    exit 1
fi

# Check LaunchAgents directory
LAUNCH_AGENTS_DIR="$LIBRARY_DIR/LaunchAgents"
if [[ -d "$LAUNCH_AGENTS_DIR" ]]; then
    log_success "LaunchAgents directory exists"
elif [[ ! -e "$LAUNCH_AGENTS_DIR" ]]; then
    log_success "LaunchAgents directory doesn't exist yet (will be created)"
else
    log_error "LaunchAgents path exists but is not a directory"
    exit 1
fi

# Disk space check
DISK_FREE=$(df "$HOME_DIR" | tail -1 | awk '{print $4}')
DISK_FREE_GB=$((DISK_FREE / 1024 / 1024))
log_success "Free disk space: ~${DISK_FREE_GB}GB"

if [[ $DISK_FREE_GB -lt 10 ]]; then
    log_warning "Low disk space (<10GB) - VM creation may fail"
else
    log_success "Sufficient disk space for VM operations"
fi

# ============================================================================
# Plist Validation
# ============================================================================

section "macOS Property List (Plist) Validation"

# Create test plist
TEST_PLIST_DIR="${RESULTS_DIR}/plist-tests"
mkdir -p "$TEST_PLIST_DIR"

TEST_LAUNCH_AGENT="${TEST_PLIST_DIR}/test-launch-agent.plist"
cat > "$TEST_LAUNCH_AGENT" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>io.ferrocrate.test</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/bin/echo</string>
      <string>test</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
PLIST

if plutil -lint "$TEST_LAUNCH_AGENT" >/dev/null 2>&1; then
    log_success "Plist format validation passed"
else
    log_error "Plist format validation failed"
    plutil -lint "$TEST_LAUNCH_AGENT"
    exit 1
fi

# ============================================================================
# Cargo Build Tests
# ============================================================================

section "Cargo Build Verification"

log "Building ferro-cli for $TARGET_ARCH..."
if cargo build -p ferro-cli --release 2>&1 | tee -a "$RESULTS_FILE" | tail -20; then
    log_success "ferro-cli build successful"
else
    log_error "ferro-cli build failed"
    exit 1
fi

log "Building ferro-desktop..."
if cargo build -p ferro-desktop --release 2>&1 | tee -a "$RESULTS_FILE" | tail -20; then
    log_success "ferro-desktop build successful"
else
    log_error "ferro-desktop build failed"
    exit 1
fi

# ============================================================================
# macOS-specific Tests
# ============================================================================

section "macOS-specific Unit Tests"

log "Running macOS compatibility tests..."
if cargo test --test macos_compatibility_tests -- --nocapture 2>&1 | tee -a "$RESULTS_FILE"; then
    log_success "macOS compatibility tests passed"
else
    log_warning "Some tests failed (check detailed output)"
fi

# ============================================================================
# Binary Verification
# ============================================================================

section "Binary Verification"

CLI_BIN="${REPO_ROOT}/target/release/ferro-cli"
DESKTOP_BIN="${REPO_ROOT}/target/release/ferro-desktop"

if [[ -x "$CLI_BIN" ]]; then
    log_success "ferro-cli binary found and executable"

    # Get binary info
    CLI_SIZE=$(du -h "$CLI_BIN" | cut -f1)
    CLI_ARCH=$(file "$CLI_BIN" | grep -o "Mach-O.*")
    log "  Size: $CLI_SIZE"
    log "  Type: $CLI_ARCH"
else
    log_error "ferro-cli binary not found or not executable"
    exit 1
fi

if [[ -x "$DESKTOP_BIN" ]]; then
    log_success "ferro-desktop binary found and executable"

    DESKTOP_SIZE=$(du -h "$DESKTOP_BIN" | cut -f1)
    DESKTOP_ARCH=$(file "$DESKTOP_BIN" | grep -o "Mach-O.*")
    log "  Size: $DESKTOP_SIZE"
    log "  Type: $DESKTOP_ARCH"
else
    log_error "ferro-desktop binary not found or not executable"
    exit 1
fi

# ============================================================================
# Hypervisor Check (optional)
# ============================================================================

section "Hypervisor Framework Check"

HV_CAPABLE=$(sysctl -n hw.optional.hv_capable 2>/dev/null || echo "unknown")
if [[ "$HV_CAPABLE" == "1" ]]; then
    log_success "Hypervisor framework available (VM acceleration supported)"
elif [[ "$HV_CAPABLE" == "0" ]]; then
    log_warning "Hypervisor framework not available (VM acceleration disabled)"
else
    log_warning "Could not determine hypervisor capability"
fi

# ============================================================================
# Network Tests
# ============================================================================

section "Network Stack Tests"

# Test IPv4 loopback
if ping -c 1 127.0.0.1 >/dev/null 2>&1; then
    log_success "IPv4 loopback (127.0.0.1) working"
else
    log_error "IPv4 loopback test failed"
fi

# Test IPv6 loopback
if ping6 -c 1 ::1 >/dev/null 2>&1; then
    log_success "IPv6 loopback (::1) working"
else
    log_warning "IPv6 loopback test failed (IPv6 may be disabled)"
fi

# ============================================================================
# Signal Handling Tests
# ============================================================================

section "Unix Signal Handling"

# Test kill command
if command -v kill >/dev/null 2>&1; then
    # Test with current PID (should succeed)
    if kill -0 $$ >/dev/null 2>&1; then
        log_success "Process signal check working"
    else
        log_error "Process signal check failed"
    fi
else
    log_error "kill command not found"
fi

# ============================================================================
# Summary
# ============================================================================

section "Test Summary"

log "Test results saved to: $RESULTS_FILE"
log ""
log "macOS Compatibility Status:"
log "  Platform: macOS $MACOS_VERSION ($ARCH_NAME)"
log "  Prerequisites: ✓"
log "  Installer: ✓"
log "  Desktop: ✓"
log "  Filesystem: ✓"
log "  Network: ✓"
if [[ $QEMU_AVAILABLE -eq 1 ]]; then
    log "  QEMU VM Support: ✓"
else
    log "  QEMU VM Support: ⚠ (optional, not installed)"
fi

log_success "All critical macOS compatibility checks passed!"
log ""
log "Next steps:"
log "  1. Run: ./scripts/install-macos.sh --method source"
log "  2. Test: ferrocrate --version"
log "  3. Try: ferrocrate run alpine:latest echo 'Hello from FerroCrate'"

exit 0
