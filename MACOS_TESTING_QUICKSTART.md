# macOS Testing Quick Start

**TL;DR** - Get FerroCrate tested on macOS in 5 minutes

## 1️⃣ Run Comprehensive Test Suite (Recommended)

```bash
cd /Users/lyle/dev/ferrocrate
bash scripts/test-macos-compatibility.sh
```

**What it does:**
- ✅ Verifies macOS 12+ (required)
- ✅ Detects architecture (Intel/Apple Silicon)
- ✅ Validates installer scripts
- ✅ Tests app bundle structure
- ✅ Checks filesystem health
- ✅ Builds both binaries
- ✅ Runs 31 unit tests
- ✅ Generates detailed report

**Expected output:** Green ✓ checks for all critical systems

**Report location:** `target/test-results/macos-tests-*.txt`

---

## 2️⃣ Run Unit Tests Only

```bash
# Run all tests
cargo test

# macOS-specific tests
cargo test --test macos_compatibility_tests -- --nocapture

# Desktop daemon tests
cargo test -p ferro-desktop
```

---

## 3️⃣ Verify Installation

### Option A: Source Install (Recommended for Development)

```bash
bash scripts/install-macos.sh --method source
```

### Option B: Binary Install

```bash
bash scripts/install-macos.sh --method binary --version latest
```

### Verify Installation

```bash
ferrocrate --version
ferrocrate ps
```

---

## 4️⃣ Test Desktop Daemon

```bash
# Generate launch agent
ferro-desktop autostart install-macos

# Validate with macOS
plutil -lint ~/Library/LaunchAgents/io.ferrocrate.desktop.plist

# Check content
cat ~/Library/LaunchAgents/io.ferrocrate.desktop.plist
```

---

## 5️⃣ Test VM Integration

```bash
# Initialize VM
ferro-desktop vm init \
  --backend qemu-hvf \
  --cpus 2 \
  --memory-mb 4096

# Check status
ferro-desktop vm status
```

*(QEMU required: `brew install qemu`)*

---

## 📊 Test Results Checklist

After running tests, verify:

- [ ] Platform Detection: ✓
- [ ] Architecture (aarch64 or x86_64): ✓
- [ ] macOS Version (12+): ✓
- [ ] Installer Scripts: ✓
- [ ] Desktop Package: ✓
- [ ] Filesystem: ✓
- [ ] Cargo Build: ✓
- [ ] Binary Verification: ✓
- [ ] Unit Tests Pass: ✓

---

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| "not on macOS" | This test suite only runs on macOS |
| "requires macOS 12+" | Update to macOS 12 or later |
| "qemu not found" | Run: `brew install qemu` |
| "virtiofsd not found" | Run: `brew install virtiofsd` (optional) |
| "permission denied" | Already fixed by setup, but try: `chmod +x scripts/*.sh` |

---

## 📝 Detailed Analysis

For comprehensive information, see: [`docs/MACOS_COMPATIBILITY_ANALYSIS.md`](docs/MACOS_COMPATIBILITY_ANALYSIS.md)

Covers:
- Component-by-component analysis
- Platform-specific code review
- Known limitations
- Future improvements
- Detailed troubleshooting

---

## ✅ Success Criteria

Your macOS testing is complete when:

1. ✅ `bash scripts/test-macos-compatibility.sh` exits with code 0
2. ✅ `cargo test` shows all tests passing
3. ✅ `ferrocrate --version` works
4. ✅ `ferro-desktop --help` displays options

---

## 🚀 Next Steps

After successful testing:

```bash
# Try running a container
ferrocrate run alpine:latest echo "Hello from FerroCrate on macOS!"

# Test compose
ferrocrate compose --help

# View logs
ferrocrate logs
```

---

## 📞 Need Help?

1. Check detailed analysis: `docs/MACOS_COMPATIBILITY_ANALYSIS.md`
2. Review test results: `target/test-results/macos-tests-*.txt`
3. Check specific test: `grep -A 5 "✗" target/test-results/macos-tests-*.txt`

---

**Last Updated:** 2026-02-15
**Status:** Ready for Testing ✅
