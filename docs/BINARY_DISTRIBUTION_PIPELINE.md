# FerroCrate Binary Distribution Pipeline

**Goal:** Users download ONE binary per platform → runs instantly. Zero friction.

---

## 1. Distribution Matrix

### Primary Targets (MVP)
```
Linux:
  ├─ x86_64 → AppImage (universal), .deb package
  └─ arm64  → AppImage (universal), .deb package

macOS:
  ├─ x86_64 → .dmg (Intel)
  └─ arm64  → .dmg (Apple Silicon)
  └─ universal → .dmg (both archs, 1 binary)

Windows:
  ├─ x86_64 → .msi installer, .exe portable
  └─ arm64  → .exe portable (future)
```

### Recommended MVP Start
- **Linux**: AppImage (single universal binary)
- **macOS**: Universal .dmg
- **Windows**: .msi (standard installer experience)

---

## 2. Build Pipeline Architecture

### Entry Point: Release Trigger
```
Trigger: Push tag v0.1.x to main
  ↓
GitHub Actions Matrix Build
  ├─ Linux build job (Ubuntu 24.04)
  ├─ macOS build job (macos-latest)
  └─ Windows build job (windows-latest)
  ↓
Upload artifacts to GitHub Release
  ↓
Sign binaries + Generate checksums
  ↓
Post to package managers
```

### Per-Platform Build Strategy

#### Linux (AppImage + .deb)
```yaml
Build Environment: ubuntu-24.04
Dependencies:
  - Build essentials (gcc, make, cargo)
  - Tauri deps (libsoup-3.0-dev, libwebkit2gtk-4.1-dev, etc)
  - AppImage runtime
  - checkinstall (for .deb generation)

Process:
  1. cargo build --release (ferro-cli + ferro-mind)
  2. npm install + npm run tauri:build (ferro-desktop-ui)
  3. Create AppImage with linuxdeploy
  4. Generate .deb package
  5. Create checksums (sha256)
  6. Sign binaries (GPG)

Artifacts:
  - ferrocrate-{version}-x86_64.AppImage
  - ferrocrate_{version}_amd64.deb
  - ferrocrate-{version}.amd64.sha256
```

#### macOS (Universal .dmg)
```yaml
Build Environment: macos-latest
Targets: x86_64, arm64

Process:
  1. Build x86_64 release
  2. Build arm64 release
  3. Create universal binary using lipo
  4. Code sign with Apple Developer certificate
  5. Create .dmg with create-dmg or appdmg
  6. Notarize with Apple (required for Sonoma+)
  7. Create checksums
  8. Sign

Artifacts:
  - ferrocrate-{version}-universal.dmg
  - ferrocrate-{version}.universal.sha256
```

#### Windows (.msi + portable)
```yaml
Build Environment: windows-latest
Target: x86_64

Process:
  1. cargo build --release
  2. npm run tauri:build
  3. Create .msi installer using WiX
  4. Create portable .exe
  5. Sign with Authenticode certificate
  6. Create checksums
  7. Virus scan (VirusTotal API)

Artifacts:
  - ferrocrate-{version}-x64-setup.msi
  - ferrocrate-{version}-x64-portable.exe
  - ferrocrate-{version}.x64.sha256
```

---

## 3. Distribution Channels

### Primary: GitHub Releases
```
https://github.com/dgtise25/ferrocrate/releases/tag/v0.1.x

├─ ferrocrate-0.1.0-x86_64.AppImage
├─ ferrocrate-0.1.0-x86_64.AppImage.sha256
├─ ferrocrate-0.1.0-x86_64.AppImage.sig (GPG)
├─ ferrocrate_0.1.0_amd64.deb
├─ ferrocrate-0.1.0-universal.dmg
├─ ferrocrate-0.1.0-universal.dmg.sha256
├─ ferrocrate-0.1.0-universal.dmg.sig
├─ ferrocrate-0.1.0-x64-setup.msi
├─ ferrocrate-0.1.0-x64-portable.exe
└─ CHECKSUMS.txt (all sha256 + signatures)
```

### Secondary: Package Managers

#### Homebrew (macOS/Linux)
```bash
brew install dgtise25/ferrocrate/ferrocrate
# or
brew tap dgtise25/ferrocrate
brew install ferrocrate
```

Create: `homebrew-ferrocrate` tap repo
```ruby
class Ferrocrate < Formula
  desc "AI-native container runtime"
  homepage "https://github.com/dgtise25/ferrocrate"
  url "https://github.com/dgtise25/ferrocrate/releases/download/v#{version}/ferrocrate-#{version}-universal.dmg"
  sha256 "..."

  def install
    app.install "Ferrocrate.app"
  end
end
```

#### Debian/Ubuntu (.deb)
```bash
curl -fsSL https://ferrocrate.sh/setup.sh | sudo sh
# or manual
sudo apt-add-repository ppa:dgtise25/ferrocrate
sudo apt-get update
sudo apt-get install ferrocrate
```

Or: GitHub Package Registry (automatic)

#### Windows (Chocolatey/Winget)
```powershell
choco install ferrocrate
# or
winget install dgtise25.ferrocrate
```

#### Snap (Linux universal)
```bash
sudo snap install ferrocrate
```

---

## 4. Release Workflow

### Pre-Release Checklist
```
[ ] All tests passing on main
[ ] Update CHANGELOG.md
[ ] Bump version (Cargo.toml, package.json)
[ ] Update docs (README, getting-started)
[ ] Create release notes (features/breaking changes)
[ ] Security audit complete
```

### Release Process
```
1. Create annotated tag
   git tag -a v0.1.0 -m "Release 0.1.0"

2. Push tag
   git push origin v0.1.0

3. GitHub Actions triggered
   └─ Builds all platform binaries
   └─ Generates checksums & signs
   └─ Creates draft release

4. Manual review
   [ ] Verify all artifacts present
   [ ] Check signatures valid
   [ ] Test one binary per platform
   [ ] Update release notes

5. Publish release
   └─ Marks as latest

6. Post-release
   [ ] Update package manager repos
   [ ] Update installation docs
   [ ] Announce on social media
```

---

## 5. Signing & Verification

### GPG Signing
```bash
# Generate key (per platform/maintainer)
gpg --generate-key

# Sign each binary
gpg --detach-sign --armor ferrocrate-0.1.0-x86_64.AppImage

# Verify
gpg --verify ferrocrate-0.1.0-x86_64.AppImage.sig
```

**Store GPG key in:**
- GitHub Organization secrets (deploy key)
- 1Password/Vault (backup)

### Code Signing

#### macOS
- Apple Developer certificate
- Notarization (Apple's malware check)
- Gatekeeper friendly

#### Windows
- Authenticode certificate (DigiCert, Sectigo)
- VirusTotal scan before release

---

## 6. Checksum & Integrity

### CHECKSUMS.txt format
```
# SHA256 checksums for ferrocrate v0.1.0
# Generated: 2024-02-16

e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ferrocrate-0.1.0-x86_64.AppImage
d41d8cd98f00b204e9800998ecf8427e  ferrocrate-0.1.0-universal.dmg
abcdef1234567890...  ferrocrate-0.1.0-x64-setup.msi
```

**Verification script** (`install.sh`):
```bash
#!/bin/bash
# Verify download integrity before running

BINARY=$1
EXPECTED_SHA=$(grep "$BINARY" CHECKSUMS.txt | cut -d' ' -f1)
ACTUAL_SHA=$(sha256sum "$BINARY" | cut -d' ' -f1)

if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    echo "❌ Checksum mismatch! File may be corrupted."
    exit 1
fi

echo "✓ Checksum verified"
chmod +x "$BINARY"
./"$BINARY"
```

---

## 7. Installation Script

### One-liner installer (`ferrocrate.sh`)
```bash
#!/bin/bash
# Universal installer - detects OS and downloads appropriate binary

RELEASE_URL="https://api.github.com/repos/dgtise25/ferrocrate/releases/latest"

case "$(uname -s)" in
  Linux*)
    ARCH=$(uname -m)
    BINARY="ferrocrate-$(curl -s $RELEASE_URL | jq -r .tag_name)-$ARCH.AppImage"
    ;;
  Darwin*)
    BINARY="ferrocrate-$(curl -s $RELEASE_URL | jq -r .tag_name)-universal.dmg"
    ;;
  MINGW*|CYGWIN*)
    BINARY="ferrocrate-$(curl -s $RELEASE_URL | jq -r .tag_name)-x64-setup.msi"
    ;;
esac

echo "📦 Downloading $BINARY..."
curl -L -O "https://github.com/dgtise25/ferrocrate/releases/latest/download/$BINARY"

echo "✓ Installation complete. Run: ./$BINARY"
```

**Usage:**
```bash
curl -fsSL https://ferrocrate.sh/install.sh | bash
```

---

## 8. Continuous Delivery Automation

### GitHub Actions Workflow (`.github/workflows/release-build.yml`)

```yaml
name: Build Release Binaries

on:
  push:
    tags:
      - 'v*'

jobs:
  build-linux:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Install Linux dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libsoup-3.0-dev libwebkit2gtk-4.1-dev ...

      - name: Build release
        run: |
          cargo build --release
          cd apps/ferro-desktop-ui && npm install && npm run tauri:build

      - name: Create AppImage
        run: # ... linuxdeploy commands

      - name: Sign and checksum
        run: |
          gpg --detach-sign ferrocrate-*.AppImage
          sha256sum ferrocrate-* > CHECKSUMS.txt

      - name: Upload artifacts
        uses: softprops/action-gh-release@v1
        with:
          files: ferrocrate-*

  build-macos:
    runs-on: macos-latest
    # ... similar matrix build for Intel + Apple Silicon

  build-windows:
    runs-on: windows-latest
    # ... Windows .msi + .exe build
```

---

## 9. Success Metrics

```
✓ Users download binary → runs immediately (< 5 min setup)
✓ One binary per platform (no compilation needed)
✓ Signed & verified (checksum validation)
✓ Auto-updates via package managers
✓ Clear installation documentation
✓ < 100MB binary size (lightweight)
```

---

## 10. Phased Rollout

### Phase 1 (MVP - Week 1)
- Linux AppImage
- macOS universal .dmg
- Windows .msi
- GitHub Releases only
- Manual sign-off on each release

### Phase 2 (Week 2-3)
- Homebrew tap
- Debian PPA
- GitHub Package Registry
- Auto-generated release notes

### Phase 3 (Week 4+)
- Chocolatey/Winget
- Snap store
- Auto-updates within app
- Version checking

---

## 11. Future: Self-Updating

Once binaries are distributed, add auto-update within app:

```rust
// In ferro-desktop-ui/src-tauri backend
#[tauri::command]
async fn check_for_updates() -> Result<UpdateInfo> {
    let latest = fetch_github_releases().await?;
    Ok(UpdateInfo {
        version: latest.tag_name,
        url: latest.assets[0].browser_download_url,
        checksum: verify_latest_checksum().await?,
    })
}
```

---

## Files to Create

```
.github/workflows/
├─ release-build.yml          # Matrix build for all platforms
└─ release-publish.yml        # Publish to package managers

scripts/
├─ build-appimage.sh          # Linux AppImage builder
├─ build-dmg.sh               # macOS .dmg builder
├─ build-msi.ps1              # Windows .msi builder
├─ sign-binaries.sh            # GPG/Authenticode signing
└─ install.sh                  # Universal installer

docs/
├─ INSTALLATION.md             # User setup guide
├─ BINARY_DISTRIBUTION.md      # This file
└─ DEVELOPER_BUILD.md          # For source builds

homebrew-ferrocrate/
└─ Formula/ferrocrate.rb       # Homebrew formula
```

---

## Timeline

| Week | Milestone |
|------|-----------|
| 1 | GitHub Releases + installer script |
| 2 | Homebrew + .deb support |
| 3 | Chocolatey/Winget |
| 4 | Snap store |
| 5 | In-app auto-updates |

---

## Success Criteria

```
✅ "I want to try FerroCrate"
   → Download binary (< 30 seconds)
   → Run binary (< 1 second)
   → Works instantly

✅ Distribution parity with Docker
   → Multiple download options
   → Package manager support
   → One-liner installer

✅ Security + Integrity
   → Signed binaries
   → Verified checksums
   → Source transparency
```
