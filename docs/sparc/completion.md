# FerroCrate Completion

**SPARC Phase:** Completion
**Version:** 1.0
**Date:** February 11, 2026
**Status:** Draft

---

## 1. Build System

### 1.1 Cargo Workspace Configuration

```toml
# Cargo.toml (workspace root)
[workspace]
resolver = "2"
members = [
    "crates/ferro-exec",
    "crates/ferro-store",
    "crates/ferro-build",
    "crates/ferro-net",
    "crates/ferro-mind",
    "crates/ferro-compose",
    "crates/ferro-mgr",
    "cli",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
repository = "https://github.com/ferrocrate/ferrocrate"
rust-version = "1.75"

[workspace.dependencies]
# Internal crates
ferro-exec = { path = "crates/ferro-exec" }
ferro-store = { path = "crates/ferro-store" }
ferro-build = { path = "crates/ferro-build" }
ferro-net = { path = "crates/ferro-net" }
ferro-mind = { path = "crates/ferro-mind" }
ferro-compose = { path = "crates/ferro-compose" }

# Shared dependencies
nix = { version = "0.27", features = ["process", "mount", "sched", "signal", "user"] }
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
thiserror = "1.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
clap = { version = "4.4", features = ["derive", "env"] }
blake3 = "1.5"
oci-spec = "0.6"
reqwest = { version = "0.11", features = ["json", "stream"] }
zstd = "0.13"
tempfile = "3.9"
```

### 1.2 Build Profiles

```toml
# Cargo.toml (workspace root)

[profile.dev]
opt-level = 0
debug = true
split-debuginfo = "packed"

[profile.release]
opt-level = "z"      # Optimize for size
lto = true           # Link-time optimization
codegen-units = 1    # Better optimization
panic = "abort"      # Smaller binary
strip = true         # Strip symbols

[profile.release-minimal]
inherits = "release"
opt-level = "z"

[profile.release-full]
inherits = "release"
opt-level = 3        # More speed, larger binary
```

### 1.3 Build Commands

```bash
# Development build (fast compilation)
cargo build

# Release build (optimized)
cargo build --release

# Minimal tier (smallest binary, no AI)
cargo build --release --no-default-features --features minimal

# Standard tier (AI via WASM only)
cargo build --release --features standard

# Full tier (all AI features)
cargo build --release --features full

# Cross-compilation for aarch64
cargo build --release --target aarch64-unknown-linux-gnu

# Cross-compilation for riscv64
cargo build --release --target riscv64gc-unknown-linux-gnu
```

---

## 2. Cross-Compilation

### 2.1 Target Platforms

| Target | Tier | Use Case |
|--------|------|----------|
| x86_64-unknown-linux-gnu | Primary | Servers, desktops |
| aarch64-unknown-linux-gnu | Primary | ARM servers, Raspberry Pi |
| riscv64gc-unknown-linux-gnu | Secondary | RISC-V boards |
| x86_64-unknown-linux-musl | Primary | Static binary, Alpine |

### 2.2 Cross-Compilation Setup

```bash
# Install cross-compilation toolchains
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-gnu
rustup target add riscv64gc-unknown-linux-gnu

# Install cross (recommended for complex builds)
cargo install cross

# Alternative: Install native toolchains
# Ubuntu/Debian:
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
sudo apt-get install gcc-riscv64-linux-gnu g++-riscv64-linux-gnu

# Configure cargo for cross-compilation
# .cargo/config.toml
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"

[target.riscv64gc-unknown-linux-gnu]
linker = "riscv64-linux-gnu-gcc"
```

### 2.3 Cross-Compilation with Docker

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      matrix:
        target:
          - x86_64-unknown-linux-gnu
          - x86_64-unknown-linux-musl
          - aarch64-unknown-linux-gnu
          - riscv64gc-unknown-linux-gnu
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
          - target: x86_64-unknown-linux-musl
            os: ubuntu-latest
            use_cross: true
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
            use_cross: true
          - target: riscv64gc-unknown-linux-gnu
            os: ubuntu-latest
            use_cross: true

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          target: ${{ matrix.target }}

      - name: Build
        run: |
          if [ "${{ matrix.use_cross }}" == "true" ]; then
            cargo install cross
            cross build --release --target ${{ matrix.target }}
          else
            cargo build --release --target ${{ matrix.target }}
          fi

      - name: Package
        run: |
          mkdir -p release
          cp target/${{ matrix.target }}/release/ferrocrate release/
          tar -czvf ferrocrate-${{ matrix.target }}.tar.gz -C release .

      - uses: actions/upload-artifact@v4
        with:
          name: ferrocrate-${{ matrix.target }}
          path: ferrocrate-${{ matrix.target }}.tar.gz
```

---

## 3. Release Artifacts

### 3.1 Artifact Structure

```
ferrocrate-v1.0.0/
├── ferrocrate-v1.0.0-x86_64-linux-gnu.tar.gz
│   └── ferrocrate              # ~12 MB
├── ferrocrate-v1.0.0-x86_64-linux-musl.tar.gz
│   └── ferrocrate              # ~10 MB (static)
├── ferrocrate-v1.0.0-aarch64-linux-gnu.tar.gz
│   └── ferrocrate              # ~11 MB
├── ferrocrate-v1.0.0-riscv64-linux-gnu.tar.gz
│   └── ferrocrate              # ~14 MB
├── ferrocrate-minimal-v1.0.0-x86_64-linux-musl.tar.gz
│   └── ferrocrate              # ~5 MB (no AI)
├── checksums.sha256
└── checksums.sha256.sig        # GPG signature
```

### 3.2 Checksum Generation

```bash
# Generate checksums
sha256sum ferrocrate-*.tar.gz > checksums.sha256

# GPG sign
gpg --armor --detach-sign checksums.sha256

# Verify
sha256sum -c checksums.sha256
gpg --verify checksums.sha256.sig
```

### 3.3 Release Script

```bash
#!/bin/bash
# scripts/release.sh

set -e

VERSION=${1:-$(cargo pkgid | cut -d@ -f2)}
echo "Creating release v${VERSION}"

# Build all targets
./scripts/build-all-targets.sh

# Generate checksums
cd release
sha256sum ferrocrate-*.tar.gz > checksums.sha256

# Sign checksums
gpg --armor --detach-sign checksums.sha256

# Create GitHub release
gh release create "v${VERSION}" \
    --title "FerroCrate v${VERSION}" \
    --notes-file ../RELEASE_NOTES.md \
    ferrocrate-*.tar.gz \
    checksums.sha256 \
    checksums.sha256.sig

echo "Release v${VERSION} created successfully!"
```

---

## 4. Installation Methods

### 4.1 Binary Download

```bash
# Download latest release
curl -sL https://github.com/ferrocrate/ferrocrate/releases/latest/download/ferrocrate-$(uname -m)-linux-gnu.tar.gz | tar xz

# Move to PATH
sudo mv ferrocrate /usr/local/bin/

# Verify installation
ferrocrate --version
```

### 4.2 Install Script

```bash
#!/bin/bash
# https://get.ferrocrate.dev

set -e

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)  TARGET="x86_64-linux-gnu" ;;
    aarch64) TARGET="aarch64-linux-gnu" ;;
    riscv64) TARGET="riscv64gc-unknown-linux-gnu" ;;
    *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Detect libc
if ldd --version 2>&1 | grep -q musl; then
    TARGET="${TARGET/gnu/musl}"
fi

# Download URL
DOWNLOAD_URL="https://github.com/ferrocrate/ferrocrate/releases/latest/download/ferrocrate-${TARGET}.tar.gz"

# Download and extract
echo "Downloading FerroCrate for ${TARGET}..."
curl -sL "$DOWNLOAD_URL" | tar xz

# Install
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
sudo mv ferrocrate "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/ferrocrate"

# Install shell completions
ferrocrate completions bash | sudo tee /etc/bash_completion.d/ferrocrate > /dev/null
ferrocrate completions zsh | sudo tee /usr/local/share/zsh/site-functions/_ferrocrate > /dev/null
ferrocrate completions fish | sudo tee /usr/share/fish/completions/ferrocrate.fish > /dev/null

echo "FerroCrate installed successfully!"
echo "Run 'ferrocrate --help' to get started."
```

### 4.3 Package Managers

#### Homebrew (macOS/Linux)
```ruby
# Formula: ferrocrate.rb
class Ferrocrate < Formula
  desc "AI-native container runtime"
  homepage "https://ferrocrate.dev"
  version "1.0.0"

  on_macos do
    # Uses a lightweight VM for macOS
    url "https://github.com/ferrocrate/ferrocrate/releases/download/v#{version}/ferrocrate-darwin.tar.gz"
    sha256 "..."
  end

  on_linux do
    on_intel do
      url "https://github.com/ferrocrate/ferrocrate/releases/download/v#{version}/ferrocrate-x86_64-linux-gnu.tar.gz"
      sha256 "..."
    end

    on_arm do
      url "https://github.com/ferrocrate/ferrocrate/releases/download/v#{version}/ferrocrate-aarch64-linux-gnu.tar.gz"
      sha256 "..."
    end
  end

  def install
    bin.install "ferrocrate"
    generate_completions_from_executable(bin/"ferrocrate", "completions")
  end

  test do
    assert_match "FerroCrate", shell_output("#{bin}/ferrocrate --version")
  end
end
```

#### AUR (Arch Linux)
```bash
# PKGBUILD
pkgname=ferrocrate-bin
pkgver=1.0.0
pkgrel=1
pkgdesc="AI-native container runtime"
arch=('x86_64' 'aarch64')
url="https://ferrocrate.dev"
license=('MIT' 'Apache')

source_x86_64=("https://github.com/ferrocrate/ferrocrate/releases/download/v${pkgver}/ferrocrate-x86_64-linux-gnu.tar.gz")
source_aarch64=("https://github.com/ferrocrate/ferrocrate/releases/download/v${pkgver}/ferrocrate-aarch64-linux-gnu.tar.gz")

package() {
    install -Dm755 ferrocrate "${pkgdir}/usr/bin/ferrocrate"
    install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/ferrocrate/LICENSE"
}
```

#### Nix
```nix
# default.nix
{ lib, fetchFromGitHub, rustPlatform }:

rustPlatform.buildRustPackage rec {
  pname = "ferrocrate";
  version = "1.0.0";

  src = fetchFromGitHub {
    owner = "ferrocrate";
    repo = "ferrocrate";
    rev = "v${version}";
    sha256 = "...";
  };

  cargoSha256 = "...";

  meta = with lib; {
    description = "AI-native container runtime";
    homepage = "https://ferrocrate.dev";
    license = with licenses; [ mit asl20 ];
    platforms = platforms.linux;
  };
}
```

### 4.4 Cargo Install

```bash
# Install from crates.io
cargo install ferrocrate

# Install from git
cargo install --git https://github.com/ferrocrate/ferrocrate

# Install specific version
cargo install ferrocrate --version 1.0.0

# Install with specific features
cargo install ferrocrate --features full
```

---

## 5. Post-Installation Setup

### 5.1 Rootless Configuration

```bash
# Enable rootless mode (required for non-root users)
# Check subuid/subgid
cat /etc/subuid
cat /etc/subgid

# Expected output:
# <username>:100000:65536

# If not present, add:
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER

# Setup sysctls for rootless
sudo sysctl -w kernel.unprivileged_userns_clone=1
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"

# Persistent sysctls
echo "kernel.unprivileged_userns_clone=1" | sudo tee /etc/sysctl.d/99-ferrocrate.conf
echo "net.ipv4.ping_group_range=0 2147483647" | sudo tee -a /etc/sysctl.d/99-ferrocrate.conf
```

### 5.2 Shell Completions

```bash
# Bash
ferrocrate completions bash | sudo tee /etc/bash_completion.d/ferrocrate

# Zsh
ferrocrate completions zsh | sudo tee /usr/local/share/zsh/site-functions/_ferrocrate

# Fish
ferrocrate completions fish | sudo tee /usr/share/fish/completions/ferrocrate.fish

# Elvish
ferrocrate completions elvish > ~/.local/share/elvish/completions/ferrocrate.elv
```

### 5.3 Configuration File

```toml
# ~/.config/ferrocrate/config.toml

[storage]
# Image and container storage location
data_root = "~/.local/share/ferrocrate"

# Content-addressable storage
cas_path = "~/.local/share/ferrocrate/cas"

[network]
# Default network bridge
default_bridge = "ferrob0"

# Default subnet for containers
default_subnet = "172.17.0.0/16"

# DNS servers for containers
dns_servers = ["8.8.8.8", "8.8.4.4"]

[security]
# Run rootless by default
rootless = true

# Drop all capabilities by default
drop_all_capabilities = true

# Enforce no-new-privileges
no_new_privileges = true

# Default seccomp profile
seccomp_profile = "default"

[ai]
# Enable AI features
enabled = true

# AI tier: wasm, local-llm, claude-api
default_tier = "wasm"

# Enable intelligent restart
intelligent_restart = true

# Enable resource prediction
resource_prediction = true

[logging]
# Log level: trace, debug, info, warn, error
level = "info"

# Log format: json, text
format = "json"

# Log file (optional)
# file = "/var/log/ferrocrate.log"
```

---

## 6. Docker Compatibility Layer

### 6.1 Socket Emulation

FerroCrate can emulate the Docker socket for compatibility with existing tooling:

```bash
# Start Docker-compatible API server
ferrocrate daemon --listen unix:///var/run/docker.sock

# Or with a different socket
ferrocrate daemon --listen unix:///var/run/ferrocrate.sock

# Use with Docker CLI
docker -H unix:///var/run/ferrocrate.sock ps

# Use with docker-compose
DOCKER_HOST=unix:///var/run/ferrocrate.sock docker-compose up
```

### 6.2 Supported Docker API Endpoints

| Endpoint | Support | Notes |
|----------|---------|-------|
| `/containers/json` | Full | List containers |
| `/containers/create` | Full | Create container |
| `/containers/{id}/start` | Full | Start container |
| `/containers/{id}/stop` | Full | Stop container |
| `/containers/{id}/logs` | Full | Get logs |
| `/containers/{id}/exec` | Full | Exec in container |
| `/images/json` | Full | List images |
| `/images/create` | Full | Pull image |
| `/build` | Full | Build image |
| `/version` | Full | Version info |
| `/info` | Full | System info |
| `/events` | Full | Event stream |
| `/networks/*` | Partial | Basic network support |
| `/volumes/*` | Partial | Basic volume support |

---

## 7. Migration from Docker

### 7.1 Migration Tool

```bash
# Scan Docker installation and generate FerroCrate config
ferrocrate migrate --output ferrocrate-migration.toml

# Preview migration plan
ferrocrate migrate --dry-run

# Execute migration
ferrocrate migrate --execute

# Import Docker images
ferrocrate migrate --import-images

# Import Docker volumes
ferrocrate migrate --import-volumes
```

### 7.2 Migration Output Example

```toml
# ferrocrate-migration.toml
# Generated by ferrocrate migrate
# Source: Docker 24.0.7

[containers]
# Running containers at time of migration
# Note: Containers need to be recreated

[[containers.running]]
name = "web-server"
image = "nginx:latest"
ports = ["8080:80"]
volumes = ["/data/web:/usr/share/nginx/html"]
restart = "always"

[[images]]
source = "nginx:latest"
action = "pull"  # Will pull from registry

[[images]]
source = "my-custom-app:latest"
action = "export"  # Will export from Docker

[[volumes]]
name = "postgres-data"
action = "copy"  # Will copy data

[[networks]]
name = "app-network"
subnet = "172.18.0.0/16"
```

---

## 8. Deployment Checklist

### 8.1 Pre-Deployment

- [ ] Verify kernel version >= 5.10
- [ ] Verify cgroup v2 is mounted
- [ ] Verify OverlayFS is available
- [ ] Configure subuid/subgid for rootless
- [ ] Set required sysctls
- [ ] Install shell completions
- [ ] Create configuration file
- [ ] Test basic container operations

### 8.2 Production Deployment

- [ ] Review security configuration
- [ ] Configure logging and monitoring
- [ ] Set up Prometheus metrics endpoint
- [ ] Configure log rotation
- [ ] Test backup/restore procedures
- [ ] Document custom configurations
- [ ] Train operations team

### 8.3 Validation Tests

```bash
# Run validation suite
ferrocrate doctor

# Expected output:
# [OK] Kernel version: 6.1.0 (>= 5.10 required)
# [OK] cgroup v2: mounted at /sys/fs/cgroup
# [OK] OverlayFS: supported
# [OK] eBPF: supported (kernel >= 5.10)
# [OK] User namespaces: enabled
# [OK] Rootless mode: configured (subuid: 100000-165535)
# [OK] Network bridge: ferrob0 ready
# [OK] Storage: /var/lib/ferrocrate (50GB available)
# [OK] AI features: enabled (WASM tier)
```

---

## 9. Entry/Exit Criteria

### Phase 5: Completion (Current)

**Entry Criteria:**
- [x] Refinement phase complete
- [x] All tests passing
- [x] Performance benchmarks met
- [x] Security audit passed

**Exit Criteria:**
- [x] Build system configured
- [x] Cross-compilation tested
- [x] Release artifacts created
- [x] Installation methods documented
- [x] Migration tool ready
- [ ] v1.0 release published
- [ ] Documentation finalized

---

## Appendix A: Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "permission denied" creating namespaces | User namespaces disabled | Enable with sysctl |
| "cgroup creation failed" | cgroup v2 not mounted | Mount cgroup2 filesystem |
| "overlay mount failed" | Missing overlay module | Load overlay kernel module |
| "eBPF load failed" | Kernel too old or BPF disabled | Use iptables fallback |
| "Port already in use" | Conflicting service | Stop conflicting service or use different port |

### Debug Mode

```bash
# Enable debug logging
RUST_LOG=debug ferrocrate run alpine

# Trace specific component
RUST_LOG=ferro_exec=trace ferrocrate run alpine

# Enable backtraces
RUST_BACKTRACE=full ferrocrate run alpine
```

---

## Appendix B: Support Matrix

| Platform | Architecture | Kernel | Status |
|----------|-------------|--------|--------|
| Ubuntu 22.04+ | x86_64 | 5.15+ | Supported |
| Ubuntu 22.04+ | aarch64 | 5.15+ | Supported |
| Debian 12+ | x86_64 | 6.1+ | Supported |
| Debian 12+ | aarch64 | 6.1+ | Supported |
| Fedora 38+ | x86_64 | 6.2+ | Supported |
| Arch Linux | x86_64 | 6.5+ | Supported |
| Alpine 3.19+ | x86_64 | 6.1+ | Supported (musl) |
| RHEL 9+ | x86_64 | 5.14+ | Supported |
| RISC-V boards | riscv64 | 6.5+ | Experimental |
