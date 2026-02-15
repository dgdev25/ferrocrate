# FerroCrate

**AI-native container runtime written in Rust** — Fast, secure, intelligent, and resource-efficient alternative to Docker with built-in AI capabilities.

[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-rootless%20by%20default-green.svg)](#security-features)

## Why FerroCrate?

- **🚀 Zero Overhead**: 0MB idle memory (no daemon required), <8MB with daemon
- **🧠 AI-Native**: Built-in predictive resource allocation, anomaly detection, and intelligent restart policies
- **🔒 Secure by Default**: Rootless containers, seccomp profiles, capability dropping, image signature verification
- **⚡ Fast**: <100ms cold start, <50ms warm start, file-level deduplication with Blake3
- **🐋 Docker Compatible**: Drop-in replacement for Docker CLI and docker-compose.yml files
- **🎯 Lightweight**: <15MB single binary, perfect for edge devices and resource-constrained environments

## Features

### Container Lifecycle Management
- ✅ **Run OCI-compliant images** — Docker Hub, GHCR, ECR, GCR, Harbor, Quay.io
- ✅ **Complete lifecycle control** — create, start, stop, restart, pause, kill, remove
- ✅ **Container exec** — run commands inside running containers
- ✅ **Real-time logs** — stdout/stderr streaming with historical log access
- ✅ **Health checks** — Dockerfile HEALTHCHECK support with configurable intervals
- ✅ **Restart policies** — no, on-failure, always, unless-stopped
- ✅ **Resource limits** — memory, CPU, PIDs via cgroups v2
- ✅ **Container inspect** — Docker-compatible JSON metadata output

### Image Management
- ✅ **OCI-compliant registries** — Pull/push from any OCI registry
- ✅ **Blake3 content-addressable store** — 40%+ storage reduction via file-level deduplication
- ✅ **Zstd compression** — 2x+ compression speed vs gzip
- ✅ **Lazy image pulling** — Start containers before full image download
- ✅ **Dockerfile build** — Multi-stage builds with build cache
- ✅ **Image operations** — tag, list, remove, prune, scan
- ✅ **ruvector-based deduplication** — Vector embeddings identify similar content

### Networking
- ✅ **Bridge networking** — Default container networking with port mapping
- ✅ **Host and none modes** — Full control over network isolation
- ✅ **Container DNS** — Automatic container-to-container name resolution
- ✅ **Custom networks** — Named networks with configurable subnets
- ✅ **eBPF + fallback** — eBPF packet forwarding with iptables/nftables fallback
- ✅ **Port mapping** — TCP/UDP port forwarding to host
- ⚠️ **IPv6 support** — Dual-stack networking (in progress)
- ⚠️ **WireGuard overlay** — Encrypted cross-host communication (planned)

### Storage & Volumes
- ✅ **Named volumes** — Persistent storage across container lifecycle
- ✅ **Bind mounts** — Host directories mounted into containers
- ✅ **tmpfs mounts** — In-memory filesystem for sensitive data
- ✅ **OverlayFS** — Efficient copy-on-write layer management
- ✅ **Read-only rootfs** — Immutable container filesystems
- ✅ **Volume backup/restore** — CLI commands for data export/import

### Security Features
- ✅ **Rootless by default** — User namespace isolation without root privileges
- ✅ **Seccomp profiles** — Default profile blocks dangerous syscalls, custom profiles loadable
- ✅ **Capability dropping** — All capabilities dropped by default
- ✅ **No-new-privileges** — Prevent privilege escalation via setuid/setgid
- ✅ **Image signature verification** — Cosign/Sigstore integration
- ✅ **Audit logging** — Structured JSON logs for compliance
- ⚠️ **AppArmor/SELinux** — MAC enforcement (in progress)
- ⚠️ **eBPF security monitoring** — Runtime syscall auditing (planned)

### AI/Intelligence Layer (ferro-mind)
- ✅ **WASM-based inference** — 1-5ms prediction latency, zero external API calls
- ✅ **Predictive resource allocation** — Memory/CPU pre-allocation based on learned patterns
- ✅ **Anomaly detection** — Resource usage anomalies with severity and recommendations
- ✅ **Intelligent restart** — Diagnostic analysis before restart with config adjustment
- ✅ **Cost-tiered routing** — WASM (free) → local LLM (cheap) → Claude API (complex)
- ✅ **Build cache optimization** — ruvector distance/embedding primitives for cache hits
- ✅ **AI opt-out** — Single flag disables all AI features (`FERROCRATE_AI=0`)
- ⚠️ **Natural language management** — "ferrocrate ask 'why did my server crash?'" (planned)
- ⚠️ **GPU/VRAM-aware scheduling** — Intelligent allocation for AI workloads (planned)

### Compose & Multi-Container
- ✅ **docker-compose.yml compatibility** — Version 3.x files work without modification
- ✅ **Native compose subcommand** — No separate tool installation required
- ✅ **Service dependencies** — depends_on with condition support
- ✅ **Service scaling** — ferrocrate compose up --scale web=3
- ✅ **Environment files** — .env support with variable substitution
- ✅ **Profiles** — Named profiles for selective service activation
- ✅ **Watch mode** — Automatic rebuild on source file changes

### CLI & Developer Experience
- ✅ **Docker-compatible syntax** — run, build, pull, push, ps, logs, exec match Docker
- ✅ **Docker socket compatibility** — Emulate /var/run/docker.sock for tool compatibility
- ✅ **Shell completion** — bash, zsh, fish support
- ✅ **Colored output** — Progress bars, table formatting, human-friendly display
- ✅ **JSON output mode** — Machine-parseable output for scripting (--format json)
- ✅ **Migration tool** — ferrocrate migrate to convert Docker configurations
- ✅ **Interactive TUI** — Terminal UI for browsing containers, logs, resources

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/dgtise25/ferrocrate.git
cd ferrocrate

# Build release binary
cargo build --release

# Install (optional)
sudo cp target/release/ferro-cli /usr/local/bin/ferrocrate
```

### One-Command Installers

macOS (secure release install with checksum verification):

```bash
curl -fsSL https://raw.githubusercontent.com/dgtise25/ferrocrate/main/scripts/install-macos.sh -o install-macos.sh
bash install-macos.sh
```

macOS source-build fallback:

```bash
bash install-macos.sh --method source
```

Windows PowerShell (secure release install with checksum verification):

```powershell
iwr https://raw.githubusercontent.com/dgtise25/ferrocrate/main/scripts/install-windows.ps1 -OutFile install-windows.ps1
powershell -ExecutionPolicy Bypass -File .\install-windows.ps1
```

Windows source-build fallback:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Method source
```

Installer notes:
- Default install paths: `/usr/local/bin` (macOS), `%ProgramFiles%\\FerroCrate\\bin` (Windows).
- Use `--version <tag>` to pin a release.
- Use `--force` to overwrite existing binaries.
- Release installer expects artifacts named `ferrocrate-<tag>-<os>-<arch>` plus a matching checksums file.

### Basic Usage

```bash
# Run a container
ferrocrate run alpine:latest echo "Hello from FerroCrate!"

# Run with port mapping and detached mode
ferrocrate run -d -p 8080:80 --name web nginx:alpine

# List running containers
ferrocrate ps

# View container logs
ferrocrate logs web

# Execute command in running container
ferrocrate exec web sh

# Stop and remove container
ferrocrate stop web
ferrocrate rm web
```

### Image Management

```bash
# Pull an image
ferrocrate pull ghcr.io/myorg/myapp:latest

# Build from Dockerfile
ferrocrate build -t myapp:dev .

# Build with multi-stage
ferrocrate build -t myapp:prod --target production .

# List images
ferrocrate images

# Tag an image
ferrocrate tag myapp:dev ghcr.io/myorg/myapp:v1.0.0

# Push to registry
ferrocrate push ghcr.io/myorg/myapp:v1.0.0
```

### Compose Workflows

```bash
# Start services from docker-compose.yml
ferrocrate compose up

# Start with specific profile
ferrocrate compose up --profile production

# Scale a service
ferrocrate compose up --scale web=3

# Watch mode for development
ferrocrate compose watch

# Stop and remove services
ferrocrate compose down
```

### AI Features

```bash
# Enable AI features (default)
export FERROCRATE_AI=1

# Disable AI features
export FERROCRATE_AI=0

# View AI decision audit log
ferrocrate ai-audit

# Container with predictive resource allocation
ferrocrate run --ai-predict myapp:latest
```

### Security

```bash
# Run with rootless mode (default)
ferrocrate run alpine:latest

# Verify image signature before running
export FERROCRATE_SIGNATURE_VERIFY=1
export FERROCRATE_SIGNATURE_KEY=/path/to/cosign.pub
ferrocrate run ghcr.io/myorg/signed-image:latest

# Run with custom seccomp profile
ferrocrate run --security-opt seccomp=/path/to/profile.json alpine

# Read-only rootfs
ferrocrate run --read-only alpine:latest
```

## Architecture

FerroCrate is built as a 7-crate Rust workspace with clean separation of concerns:

```
ferro-cli         CLI + Docker-compatible API server
  ├─ ferro-core     Container runtime engine
  │   ├─ ferro-net  Network primitives (bridge, veth, netns, eBPF)
  │   └─ ferro-mind AI/ML layer (anomaly, training, embeddings)
  ├─ ferro-compose  Compose file parser
  └─ ferro-cri      CRI gRPC server (Kubernetes integration)

ferro-desktop     Windows/WSL proxy (standalone)
```

### Key Technologies
- **Runtime**: Linux namespaces, cgroups v2, seccomp, capabilities
- **Storage**: Blake3 CAS, OverlayFS, Zstd compression
- **Networking**: eBPF (primary), iptables/nftables (fallback)
- **AI/ML**: ruvector-core (HNSW), ruv-fann (neural nets), tract-onnx (ONNX inference)
- **Security**: Rootless containers, image signature verification (Cosign)

## Performance

| Metric | Target | Status |
|--------|--------|--------|
| Container startup | <100ms cold, <50ms warm | ✅ Achieved |
| Idle memory (no daemon) | 0 MB | ✅ Achieved |
| Idle memory (with daemon) | <8 MB | ✅ Achieved |
| Per-container overhead | <2 MB | ✅ Achieved |
| Binary size | <15 MB static | ✅ Achieved |
| AI inference latency | 1-5 ms (WASM) | ✅ Achieved |

## Compatibility

- ✅ **OCI Image Spec v1.1** — Full compliance
- ✅ **OCI Runtime Spec v1.2** — Full compliance
- ✅ **OCI Distribution Spec v1.1** — Full compliance
- ✅ **Docker CLI** — 80%+ command compatibility
- ✅ **docker-compose v3.x** — 90%+ directive coverage
- ✅ **Dockerfile** — 95%+ directive coverage
- ⚠️ **Kubernetes CRI v1** — In progress (ferro-cri)

## Development

### Running Tests

```bash
# Run all tests
scripts/run-tests.sh

# Run tests for specific crate
cargo test -p ferro-core

# Run with coverage
scripts/coverage.sh
```

### Building for Production

```bash
# Build optimized release binary
cargo build --release

# Build for multiple architectures
scripts/build-targets.sh  # x86_64, aarch64, riscv64
```

### Project Status

**Current Phase:** Phase 1 (Core Parity) — 95% complete
**Total Lines of Code:** ~20,000 LOC across 111 source files
**Test Coverage:** 202 tests, all passing
**Security Audit:** Comprehensive audit completed (49 findings, 9 critical fixed)

See [ROADMAP.md](docs/ROADMAP.md) for detailed feature status and roadmap.

## Documentation

- **[Product Requirements](docs/product-requirements.md)** — Complete PRD with functional/non-functional requirements
- **[Roadmap](docs/ROADMAP.md)** — Phase-by-phase feature implementation status
- **[Audit Report](docs/AUDIT_REPORT.md)** — Comprehensive codebase audit with remediation plan
- **[Security](SECURITY.md)** — Security policy and vulnerability reporting
- **[Architecture Decision Records](docs/adr/)** — Design decisions and rationale

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

## Acknowledgments

Built with ❤️ using the rUv crate ecosystem:
- [ruvector-core](https://crates.io/crates/ruvector-core) — HNSW vector search
- [ruv-fann](https://crates.io/crates/ruv-fann) — Fast neural networks
- [ruvector-sona](https://crates.io/crates/ruvector-sona) — LoRA + EWC++ for self-learning
