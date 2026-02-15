# FerroCrate macOS Limitations

## Overview

FerroCrate has been ported to macOS to support development, image management, and AI orchestration workflows. However, native container execution is **not available** on macOS due to fundamental platform differences. This document explains the limitations and provides guidance for macOS users.

**Status:** ✅ **macOS Support Implemented** (v0.1.0+)
**Platform:** macOS (x86_64, arm64)
**Release Date:** 2026-02-15

---

## Supported Features on macOS ✅

### Image Management
- **`ferro-cli images`** - List local images
- **`ferro-cli rmi`** - Remove images
- **`ferro-cli image-prune`** - Clean up unused images
- **`ferro-cli pull`** - Download container images
- **`ferro-cli push`** - Upload images to registries

### AI & Machine Learning
- **`ferro-cli ai orchestrate`** - Run AI orchestration tasks
- **`ferro-cli ai-train`** - Train ML models
- **`ferro-cli ai-export`** - Export trained models
- **`ferro-cli ai-import`** - Import pre-trained models
- **`ferro-cli ai-stats`** - Get model statistics
- **`ferro-cli ai-audit`** - Audit AI decisions

### Configuration
- **`ferro-cli config`** - Manage configuration
- **`ferro-cli completion`** - Shell completions

---

## Unsupported Features on macOS ❌

### Container Execution (Linux-Only)
The following commands are **NOT available** on macOS:

| Command | Reason | Workaround |
|---------|--------|-----------|
| `ferro-cli run` | Requires Linux namespaces & cgroups | Use Docker Desktop + Linux VM |
| `ferro-cli ps` | Container management (Linux-only) | Use `docker ps` |
| `ferro-cli compose up/down` | Requires Linux container runtime | Use Docker Compose |
| `ferro-cli ai branch` | RVF persistence (Linux-only) | Run on Linux system |
| `ferro-cli ai lineage` | RVF file format support | Run on Linux system |
| `ferro-cli ai migrate` | Model migration to RVF format | Run on Linux system |

### Linux-Only AI Features
The following AI features require Linux-specific dependencies:

| Feature | Limitation | Details |
|---------|-----------|---------|
| **RVF Format** | Not compiled on macOS | `rvf-persistence` feature gated with `#[cfg(target_os = "linux")]` |
| **Model Branching** | Linux-specific | Requires RVF file system persistence |
| **Lineage Tracking** | Linux-specific | Requires RVF vector format |
| **Model Migration** | Linux-specific | Converts legacy models to RVF |

---

## Technical Limitations

### 1. No Linux Kernel on macOS

macOS uses the **XNU kernel**, not the Linux kernel. FerroCrate requires these Linux-specific features:

#### Required Linux Features NOT Available on macOS:
```
✗ Linux namespaces (PID, network, mount, UTS, IPC, user)
✗ cgroups v2 (resource limits and accounting)
✗ OverlayFS (layered filesystem)
✗ seccomp (system call filtering)
✗ AppArmor/SELinux (mandatory access control)
✗ netfilter/iptables (network filtering)
✗ BPF (extended Berkeley Packet Filter)
✗ eBPF observability features
```

### 2. Container Runtime Architecture

FerroCrate's architecture is designed for **direct Linux kernel integration**:

```
┌─────────────────────────────────────┐
│       FerroCrate (Rust CLI)         │
├─────────────────────────────────────┤
│   Container Runtime (Linux-only)    │
│  - Direct kernel access             │
│  - Namespace management             │
│  - cgroups v2 integration           │
├─────────────────────────────────────┤
│      Linux Kernel                   │
│  - namespaces, cgroups, seccomp     │
└─────────────────────────────────────┘

                vs.

┌─────────────────────────────────────┐
│      macOS Application              │
├─────────────────────────────────────┤
│    XNU Kernel (NOT Linux)           │
│  - No namespace support             │
│  - No cgroup support                │
│  - No OverlayFS                     │
└─────────────────────────────────────┘
```

### 3. RVF Format (FerroCrate Vector Format)

The **RVF format** for model serialization is Linux-only because:
- Requires `rvf-runtime` library (Linux-specific syscalls)
- Contains `___errno_location` symbol (glibc-specific)
- Links to Linux-only system libraries

**Conditional Compilation:**
```rust
#[cfg(target_os = "linux")]
use rvf_runtime;  // Only compiled on Linux
```

---

## Workarounds for macOS Users

### Scenario 1: Develop Locally, Deploy on Linux

**Recommended setup:**
1. Use macOS for development/testing with supported features
2. Deploy to Linux production for full container execution
3. Push images to registry for cross-platform use

```bash
# macOS development
ferro-cli ai-train --model-type anomaly-detector
ferro-cli ai-export --model-type anomaly-detector --output model.native
ferro-cli push myregistry.com/myimage:latest

# Linux production
ferro-cli run myimage:latest
ferro-cli ai-stats --model-type anomaly-detector
```

### Scenario 2: Use Docker Desktop for Container Execution

If you need to run containers on macOS:

1. **Install Docker Desktop** for macOS
2. Use Docker CLI for container operations
3. Use FerroCrate for image management and AI features

```bash
# FerroCrate on macOS (cross-platform)
ferro-cli images
ferro-cli pull alpine:latest
ferro-cli ai orchestrate --task "analyze containers"

# Docker Desktop (container execution)
docker run alpine:latest echo "Hello"
```

### Scenario 3: Use Linux VM/Remote Machine

For full FerroCrate functionality:

```bash
# macOS: Remote SSH
ssh user@linux-server.com
ferro-cli run alpine:latest echo "Hello from Linux"
ferro-cli ai branch --source model1.rvf --target model2.rvf
```

---

## Implementation Details

### Platform Gating Strategy

All Linux-only code is gated using Rust's `#[cfg]` attribute:

```rust
// Linux-only command variant
#[cfg(target_os = "linux")]
Run { /* container execution */ }

// Linux-only enum arm in match statement
#[cfg(target_os = "linux")]
AiCommands::Branch { /* RVF operations */ }

// Linux-only conditional code
#[cfg(target_os = "linux")]
{
    handle_rvf_operations()
}

// Fallback for non-Linux platforms
#[cfg(not(target_os = "linux"))]
{
    standard_export_operations()
}
```

### Build-Time Elimination

Features gated with `#[cfg]` are **completely removed** at compile time:
- Zero runtime overhead
- No conditional checks needed
- Smaller binary on macOS

**Cargo Configuration:**
```toml
# ferro-mind/Cargo.toml
[features]
default = []  # No RVF by default
rvf-persistence = ["dep:rvf-runtime"]  # Optional on Linux

# ferro-cli/Cargo.toml
[target.'cfg(target_os = "linux")'.dependencies]
ferro-mind = { path = "../ferro-mind", features = ["rvf-persistence"] }
```

---

## Future Possibilities

### Short Term (v0.2.0+)
- ✅ Enhanced image metadata caching
- ✅ Better registry credential management
- ✅ Improved AI model discovery and download

### Medium Term (v1.0+)
- 🔮 Docker integration layer (optional)
- 🔮 OCI image spec enhancements
- 🔮 Cross-platform model compatibility

### Long Term (v2.0+)
- 🔮 WebAssembly-based model execution
- 🔮 Platform-independent model serialization
- 🔮 Cloud-native deployment helpers

---

## Troubleshooting

### "Command not available on macOS"

**Symptom:**
```
$ ferro-cli run alpine:latest
error: unrecognized subcommand 'run'
```

**Cause:** Attempting to use a Linux-only command on macOS

**Solution:**
1. Switch to a Linux machine/VM
2. Use `ferro-cli --help` to see available commands
3. Refer to "Workarounds" section above

### "RVF format not supported"

**Symptom:**
```
$ ferro-cli ai branch --source model.rvf --target model2.rvf
error: cannot find function `handle_rvf_branch_command`
```

**Cause:** RVF features are Linux-only

**Solution:**
1. Convert model to standard format on Linux
2. Use `.native` format on macOS
3. Transfer via registry for cross-platform use

---

## Testing on macOS

### Verified Working
```bash
✓ Build: cargo build --bins
✓ Test: cargo test
✓ Commands: ai, images, config, pull, push
✓ AI Operations: orchestrate, train, export, import
```

### Platform Detection
```bash
$ uname -s
Darwin
$ uname -m
arm64  # or x86_64

$ rustc --version --verbose | grep host
host: aarch64-apple-darwin  # or x86_64-apple-darwin
```

---

## Contributing

For macOS-specific issues:
1. Verify the command is not gated as Linux-only
2. Check `#[cfg]` gates in source code
3. Ensure feature is platform-agnostic
4. File issues with:
   - macOS version
   - FerroCrate version
   - Command used
   - Full error message

---

## Summary

| Aspect | Status | Details |
|--------|--------|---------|
| **Platform Support** | ✅ Supported | Builds and runs on macOS |
| **Image Management** | ✅ Supported | Full image operations |
| **AI Features** | ✅ Mostly Supported | Except RVF-specific features |
| **Container Execution** | ❌ Not Supported | Requires Linux kernel |
| **RVF Format** | ❌ Not Supported | Linux-only persistence layer |
| **Recommended Use** | 📱 Development & Management | Not production container host |

---

## Quick Reference

### Available on macOS
```bash
ferro-cli images
ferro-cli pull <image>
ferro-cli push <image>
ferro-cli ai orchestrate --task "..."
ferro-cli ai-train --model-type <type>
ferro-cli ai-export --model-type <type>
ferro-cli ai-import --model-type <type>
ferro-cli config
```

### Not Available on macOS
```bash
ferro-cli run                    # ❌ Container execution
ferro-cli ps                     # ❌ Container listing
ferro-cli compose up/down        # ❌ Compose orchestration
ferro-cli ai branch              # ❌ RVF branching
ferro-cli ai lineage             # ❌ RVF lineage
ferro-cli ai migrate             # ❌ RVF migration
```

---

**Last Updated:** 2026-02-15
**FerroCrate Version:** 0.1.0
**macOS Support:** Beta

For more information, see [README.md](../README.md) and [ARCHITECTURE.md](./ARCHITECTURE.md)
