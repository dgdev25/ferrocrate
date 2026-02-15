# FerroCrate macOS Runtime Notes

## Overview

FerroCrate supports macOS by running the Linux container runtime in a Linux guest (desktop VM path). Native Linux-kernel container primitives are not available on macOS itself, but standard user-facing commands (including `run`) are expected to work via the desktop integration layer.

**Status:** ✅ **macOS host support implemented** (v0.1.0+)
**Platform:** macOS (x86_64, arm64)
**Release Date:** 2026-02-15

---

## Supported Features on macOS ✅

### Desktop VM Runtime Path
- **`ferrocrate run`** - Runs containers through Linux guest runtime
- **`ferrocrate ps`** - Lists containers via desktop bridge
- **`ferrocrate compose up/down`** - Compose workflows via desktop bridge
- **`ferro-desktop vm ...`** - VM lifecycle (init/start/stop/status/update)
- **`ferro-desktop autostart ...`** - launch agent setup

### Image Management
- **`ferrocrate images`** - List local images
- **`ferrocrate rmi`** - Remove images
- **`ferrocrate image-prune`** - Clean up unused images
- **`ferrocrate pull`** - Download container images
- **`ferrocrate push`** - Upload images to registries

### AI & Machine Learning
- **`ferrocrate ai orchestrate`** - Run AI orchestration tasks
- **`ferrocrate ai-train`** - Train ML models
- **`ferrocrate ai-export`** - Export trained models
- **`ferrocrate ai-import`** - Import pre-trained models
- **`ferrocrate ai-stats`** - Get model statistics
- **`ferrocrate ai-audit`** - Audit AI decisions

### Configuration
- **`ferrocrate config`** - Manage configuration
- **`ferrocrate completion`** - Shell completions

---

## Not Native on macOS ❌

### Direct Host-Kernel Container Execution
The following is not available directly on the macOS host kernel:

| Area | Reason | Practical path |
|------|--------|----------------|
| Linux namespaces/cgroups/seccomp on host | macOS kernel is XNU, not Linux | Run through `ferro-desktop` Linux guest |
| Host-native OverlayFS/netfilter/eBPF runtime hooks | Linux kernel-only subsystems | Use guest runtime networking/storage |

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

### Scenario 1: Use FerroCrate Desktop VM Path (Recommended)

```bash
# Start VM/runtime path
ferro-desktop vm init --backend qemu-hvf --cpus 2 --memory-mb 2048
ferro-desktop vm start

# Use ferrocrate as normal
ferrocrate run alpine:latest echo "Hello from FerroCrate on macOS"
ferrocrate ps
```

### Scenario 2: Develop Locally, Deploy on Linux

1. Use macOS for development/testing.
2. Deploy to Linux production for strict Linux-native parity.
3. Push images to a registry for cross-platform use.

```bash
ferrocrate ai-train --model-type anomaly-detector
ferrocrate ai-export --model-type anomaly-detector --output model.native
ferrocrate push myregistry.com/myimage:latest
```

### Scenario 3: Use Linux VM/Remote Machine

For full FerroCrate functionality:

```bash
# macOS: Remote SSH
ssh user@linux-server.com
ferrocrate run alpine:latest echo "Hello from Linux"
ferrocrate ai branch --source model1.rvf --target model2.rvf
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

### "`run` command missing on macOS"

**Symptom:**
```
$ ferrocrate run alpine:latest
error: unrecognized subcommand 'run'
```

**Cause:** Usually an installation/path mismatch (wrong binary), not expected behavior.

**Solution:**
1. Ensure you are running `ferrocrate` (CLI), not only `ferro-desktop`.
2. Check `which ferrocrate` and `ferrocrate --help`.
3. Confirm desktop VM path is initialized and started.

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
| **Container Execution** | ✅ Supported via Desktop VM | Not host-native on XNU kernel |
| **RVF Format** | ❌ Not Supported | Linux-only persistence layer |
| **Recommended Use** | 📱 Development & Managed Runtime | Use desktop VM path for parity |

---

## Quick Reference

### Available on macOS
```bash
ferro-desktop vm init --backend qemu-hvf --cpus 2 --memory-mb 2048
ferro-desktop vm start
ferrocrate run <image>
ferrocrate ps
ferrocrate compose up/down
ferrocrate images
ferrocrate pull <image>
ferrocrate push <image>
ferrocrate ai orchestrate --task "..."
ferrocrate ai-train --model-type <type>
ferrocrate ai-export --model-type <type>
ferrocrate ai-import --model-type <type>
ferrocrate config
```

### Not Host-Native on macOS
```bash
Linux namespaces/cgroups/seccomp on host kernel  # ❌ requires Linux guest runtime
ferrocrate ai branch                            # ❌ RVF branching
ferrocrate ai lineage                           # ❌ RVF lineage
ferrocrate ai migrate                           # ❌ RVF migration
```

---

**Last Updated:** 2026-02-15
**FerroCrate Version:** 0.1.0
**macOS Support:** Beta

For more information, see [README.md](../README.md) and [ARCHITECTURE.md](./ARCHITECTURE.md)
