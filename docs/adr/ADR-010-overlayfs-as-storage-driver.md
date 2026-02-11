# ADR-010: OverlayFS as Storage Driver

## Status

**Accepted**

## Context

Container images use layered filesystems for efficient storage and sharing. Each layer contains filesystem changes (additions, modifications, deletions).

**Storage Driver Options:**

| Driver | CoW | Performance | Stability | Kernel Version |
|--------|-----|-------------|-----------|----------------|
| OverlayFS | Yes | Excellent | Excellent | 3.18+ |
| Btrfs | Yes | Good | Good | 2.6.29+ |
| ZFS | Yes | Good | Good | External |
| Device Mapper | Yes | Medium | Good | 2.6.18+ |
| AUFS | Yes | Medium | Deprecated | Patched kernel |
| VFS | No | Poor | Excellent | All |

**OverlayFS Characteristics:**
- Native kernel driver (merged in 3.18, mature by 4.x)
- Efficient copy-on-write via kernel page cache
- Lower directory (image layers) + upper directory (container writes) + work directory
- Standard in all major container runtimes
- Rootless support (kernel 5.11+)

**OCI Layer Model:**
- Images are read-only layers stacked bottom-up
- Container has writable layer on top
- Whiteout files (`.wh.*`) mark deletions

## Decision

**OverlayFS as the sole storage driver. No pluggable storage driver system.**

Implementation:
1. **Single driver**: OverlayFS only; no VFS, btrfs, zfs alternatives
2. **Rootless support**: Use kernel 5.11+ unprivileged OverlayFS or FUSE fallback
3. **Layer storage**: `/var/lib/ferrocrate/overlay2/`
4. **Cleanup**: Automatic layer garbage collection for unreferenced layers

Rationale:
- OverlayFS is the industry standard (Docker, containerd, Podman default)
- All major Linux distributions ship with OverlayFS enabled
- Performance is excellent for container workloads
- Simpler codebase with single driver

## Consequences

### Positive

- **Code simplicity**: Single code path for storage operations
- **Performance**: OverlayFS is the fastest option for container workloads
- **Reliability**: Mature, well-tested kernel driver
- **Compatibility**: Standard layer format works with all OCI images
- **Read-only rootfs**: Easy to implement immutable containers

### Negative

- **No btrfs/ZFS users**: Cannot use advanced filesystem features
- **Rootless limitation**: Requires kernel 5.11+ for unprivileged OverlayFS
- **No Windows**: OverlayFS is Linux-only (Windows has its own drivers)

### Neutral

- **Distribution support**: All modern distros support OverlayFS; not a practical limitation

## Alternatives Considered

### Multiple Storage Drivers (Docker Model)

**Pros:**
- Flexibility for different environments
- btrfs/ZFS users get native features

**Cons:**
- Significant code complexity
- Testing burden multiplies
- Most drivers rarely used
- OverlayFS covers 95%+ of use cases

**Decision**: Rejected. Complexity cost exceeds benefit.

### Btrfs as Primary

**Pros:**
- Native snapshots
- Built-in compression
- Subvolumes for isolation

**Cons:**
- Not default on most distributions
- Requires dedicated btrfs partition
- More complex setup

**Decision**: Rejected. OverlayFS works on any filesystem.

### Device Mapper (Direct LVM)

**Pros:**
- Predictable performance
- Good for production workloads

**Cons:**
- Requires LVM setup
- No rootless support
- Larger disk footprint

**Decision**: Rejected. Too much setup complexity for users.

## Implementation Notes

**OverlayFS Mount:**
```rust
// Mount overlay for container
mount(
    Some("overlay"),
    &container_root,
    Some("overlay"),
    MsFlags::empty(),
    Some(
        format!(
            "lowerdir={}:{}:{},upperdir={},workdir={}",
            layer3, layer2, layer1,  // Read-only image layers (bottom-up)
            upper_dir,                // Container write layer
            work_dir                  // OverlayFS work directory
        )
        .as_str(),
    ),
)?;
```

**Directory Structure:**
```
/var/lib/ferrocrate/overlay/
├── l/                    // Layer metadata (symlinks to digest paths)
│   ├── L1 -> ../layers/sha256/abc...
│   └── L2 -> ../layers/sha256/def...
├── layers/               // Read-only image layers
│   └── sha256/abc.../
│       ├── layer.tar
│       └── manifests.json
├── containers/           // Container write layers
│   └── <container-id>/
│       ├── upper/        // Writable layer
│       └── work/         // OverlayFS work directory
└── merged/               // Merged mount points
    └── <container-id>/   // Final container rootfs
```

**Whiteout Handling:**
```rust
// OCI whiteout format: .wh.<filename>
fn apply_whiteouts(upper_dir: &Path) -> Result<()> {
    for entry in WalkDir::new(upper_dir) {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy();
        if name.starts_with(".wh.") {
            // Mark file as deleted
            let original_name = &name[4..];
            let to_delete = entry.path().parent().unwrap().join(original_name);
            if to_delete.exists() {
                std::fs::remove_file(&to_delete)?;
            }
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}
```

## References

- [OverlayFS Kernel Documentation](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html)
- [OCI Image Spec - Layer Filesystem](https://github.com/opencontainers/image-spec/blob/main/layer.md)
- [Docker Storage Drivers](https://docs.docker.com/storage/storagedriver/)
- PRD Requirements: STR-05, STR-06, IMG-03
