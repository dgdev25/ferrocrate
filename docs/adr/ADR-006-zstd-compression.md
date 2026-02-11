# ADR-006: Zstd Compression

## Status

**Accepted**

## Context

Container image layers are compressed for storage and transfer. The choice of compression algorithm affects:
- Image pull time (decompression speed)
- Image push time (compression speed)
- Storage costs (compression ratio)
- CPU usage during pull/push

**Compression Algorithm Comparison:**

| Algorithm | Ratio | Compress | Decompress | CPU Usage |
|-----------|-------|----------|------------|-----------|
| gzip (9)  | 2.7x  | Slow     | Medium     | High      |
| gzip (1)  | 2.3x  | Fast     | Medium     | Medium    |
| zstd (19) | 2.9x  | Slow     | Fast       | High      |
| zstd (3)  | 2.7x  | Fast     | Very Fast  | Low       |
| xz        | 3.1x  | Very Slow| Slow       | Very High |
| lz4       | 2.1x  | Very Fast| Very Fast  | Very Low  |

**OCI Image Spec:**
- Supports gzip, zstd (since v1.1), and uncompressed layers
- Historically, gzip has been the default for Docker compatibility

**Zstd Characteristics:**
- Developed by Facebook (2016)
- Tunable compression levels (1-22)
- Fast decompression regardless of compression level
- Native multi-threading support
- Dictionary compression for small files
- Widely adopted (Linux kernel, Btrfs, Hadoop, etc.)

## Decision

**Use Zstd compression (level 3) as default for image layers. Support gzip for compatibility.**

Implementation:
1. **Default compression**: zstd level 3 for all new layers
2. **Pull compatibility**: Support gzip, zstd, and uncompressed layers
3. **Push compatibility**: Allow user to specify compression format via flag
4. **Registry support**: Detect registry capabilities; some older registries only accept gzip

CLI options:
```bash
ferrocrate build --compression zstd --compression-level 3
ferrocrate build --compression gzip    # For legacy registry compatibility
ferrocrate pull                        # Auto-detects layer compression
```

## Consequences

### Positive

- **2-4x faster decompression**: Image pull time dominated by decompression
- **Better compression ratio**: Slightly smaller images than gzip at default levels
- **Multi-threading**: Parallel compression during build/push
- **Future-proof**: zstd is the modern standard; gzip is legacy

### Negative

- **Legacy registry compatibility**: Some older registries may not support zstd layers
- **Tool compatibility**: Some image manipulation tools expect gzip
- **OCI v1.0 only guaranteed gzip**: zstd added in OCI v1.1

### Neutral

- **Migration**: Existing images remain gzip-compressed; only new builds use zstd

## Alternatives Considered

### gzip Only (Maximum Compatibility)

**Pros:**
- Universal registry support
- All tools support gzip layers
- OCI v1.0 compliant

**Cons:**
- 2-4x slower decompression than zstd
- No multi-threading
- Legacy technology

**Decision**: Rejected. Performance is a core differentiator; gzip is too slow.

### lz4 (Maximum Speed)

**Pros:**
- Fastest decompression
- Lowest CPU usage
- Good for cold start optimization

**Cons:**
- Poor compression ratio (~2.1x vs ~2.7x for zstd)
- Larger storage costs
- Not in OCI spec

**Decision**: Rejected. Compression ratio is too poor for storage efficiency.

### xz (Maximum Compression)

**Pros:**
- Best compression ratio
- Smallest images for bandwidth-constrained environments

**Cons:**
- Very slow decompression
- High CPU usage during pull
- Impractical for large images

**Decision**: Rejected. Decompression speed is critical for pull performance.

## Implementation Notes

**Rust crates:**
```toml
[dependencies]
zstd = "0.13"
flate2 = "1.0"  # gzip
```

**Compression during build:**
```rust
use zstd::stream::Encoder;

let encoder = Encoder::new(writer, 3)?  // level 3
    .multithread(num_cpus::get())?;     // parallel compression
```

**Decompression during pull:**
```rust
// Auto-detect from layer media type
match media_type {
    "application/vnd.oci.image.layer.v1.tar+gzip" => {
        GzipDecoder::new(reader)
    }
    "application/vnd.oci.image.layer.v1.tar+zstd" => {
        ZstdDecoder::new(reader)?
    }
    "application/vnd.oci.image.layer.v1.tar" => {
        reader  // uncompressed
    }
}
```

**Media types:**
```
OCI zstd: application/vnd.oci.image.layer.v1.tar+zstd
OCI gzip: application/vnd.oci.image.layer.v1.tar+gzip
Docker:   application/vnd.docker.image.rootfs.diff.tar.gzip
```

## References

- [Zstandard Official Site](https://facebook.github.io/zstd/)
- [OCI Image Spec - Media Types](https://github.com/opencontainers/image-spec/blob/main/media-types.md)
- [Zstd Rust Crate](https://docs.rs/zstd/)
- PRD Requirements: IMG-04, PERF-02
