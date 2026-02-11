# ADR-005: Blake3 for Content Hashing

## Status

**Accepted**

## Context

Container images use content-addressable storage. Each layer is identified by its cryptographic hash. The OCI Image Spec mandates SHA-256 as the digest algorithm.

**Hash Performance Comparison** (on 1GB data, AMD Ryzen 9 5950X):

| Algorithm | Throughput | Latency (1MB) |
|-----------|-----------|---------------|
| SHA-256   | ~600 MB/s | ~1.7 ms      |
| SHA-512   | ~900 MB/s | ~1.1 ms      |
| BLAKE3    | ~6000 MB/s| ~0.17 ms     |
| xxHash    | ~15000 MB/s| ~0.07 ms   |

**BLAKE3 Characteristics:**
- Cryptographic hash (256-bit output, extendable)
- Based on BLAKE2 (SHA-3 finalist) with modifications
- Parallelizable (uses all CPU cores)
- SIMD-optimized (AVX-512, AVX2, SSE4.1)
- Official Rust implementation available
- Used by IPFS, Bazel, and other large-scale systems

**OCI Compatibility:**
- OCI spec requires SHA-256 for manifests and layer digests
- Internal deduplication can use any hash algorithm
- Need to maintain SHA-256 for external compatibility

## Decision

**Use Blake3 for internal content-addressable storage. SHA-256 for OCI-compliant digests.**

Implementation:
1. **Layer storage**: Files stored keyed by Blake3 hash
2. **Deduplication**: Blake3 enables fast file-level deduplication across all layers
3. **OCI compatibility**: Compute SHA-256 for manifest digests (required by spec)
4. **Hybrid indexing**: Store both Blake3 (internal) and SHA-256 (external) mappings

Performance optimization:
```rust
// Parallel Blake3 computation during image pull
let blake3_hash = blake3::Hasher::new()
    .update_with_join::<join::RayonJoin>(&data)?;

// SHA-256 computed once for OCI digest
let sha256_digest = sha2::Sha256::digest(&data);
```

## Consequences

### Positive

- **10x faster hashing**: Layer deduplication during pull is dramatically faster
- **Parallel processing**: Uses all cores; scales with CPU
- **File-level deduplication**: Faster detection of duplicate files across layers
- **Storage efficiency**: PRD target of 40%+ storage reduction achievable
- **Build cache**: Blake3 enables fast cache invalidation checks

### Negative

- **Dual hashing**: Must compute both Blake3 and SHA-256 for OCI compatibility
- **Non-standard**: Blake3 not in OCI spec; internal-only
- **Storage overhead**: Index stores two hashes per blob

### Neutral

- **Implementation complexity**: Hash mapping layer required

## Alternatives Considered

### SHA-256 Only (OCI Compliant)

**Pros:**
- Single hash algorithm
- Full OCI compliance without translation
- No storage overhead for dual hashes

**Cons:**
- 10x slower than Blake3
- Single-threaded computation
- Deduplication during pull is slow for large images

**Decision**: Rejected. Performance target of 500 MB/s pull throughput requires faster hashing.

### xxHash (Non-Cryptographic)

**Pros:**
- Extremely fast (15 GB/s)
- Widely used for non-security hashing

**Cons:**
- Not cryptographically secure
- Cannot use for security verification
- Collision resistance insufficient for content addressing

**Decision**: Rejected. Content-addressable storage requires cryptographic hashes.

### SHA-512 (Faster on 64-bit)

**Pros:**
- Faster than SHA-256 on 64-bit systems
- Standard algorithm
- More collision resistance than SHA-256

**Cons:**
- Still single-threaded
- Not as fast as Blake3
- Larger digest size (64 bytes vs 32)

**Decision**: Rejected. Blake3 provides better performance and parallelization.

## Implementation Notes

**Blake3 crate:**
```toml
[dependencies]
blake3 = "1.5"
sha2 = "0.10"
```

**Digest format in store:**
```rust
struct BlobRef {
    blake3: [u8; 32],    // Internal lookup key
    sha256: [u8; 32],    // OCI digest
    size: u64,
    compressed_size: u64,
}
```

**OCI digest format:**
```
sha256:abc123...  // External reference
blake3:def456...   // Internal reference only
```

## References

- [BLAKE3 Official Site](https://blake3.io/)
- [BLAKE3 Paper](https://github.com/BLAKE3-team/BLAKE3-specs)
- [OCI Image Spec - Descriptors](https://github.com/opencontainers/image-spec/blob/main/descriptor.md)
- PRD Requirements: IMG-03, PERF-02
