# ADR-001: Use Rust as Primary Language

## Status

**Accepted**

## Context

FerroCrate is an AI-native container runtime targeting:
- Sub-100ms container startup latency
- Zero idle memory when no containers are running
- Memory-safe execution without garbage collection pauses
- Support for resource-constrained edge devices (512MB-2GB RAM)

Container runtimes are security-critical infrastructure. Memory corruption vulnerabilities in container runtimes can lead to container escapes and host compromise. Traditional runtimes written in C/C++ face inherent memory safety challenges, while runtimes written in Go (like Docker/containerd) experience garbage collection pauses and have larger memory footprints.

The primary language choice affects:
- Runtime memory footprint
- Startup latency predictability
- Security posture (memory safety)
- Binary size for edge deployments
- Development velocity and ecosystem

## Decision

**Use Rust as the primary implementation language for all FerroCrate components.**

This includes:
- `ferro-exec` - Core container execution
- `ferro-store` - Image and layer management
- `ferro-build` - Build system
- `ferro-net` - Networking stack
- `ferro-mind` - AI inference engine (with WASM components)
- `ferro-compose` - Multi-container orchestration

Rust provides:
1. **Memory safety without GC** - Compile-time ownership model eliminates use-after-free, buffer overflows, and null pointer dereferences at compile time
2. **Zero-cost abstractions** - High-level constructs compile to machine code equivalent to hand-tuned C
3. **No runtime pauses** - Predictable latency critical for <100ms container startup
4. **Small binaries** - Single statically-linked binary under 15MB target is achievable
5. **Fearless concurrency** - Safe multi-threading for parallel image pulling, concurrent container management

## Consequences

### Positive

- **Security**: Memory safety eliminates entire classes of vulnerabilities that plague C/C++ container infrastructure
- **Performance**: No GC pauses means predictable sub-millisecond latency for critical paths
- **Resource efficiency**: Zero idle memory achievable; no runtime overhead when idle
- **Binary size**: Static linking with `musl` produces small, portable binaries for edge deployment
- **Modern tooling**: Cargo ecosystem, integrated testing, excellent documentation generation

### Negative

- **Learning curve**: Rust ownership model requires training for developers from GC languages
- **Compilation time**: Rust compile times are slower than Go; affects CI/CD feedback loops
- **Ecosystem gaps**: Some container-related libraries may need to be written from scratch vs using existing Go libraries

### Neutral

- **Hiring**: Rust developers are in high demand but smaller pool than Go developers

## Alternatives Considered

### Go

**Pros:**
- Dominant language in container ecosystem (Docker, containerd, CRI-O, Podman)
- Rich container-related libraries (containers/image, opencontainers/runtime-spec)
- Fast compilation, simple syntax, easy hiring

**Cons:**
- Garbage collection introduces unpredictable pauses (violates sub-100ms startup guarantee)
- Larger memory footprint due to runtime and GC overhead
- CGO memory safety concerns when interfacing with C libraries
- Binary sizes typically 2-3x larger than equivalent Rust

**Decision**: Rejected due to GC pauses and memory overhead incompatible with edge deployment targets.

### C/C++

**Pros:**
- Maximum control over memory and performance
- Direct access to Linux kernel APIs (namespaces, cgroups, eBPF)
- Existing container runtime implementations (runc, crun)

**Cons:**
- Memory safety vulnerabilities are endemic (see runc CVE history)
- Requires extensive testing/fuzzing to achieve safety Rust provides by default
- Developer productivity lower due to manual memory management

**Decision**: Rejected due to memory safety risks in security-critical infrastructure.

### Zig

**Pros:**
- Modern systems language with safety focus
- Excellent cross-compilation
- No hidden control flow

**Cons:**
- Immature ecosystem; not production-ready for infrastructure
- Smaller community and fewer libraries
- Higher risk for long-term maintenance

**Decision**: Rejected due to ecosystem immaturity.

## References

- [Rust for Systems Programming](https://rust-lang.org/)
- [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec)
- [runc Security CVEs](https://www.cvedetails.com/product/40688/Opencontainers-Runc.html)
- PRD Requirements: PERF-01, PERF-03, PERF-07, REL-05
