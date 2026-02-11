# ADR-013: Networking Fallback Strategy

## Status

**Accepted** (February 11, 2026 - Formalized eBPF with explicit iptables/nftables fallback per AI consensus)

## Context

ADR-004 established eBPF as the primary networking backend, but left the fallback strategy ambiguous. The product requirements (PRD line 303) mention "graceful fallback" and architecture.md references an iptables directory, suggesting multiple paths forward.

**Networking Backend Options:**

| Backend | Latency | Complexity | Maintenance | Kernel |
|---------|---------|-----------|------------|--------|
| eBPF (XDP/TC) | <1ms | High | Medium | 5.10+ |
| iptables | 1-5ms | Low | Low | 3.10+ |
| nftables | 1-5ms | Low | Low | 3.13+ |
| netfilter (raw) | <1ms | Very High | High | 2.6+ |

**Current Problem:**
- ADR-004 states "No iptables rules created"
- PRD line 303 states "graceful fallback to iptables if unavailable"
- Architecture suggests iptables as optional optimization path
- Users need explicit control; silent fallback creates confusion

**AI Consensus Recommendation:**
All 4 consensus models agreed: Make fallback explicit and opt-in via `--network-backend` flag.

## Decision

**Primary: eBPF (XDP/TC) for all container networking.**
**Secondary: Explicit fallback to iptables (Linux 3.10+) or nftables (Linux 3.13+) via `--network-backend` flag.**
**No silent fallback: Users must explicitly choose fallback.**

Implementation:
1. **Default behavior**: Use eBPF if kernel supports XDP/TC (5.10+)
2. **Fallback trigger**: On startup, if eBPF unavailable, error (not silent fallback)
3. **Explicit opt-in**: Users can force fallback with `--network-backend=iptables` or `--network-backend=nftables`
4. **Logging**: All backend selection decisions logged at startup
5. **Testing**: Separate test suites for each backend path

## Consequences

### Positive

- **Clarity**: Users understand which backend is in use (no surprises)
- **Debugging**: Explicit backend choice makes troubleshooting easier
- **Compatibility**: Explicit iptables/nftables support for older kernels (user responsibility)
- **Performance**: eBPF primary path optimized for modern kernels
- **Separation of concerns**: Each backend testable independently

### Negative

- **User education**: Must document when to use each backend
- **Testing burden**: Multiple backend paths increase test complexity
- **Transition friction**: Users cannot transparently upgrade to eBPF-capable systems

### Neutral

- **Maintenance**: Maintaining 3 backends (eBPF, iptables, nftables) requires expertise

## Alternatives Considered

### Silent Fallback (Current PRD interpretation)

**Pros:**
- Seamless user experience
- "Just works" on any kernel

**Cons:**
- Hidden behavior confuses debugging
- Users don't know which backend is active
- Performance surprises (iptables slower than eBPF)
- Inconsistent behavior across environments

**Decision**: Rejected. Explicit is better than implicit.

### eBPF Only (No Fallback)

**Pros:**
- Simplest implementation
- Clear focus on modern kernels
- No backward compatibility burden

**Cons:**
- Unusable on older systems (< Linux 5.10)
- Excludes enterprise deployments with locked-down kernels

**Decision**: Rejected. Explicit fallback provides flexibility without confusion.

### All Three Backends Simultaneously

**Pros:**
- Maximum flexibility
- Could dynamically switch

**Cons:**
- Massive complexity (rule synchronization)
- Significantly increased maintenance
- Unclear what "default" means

**Decision**: Rejected. One backend active at a time is simpler.

## Implementation Notes

**Startup Negotiation:**
```rust
fn select_network_backend(requested: Option<&str>, kernel_version: &KernelVersion) -> Result<Backend> {
    match requested {
        Some("ebpf") => {
            if kernel_supports_xdp(kernel_version) {
                Ok(Backend::eBPF)
            } else {
                Err("eBPF not supported on kernel < 5.10")
            }
        }
        Some("iptables") => Ok(Backend::Iptables),  // Always available
        Some("nftables") => {
            if kernel_supports_nftables(kernel_version) {
                Ok(Backend::Nftables)
            } else {
                Err("nftables not supported on kernel < 3.13")
            }
        }
        None => {
            // Default to eBPF if available
            if kernel_supports_xdp(kernel_version) {
                Ok(Backend::eBPF)
            } else {
                // Error: user must choose fallback explicitly
                Err("Kernel does not support eBPF (5.10+). Use --network-backend=iptables or --network-backend=nftables")
            }
        }
    }
}
```

**CLI Interface:**
```bash
# Explicit eBPF (default on capable kernels)
ferrocrate run --network-backend=ebpf ubuntu:22.04

# Explicit iptables fallback (for older kernels)
ferrocrate run --network-backend=iptables ubuntu:22.04

# Explicit nftables (for modern non-eBPF deployments)
ferrocrate run --network-backend=nftables ubuntu:22.04
```

**Logging at Startup:**
```
[INFO] Network backend selection:
       Kernel: Linux 5.15.0-56-generic
       eBPF support: Yes (XDP/TC available)
       Selected backend: eBPF (default)

[INFO] Network backend selection:
       Kernel: Linux 4.15.0-140-generic
       eBPF support: No (requires 5.10+)
       Selected backend: ERROR - must specify --network-backend=iptables or --network-backend=nftables
```

## References

- [ADR-004: eBPF for Networking](ADR-004-ebpf-for-networking.md)
- [Linux XDP (eXpress Data Path)](https://www.kernel.org/doc/html/latest/networking/XDP/)
- [Linux Traffic Control (TC)](https://man7.org/linux/man-pages/man8/tc.8.html)
- [iptables Reference](https://linux.die.net/man/8/iptables)
- [nftables Wiki](https://wiki.nftables.org/)
- PRD Requirements: NET-06, COMPAT-08
