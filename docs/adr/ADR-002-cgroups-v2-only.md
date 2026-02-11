# ADR-002: cgroups v2 Only

## Status

**Accepted**

## Context

Linux cgroups (control groups) provide resource limiting, accounting, and isolation for process groups. Two versions exist:

**cgroups v1:**
- Multiple hierarchies (one per controller: cpu, memory, io, etc.)
- Each controller mounted separately at `/sys/fs/cgroup/<controller>`
- Complex management due to inconsistent interfaces across controllers
- Legacy but still supported by kernel

**cgroups v2:**
- Unified hierarchy (single tree at `/sys/fs/cgroup`)
- Consistent interface across all controllers
- Thread mode for threaded workloads
- Better delegation for rootless containers
- Pressure stall information (PSI) for resource pressure monitoring

Major distributions shipping cgroups v2 by default:
- Fedora 31+ (October 2019)
- Ubuntu 22.04+ (April 2022)
- RHEL 9+ (May 2022)
- Debian 11+ (August 2021)
- Arch Linux (October 2021)

Kubernetes requires cgroups v2 for newer features (PodResources API, in-place updates).

## Decision

**Support cgroups v2 only. No cgroups v1 support will be implemented.**

This is a hard requirement:
- FerroCrate will fail to start on systems with only cgroups v1 mounted
- No fallback or compatibility layer for v1 will be provided
- Documentation will clearly state kernel 5.10+ with cgroups v2 as minimum requirement

## Consequences

### Positive

- **Simplified codebase**: Single code path for resource management; no v1/v2 branching
- **Rootless container support**: v2 delegation model works naturally with user namespaces
- **Consistent interface**: All controllers use same file-based API
- **Modern features**: Access to PSI (pressure stall information) for intelligent resource decisions
- **Future-proof**: v2 is the Linux standard; v1 is effectively deprecated

### Negative

- **Legacy system support**: Users on older distributions (Ubuntu 20.04, RHEL 8) cannot use FerroCrate
- **Migration requirement**: Some users must upgrade kernels/distributions to adopt FerroCrate

### Neutral

- **Market timing**: By FerroCrate v1.0 release (2026), cgroups v2 will be universal on supported distributions

## Alternatives Considered

### Support Both v1 and v2

**Pros:**
- Maximum compatibility with older systems
- Smoother migration path for conservative enterprises

**Cons:**
- Significant code complexity (dual code paths)
- Testing burden doubles
- v1 lacks clean delegation for rootless containers
- Perpetual maintenance of legacy code

**Decision**: Rejected. The complexity cost outweighs the diminishing value of v1 support as distributions have moved to v2.

### v1 Only (Docker-compatible)

**Pros:**
- Compatibility with existing Docker deployments
- Well-tested patterns

**Cons:**
- Dead-end technology path
- Poor rootless container support
- Misses v2 improvements (PSI, unified hierarchy)

**Decision**: Rejected. v1 is deprecated; building new infrastructure on it would be technically irresponsible.

## Implementation Notes

cgroups v2 mount detection:
```bash
# Check for unified hierarchy
mountpoint -q /sys/fs/cgroup/cgroup.controllers && echo "v2" || echo "v1"
```

Required kernel config:
```
CONFIG_CGROUPS=y
CONFIG_CGROUP_V2=y
CONFIG_CGROUP_CPU=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_CPUSET=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_CGROUP_MEMORY=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_RDMA=y
CONFIG_CGROUP_MISC=y
```

## References

- [cgroups v2 Kernel Documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [Red Hat: cgroups v2](https://www.redhat.com/en/blog/cgroups-v2-better-resource-management-linux)
- PRD Requirements: CLM-09, SEC-01, COMPAT-07
