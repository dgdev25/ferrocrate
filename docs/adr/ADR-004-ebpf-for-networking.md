# ADR-004: eBPF for Networking

## Status

**Amended** (February 11, 2026 - Added iptables/nftables fallback per AI consensus)

## Context

Container networking traditionally uses iptables/nftables for:
- NAT (Network Address Translation) for container-to-external traffic
- Port forwarding (host port -> container port)
- Network policy enforcement
- Load balancing

**iptables Problems:**
- Linear rule evaluation (O(n) complexity)
- Rules are global; container runtimes modify system-wide firewall
- Conflicts with host firewall management (ufw, firewalld, cloud-provider rules)
- Difficult to debug which rule matched
- Performance degrades with many rules

**eBPF (Extended Berkeley Packet Filter):**
- Kernel bytecode executed in sandboxed environment
- Just-in-time compiled to native code
- O(1) lookup via hash maps
- Per-container network policies without global state
- Observability: Trace every packet decision
- No interaction with host iptables

**Kernel Requirements:**
- eBPF basic features: kernel 4.10+
- eBPF socket operations: kernel 4.18+
- eBPF sockmap (socket redirection): kernel 4.20+
- eBPF sk_lookup: kernel 5.7+

FerroCrate targets kernel 5.10+ minimum, ensuring eBPF availability.

## Decision

**Use eBPF as primary networking backend with iptables/nftables as officially supported fallback.**

**Primary Path (eBPF - kernel 5.10+):**
1. **Bridge replacement**: eBPF programs handle inter-container traffic
2. **Port forwarding**: eBPF `sk_lookup` redirects host port traffic to container sockets
3. **NAT**: eBPF connection tracking replaces iptables MASQUERADE
4. **Network policy**: eBPF maps store per-container allow/deny lists
5. **Observability**: All packet decisions traceable via eBPF maps

**Fallback Behavior (explicit opt-in):**
- If eBPF unavailable (older kernel < 5.10, locked-down system), user can explicitly request fallback via `--network-backend=iptables` or `--network-backend=nftables`
- Fallback is **not silent** — logs clearly indicate which backend is active
- iptables/nftables fallback uses identical feature set as eBPF path; behavior is transparent to user
- Both backends coexist in binary; kernel capabilities determine which is available

## Consequences

### Positive

- **No firewall conflicts**: FerroCrate never touches host iptables/nftables
- **Performance**: O(1) lookups vs O(n) iptables chains
- **Isolation**: Container network rules are independent of host rules
- **Observability**: Every networking decision is traceable
- **Cloud compatibility**: No conflicts with cloud provider firewall agents

### Negative

- **Kernel requirement**: Requires kernel 5.10+ with eBPF enabled
- **Privilege requirement**: eBPF requires `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`
  - For rootless mode: Requires kernel 5.12+ with unprivileged eBPF
  - May require `--rootful` for networking on older systems
- **Complexity**: eBPF programs are harder to develop and debug than iptables rules

### Neutral

- **Learning curve**: Users familiar with `iptables -L` cannot inspect FerroCrate networking
- **Tooling**: Need custom CLI commands for network debugging

## Alternatives Considered

### iptables (Traditional)

**Pros:**
- Universal compatibility
- Well-understood debugging
- No special kernel features required

**Cons:**
- Global state conflicts with host firewall
- Linear rule evaluation
- Docker networking issues with uwf/firewalld are notorious

**Decision**: Rejected. iptables conflicts are a top user complaint with Docker.

### nftables (Modern Replacement)

**Pros:**
- Better syntax than iptables
- Unified interface (replaces iptables, ip6tables, arptables, ebtables)
- More efficient than iptables

**Cons:**
- Still global state; conflicts with host firewall
- Not as performant as eBPF for container-scale
- Does not solve the fundamental "modifying system firewall" problem

**Decision**: Rejected. nftables shares iptables' core problems.

### Cilium (eBPF Platform)

**Pros:**
- Battle-tested eBPF networking
- Kubernetes-native
- Rich observability

**Cons:**
- Heavyweight; designed for Kubernetes clusters
- Overkill for single-host container runtime
- Adds external dependency

**Decision**: Rejected. FerroCrate implements lightweight eBPF networking directly.

## Implementation Notes

**eBPF Program Types Used:**
- `BPF_PROG_TYPE_SCHED_CLS` - Traffic classification
- `BPF_PROG_TYPE_XDP` - Fast packet processing (optional optimization)
- `BPF_PROG_TYPE_SK_LOOKUP` - Port forwarding
- `BPF_PROG_TYPE_CGROUP_SKB` - Per-container packet filtering

**Required Kernel Config:**
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUP_BPF=y
CONFIG_NET_CLS_BPF=y
CONFIG_BPF_EVENTS=y
```

**Rootless eBPF (kernel 5.12+):**
```bash
# Allow unprivileged eBPF
sysctl kernel.unprivileged_bpf_disabled=0
```

## References

- [eBPF Documentation](https://ebpf.io/)
- [Cilium eBPF Networking](https://docs.cilium.io/en/stable/network/ebpf/)
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)
- PRD Requirements: NET-06, NET-08, NET-10
