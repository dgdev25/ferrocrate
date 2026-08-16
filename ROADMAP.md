# FerroCrate Roadmap

<!-- Maintained as the strategic follow-on to the FCNET ticket plan. -->

**Maturity:** feature-complete core with production-hardening gaps · **Last updated:** 2026-08-16 · HEAD `d283473`

This roadmap separates the completed FCNET lifecycle work from the remaining
host qualification and execution-layer work. The authoritative ticket detail
remains in `docs/superpowers/plans/2026-08-15-p0-network-execution-tickets.md`.

## Now

### 1. Supported-host network qualification matrix

*Why now:* bridge and IPv6 lifecycle evidence exists on one Linux host, while
`docs/ROADMAP.md` still identifies kernel/distribution coverage as the release
gap. **Size:** L. *Source:* NET-01/04/05/06/07/08/09/10 status table and FCNET-103/104/105 evidence.

- [x] Define the supported distribution/kernel capability matrix and required tools.
- [x] Add a non-destructive preflight that records distro, kernel, capabilities, WireGuard, iproute2, nftables/iptables, DNS, MTU, and traffic-control support.
- [x] Parameterize the privileged bridge/IPv6, managed-overlay, and teardown harnesses by matrix row.
- [x] Run and archive one green evidence bundle for the first supported row, including cleanup verification.
- [ ] Add a CI/manual gate that rejects a claimed supported row without its evidence bundle.

### 2. Production `ferro-net` execution layers

*Why now:* the current networking table still records command-builder stubs for
custom bridges, DNS, firewall/port mapping, eBPF fallback, and bandwidth
limiting. **Size:** XL. *Source:* `docs/ROADMAP.md` NET-01, NET-04–06, NET-08, NET-10.

- [x] Define one capability-aware execution boundary for privileged network mutations.
- [ ] Implement bridge and route execution with read-back verification and rollback.
- [ ] Implement DNS/hosts and MTU behavior with explicit unsupported-capability errors.
- [ ] Implement nftables/iptables port mapping and eBPF fallback with provenance and cleanup.
- [ ] Implement `tc` bandwidth limits with read-back and recovery tests.
- [ ] Migrate public runtime paths from direct shelling-out to the execution boundary.

## Next

### 3. Physically separate-host FCNET-105 qualification

*Why now:* FCNET-105 is qualified across isolated namespaces; operational
deployment may require independent machines and a transport-aware test harness.
**Size:** L. *Source:* FCNET-105 follow-on note in `docs/ROADMAP.md`.

- [ ] Decide whether physical multi-host coverage is a release requirement.
- [ ] Provide host/agent/netd endpoint configuration and clock/MTU/route checks.
- [ ] Re-run authenticated packet flow, stale revision, rollback, recovery, and key rotation across two machines.
- [ ] Archive logs, topology, key IDs (never private keys), and cleanup results.

### 4. Security and API parity hardening

*Why now:* the broader roadmap identifies seccomp application, CRI methods, and
Docker API coverage as independent partial areas. **Size:** XL. *Source:*
`docs/ROADMAP.md` SEC-02, COMPAT-09, and Docker compatibility checklist.

- [ ] Apply parsed seccomp profiles in the container launch path and verify denial behavior.
- [ ] Complete CRI pod-sandbox/container lifecycle methods and conformance fixtures.
- [ ] Publish supported Docker Engine API versions and complete high-value endpoint coverage.
- [ ] Add SDK/Compose contract tests while preserving authorization and witness mediation.

## Later

### 5. Release operations and scale

- [ ] Add repeatable performance baselines and regression thresholds.
- [ ] Expand rootless networking and supported-host prerequisites.
- [ ] Add off-host witness retention, replication, and operational recovery procedures.

## Shipped

- [x] FCNET-101 durable named-network lifecycle — completed 2026-08-16.
- [x] FCNET-102 authorized CLI/Docker network mediation — completed 2026-08-16.
- [x] FCNET-103 privileged single-host bridge qualification — completed 2026-08-16.
- [x] FCNET-104 IPv6 named-network lifecycle — completed 2026-08-16.
- [x] FCNET-105 authenticated isolated-host managed-overlay qualification — completed 2026-08-16.

### Current matrix row

- Ubuntu 26.04 LTS · Linux 7.0.0-29-generic · x86_64
- Privileged capability row: `CAP_NET_ADMIN=yes`; iproute2 6.19.0, WireGuard tools 1.0.20250521, nftables 1.1.6, iptables 1.8.11, tc 6.19.0, systemd-resolved 259.5, iputils 20250605.
- Evidence: `docs/evidence/host-matrix/ubuntu-26.04-kernel-7.0.0-29/preflight.txt` and `bridge-ipv6-lifecycle.log`.
- The row is reproducible with `sudo env ... bash scripts/run-host-matrix-row.sh ubuntu-26.04-kernel-7.0.0-29`, which also runs the managed-overlay kernel and authenticated manager→agent→netd gates.
- The privileged bridge/IPv6 lifecycle gate passed after adding `nodad` to the production IPv6 bridge-address command; this is a kernel portability fix, not a test-only workaround.
- [x] First-row supporting checks pass for read-only MTU, nftables/iptables, `tc`, DNS resolver, and WireGuard availability (`supporting-checks.txt`).

## Update log

- 2026-08-16 `d283473` — created the follow-on qualification, execution-layer, multi-host, and parity roadmap; started host-matrix preflight.
- 2026-08-16 — qualified the first Ubuntu 26.04/kernel 7.0 matrix row and fixed IPv6 DAD portability with `nodad`.
- 2026-08-16 — added `HostCapabilities` admission to the shared executor and wired bridge mutations to fail closed before effects when Linux/root/CAP_NET_ADMIN/iproute2 are unavailable.
