# FerroCrate Roadmap

<!-- Maintained as the strategic follow-on to the FCNET ticket plan. -->

**Maturity:** feature-complete core with production-hardening gaps · **Last updated:** 2026-08-16 · HEAD `WORKTREE`

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
- [x] Add a CI/manual gate that rejects a claimed supported row without its evidence bundle.

### 2. Production `ferro-net` execution layers

*Why now:* the current networking table still records command-builder stubs for
custom bridges, DNS, firewall/port mapping, eBPF fallback, and bandwidth
limiting. **Size:** XL. *Source:* `docs/ROADMAP.md` NET-01, NET-04–06, NET-08, NET-10.

- [x] Define one capability-aware execution boundary for privileged network mutations.
- [x] Implement bridge execution with exact CIDR read-back verification and rollback on mismatch.
- [x] Extend read-back verification and rollback coverage to WireGuard route installation and interface teardown.
- [x] Extend read-back verification and rollback coverage to DNS, firewall, and traffic-control mutations.
- [x] Implement atomic DNS resolver publication with fsync and exact read-back.
- [x] Implement configurable veth MTU behavior (`FERROCRATE_VETH_MTU`) with range validation and exact `ip -j` read-back.
- [x] Publish container hosts files atomically with symlink refusal and exact read-back.
- [x] Add exact post-effect read-back to direct iptables/nftables rule application and deletion.
- [x] Implement port-mapping integration and eBPF fallback with provenance and cleanup.
- [x] Implement `tc` bandwidth limits with capability admission and exact rate read-back; privileged recovery coverage remains in the host matrix.
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

- [x] Apply parsed seccomp profiles in the container launch path; the runtime applies the resolved profile in `pre_exec` and retains ignored root-only denial coverage.
- [ ] Complete CRI pod-sandbox/container lifecycle methods and conformance fixtures.
- [x] Publish supported Docker Engine API versions and document the implemented high-value endpoint groups; endpoint gaps remain explicit unsupported errors.
- [ ] Add SDK/Compose contract tests while preserving authorization and witness mediation.

## Later

### 5. Release operations and scale

- [x] Add repeatable performance baselines and regression thresholds; `scripts/perf/run-baseline.sh` produces metadata and benchmark artifacts, while existing scripts enforce their SLOs.
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
- 2026-08-16 — corrected tool capability detection to resolve binaries through `PATH`, avoiding false negatives from nonstandard `ip --version` exit codes.
- 2026-08-16 — bridge execution now verifies post-effect identity/CIDRs and rolls back on read-back mismatch; the full matrix runner was rerun green.
- 2026-08-16 — WireGuard apply now verifies expected IPv4/IPv6 routes and removal verifies interface absence.
- 2026-08-16 — added atomic DNS resolver publication with symlink refusal, fsync, and exact read-back coverage.
- 2026-08-16 — firewall rule application/deletion now verifies exact iptables presence or nftables handles after each mutation.
- 2026-08-16 — traffic-control mutation now requires the shared host capability gate and verifies the requested TBF rate exactly; the existing runtime port-map/eBPF paths are recorded as the production integration boundary.
- 2026-08-16 — container hosts publication now uses an atomic, symlink-safe, fsynced write with exact read-back; resolver publication uses the shared atomic DNS writer.
- 2026-08-16 — nftables and traffic-control read-back now use the shared `ferro-net` command-capture executor instead of runtime-local subprocess handling.
- 2026-08-16 — bridge-mode veth creation accepts a validated `FERROCRATE_VETH_MTU` and fails closed when kernel read-back does not report the requested MTU.
- 2026-08-16 — idempotent network cleanup now routes through `ferro-net`’s executor, centralizing subprocess errors and safe missing-resource handling.
- 2026-08-16 — added a CI/manual host-matrix evidence gate that rejects qualified rows with missing or mismatched evidence artifacts.
- 2026-08-16 — audited seccomp wiring: resolved profiles are applied in the container launch `pre_exec` path; roadmap status corrected from stale unchecked state.
- 2026-08-16 — published the Docker API compatibility declaration for advertised versions, endpoint groups, and authorization behavior.
- 2026-08-16 — published the CRI method matrix; it records the implemented runtime/image RPCs and explicitly identifies absent pod/container lifecycle RPCs.
- 2026-08-16 — wired repeatable startup/OCI/rootless performance baselines into a manual artifact-upload workflow.
