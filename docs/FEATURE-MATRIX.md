# Ferrocrate feature matrix (authoritative)

This is the single authoritative support-contract matrix. Every product claim
about what Ferrocrate supports must trace to a row here, and every row links
dated evidence. If a document disagrees with this matrix, this matrix wins
until the evidence changes.

Status vocabulary (extends `docs/compatibility/reference-index.md`):

- **Supported** — repeatable fixture passes on the qualified host tier and the
  behavior is part of the advertised contract.
- **Experimental** — implementation and a passing fixture exist, but the
  feature is opt-in, narrowly scoped, or not yet portable across host tiers.
- **Unsupported** — the request is rejected explicitly and fail-closed.
- **Host-blocked** — proof requires a host capability this repository's
  current hosts do not provide; the exact blocker is recorded.

Snapshot: 2026-08-25, Round 10 fleet control-plane implementation branch.

## Host tiers

| Tier | Status | Evidence |
|---|---|---|
| Rootful Ubuntu 26.04 x86_64 (qualified baseline) | Supported | [`host-matrix/2026-08-21-four-distro-privileged-rerun-current-head-5cd9d154.md`](evidence/host-matrix/2026-08-21-four-distro-privileged-rerun-current-head-5cd9d154.md) |
| Debian 12 / Debian 13 / Fedora 42 rootful rows | Supported | four-distro rerun witness above; 2026-08-25 re-run [`host-matrix/rows.tsv`](evidence/host-matrix/rows.tsv) |
| Rocky 9, Linux 5.14 (RHEL kernel) | Qualified 60/60 with opt-in `legacy-peercred`; default remains unavailable without `SO_PEERPIDFD` | [`host-matrix/rocky-9-kernel-5.14/BOUNDARY.md`](evidence/host-matrix/rocky-9-kernel-5.14/BOUNDARY.md) |
| Alpine 3.22, Linux 6.12, x86_64 (musl) | Supported | [`host-matrix/alpine-3.22-kernel-6.12/README.md`](evidence/host-matrix/alpine-3.22-kernel-6.12/README.md) |
| Ubuntu 24.04, Linux 6.17, aarch64 (Oracle A1) | Supported | [`host-matrix/aarch64-linux-kernel-6.17/README.md`](evidence/host-matrix/aarch64-linux-kernel-6.17/README.md) |
| Ubuntu 20.04 HWE, Linux 5.15, x86_64 | Qualified 60/60 with opt-in `legacy-peercred`; default remains unavailable without `SO_PEERPIDFD` | [`host-matrix/ubuntu-20.04-kernel-5.15/BOUNDARY.md`](evidence/host-matrix/ubuntu-20.04-kernel-5.15/BOUNDARY.md) |
| Rootless per-distribution (doctor, PTY, published IPv4) | Partial: hosts without `SO_PEERPIDFD` fail closed by default; `legacy-peercred` is an explicit downgrade with a PID-reuse race | The [packaged-profile qualification](evidence/host-matrix/2026-08-24-ubuntu-rootless-apparmor-profile.md) supersedes the historical host-wide sysctl relaxation for Ubuntu; old-kernel boundaries are recorded above |
| Windows 11 via WSL2 backend | Implemented; native/browser acceptance on a Windows 11 VM is pending | Backend contract and installer tests in `ferro-desktop/tests/backend_contract.rs` and `scripts/test-desktop-backend-contracts.sh`; a Linux/WSL run is not Windows-host acceptance. The Windows 11 VM rerun remains recorded in the Round 10 plan |
| macOS Tahoe via Linux VM backend | Implemented; native/browser acceptance on a Tahoe VM is pending | vfkit-first/QEMU-fallback provisioning contract in `scripts/install-macos.sh`; non-macOS runs explicitly skip this row. The Tahoe VM rerun remains recorded in the Round 10 plan |

## Product areas

| Area | Status | Boundary / evidence |
|---|---|---|
| Image pull (warm), list, inspect, tag, remove, and Docker Hub search proxy | Supported; Hub search uses a five-second total timeout and returns a clean 503-class offline error | [`compatibility/parity-scoreboard.md`](compatibility/parity-scoreboard.md) (`registry-search`) |
| Image save/load, export/import | Supported | [`docker-api/2026-08-21-api-endpoint-completion.md`](evidence/docker-api/2026-08-21-api-endpoint-completion.md) |
| Registry auth/TLS, transient retry (429/5xx/timeout) | Supported (local fixture scope) | [`verification/2026-08-21-registry-transient-retry-current-head.md`](evidence/verification/2026-08-21-registry-transient-retry-current-head.md) |
| LAN image mirror (mDNS discovery, read-only registry-v2 pulls) | Experimental: opt-in, private-IPv4 listener, digest verified with registry fallback | [`networking/2026-08-25-lan-image-mirror.md`](evidence/networking/2026-08-25-lan-image-mirror.md), [`design/lan-image-mirror.md`](design/lan-image-mirror.md) |
| External live-registry exchange (pull/push beyond fixture) | Experimental | not claimed by any current evidence; boundary recorded in registry retry evidence |
| Dockerfile build, cache identity, provenance | Supported | [`build/2026-08-22-parallel-build-graphs.md`](evidence/build/2026-08-22-parallel-build-graphs.md) |
| BuildKit session builds | Unsupported: `/session` and `/build?version=2` fail cleanly and direct clients to `DOCKER_BUILDKIT=0`; implementation is sized at 17–29 engineering days | [`docker-client-conformance/2026-08-24-buildkit-fallback.md`](evidence/docker-client-conformance/2026-08-24-buildkit-fallback.md), [`design/buildkit-session-endpoint.md`](design/buildkit-session-endpoint.md), merge `c59f6e2a` |
| Dockerfile secrets/SSH mounts | Supported (root-qualified on this host) | [`build/2026-08-21-build-secrets-ssh-mounts.md`](evidence/build/2026-08-21-build-secrets-ssh-mounts.md) |
| Container lifecycle (create/start/stop/kill/wait/restart) | Supported | [`verification/2026-08-21-docker-tty-container-lifecycle-current-head.md`](evidence/verification/2026-08-21-docker-tty-container-lifecycle-current-head.md) |
| Logs, exec, attach (TCP hijack and WebSocket), TTY, resize | Supported | [`compatibility/parity-scoreboard.md`](compatibility/parity-scoreboard.md) (`container-attach-websocket`); PTY qualification [`verification/2026-08-21-pty-docker-qualification-current-head-b8d464d4.md`](evidence/verification/2026-08-21-pty-docker-qualification-current-head-b8d464d4.md) |
| Container log drivers | `json-file` supported; `journald` and `syslog` supported behind crate features with live proofs; signed manifest plugins supported (fixture scope). Readback is supported only for `json-file`, matching Docker. | [`log-drivers/2026-08-24-live-drivers.md`](evidence/log-drivers/2026-08-24-live-drivers.md) |
| Docker-client classic-builder conformance | Supported: 60/60 pass, rootless and rootful, on every qualified row of the 2026-08-25 matrix re-run | [`compatibility/parity-scoreboard.md`](compatibility/parity-scoreboard.md), merge `363a7b24` |
| Named and bind volumes, read-only mounts | Supported | [`verification/2026-08-21-rootless-shared-compose-fixed-current-head-c7c15505.md`](evidence/verification/2026-08-21-rootless-shared-compose-fixed-current-head-c7c15505.md) |
| Bridge networking via iptables and nftables | Supported | four-distro privileged rerun witness (host tiers above) |
| Multi-network containers, Docker connect/disconnect, Compose multi-network services, and per-network DNS aliases | Supported on the rootful qualified tier; aliases are durable endpoint metadata and resolve only for peers sharing that network | [`compatibility/parity-scoreboard.md`](compatibility/parity-scoreboard.md) (`network-alias-nslookup`) |
| Published IPv4 ports (rootful and rootless) | Supported | [`verification/2026-08-19-rootless-published-port-fedora-rocky-current-head.md`](evidence/verification/2026-08-19-rootless-published-port-fedora-rocky-current-head.md) |
| DNS, firewall allow/deny, MTU, WireGuard overlay | Supported | four-distro privileged rerun witness (host tiers above) |
| IPv6 address lifecycle | Supported | [`performance/2026-08-21-docker-ipv6-comparison.md`](evidence/performance/2026-08-21-docker-ipv6-comparison.md) |
| Published IPv6 ports / global IPv6 traffic | Host-blocked: no upstream IPv6 route on any current host | [`verification/2026-08-19-rootless-ipv6-guest-boundary-current-head.md`](evidence/verification/2026-08-19-rootless-ipv6-guest-boundary-current-head.md) |
| eBPF published ports | Experimental: opt-in (`FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS=1` + two host sysctls); iptables/nftables stay the supported path | [`verification/2026-08-22-ebpf-published-port-reverse-path-resolved.md`](evidence/verification/2026-08-22-ebpf-published-port-reverse-path-resolved.md) |
| Rootless run/pull/volumes/slirp/Compose/CRI | Supported on the qualified tier; hosts denying nested user namespaces fail closed with diagnostics. Ubuntu 24.04+ uses the shipped AppArmor profile instead of a host-wide sysctl relaxation. | [`rootless/2026-08-21-context-socket-diagnostics.md`](evidence/rootless/2026-08-21-context-socket-diagnostics.md), [restricted-policy profile proof](evidence/host-matrix/2026-08-24-ubuntu-rootless-apparmor-profile.md) |
| Compose (up/down, volumes, secrets/configs, health, read-only rootfs, shared project network) | Supported on qualified tier | six-case corpus witness (volumes row above) |
| Compose profiles (`--profile`, `COMPOSE_PROFILES`), scale, and watch sync | Supported; genuine Compose-client rows are measured locally | [`performance/2026-08-25-compose-profiles-scale-watch.md`](evidence/performance/2026-08-25-compose-profiles-scale-watch.md), benchmark row B-068 |
| Docker Engine API | Supported: 89 declared cases, 86 implemented, 0 partial, 3 explicitly unsupported | [`verification/2026-08-21-docker-tty-container-lifecycle-current-head.md`](evidence/verification/2026-08-21-docker-tty-container-lifecycle-current-head.md) (count refreshed 2026-08-22) |
| Native CLI / Docker API unified engine state | Supported: daemon is the sole concurrent writer; containers, images, volumes, and networks are durable and visible across both surfaces and daemon restart | [`compatibility/unified-engine-state.md`](compatibility/unified-engine-state.md), [`verification/2026-08-24-unified-engine-state.md`](evidence/verification/2026-08-24-unified-engine-state.md) |
| CRI socket lifecycle (image + sandbox + container) | Supported (fixture scope; cross-distribution open) | [`verification/2026-08-21-rootless-compose-cri-current-head-5da6664c.md`](evidence/verification/2026-08-21-rootless-compose-cri-current-head-5da6664c.md) |
| Seccomp enforcement, capability/device restrictions | Supported | [`security/2026-08-19-seccomp-unprivileged-enforcement-current-head.md`](evidence/security/2026-08-19-seccomp-unprivileged-enforcement-current-head.md) |
| AppArmor / SELinux MAC enforcement | Supported on matching hosts | [`security/2026-08-21-local-mac-enforcement-current-head.md`](evidence/security/2026-08-21-local-mac-enforcement-current-head.md) |
| Crash/daemon-restart journal recovery, 100-container fault qualification | Supported | [`verification/2026-08-22-100-container-fault-qualification.md`](evidence/verification/2026-08-22-100-container-fault-qualification.md) |
| Host reboot recovery | Host-blocked: needs reboot-capable host | blocked row in benchmark register |
| Disk-full/ENOSPC rootful fixture | Host-blocked: `sudo -n` unavailable | same 100-container qualification witness (host-blocked rows) |
| Installer (install/upgrade/rollback/uninstall/migration, checksums) | Supported | [`release/2026-08-21-release-operational-gates-current-head-715581f3.md`](evidence/release/2026-08-21-release-operational-gates-current-head-715581f3.md) |
| AI assist (monitoring, predictive signals, adaptive restart) | Experimental: `FERROCRATE_AI=0` disables; `FERROCRATE_AI_ACT=1` gates autonomous actions | [`ai/2026-08-22-multi-container-lifecycle-qualification.md`](evidence/ai/2026-08-22-multi-container-lifecycle-qualification.md) |
| RVF image launcher/QEMU | Experimental (dry-run default) | [`rvf/2026-08-22-launcher-interop.md`](evidence/rvf/2026-08-22-launcher-interop.md) |
| Node/reconciliation supervisor | Experimental (single-node, no live cluster claim) | [`manager/2026-08-22-node-reconciliation-lifecycle.md`](evidence/manager/2026-08-22-node-reconciliation-lifecycle.md) |
| Desktop backend seam, loopback web bridge, and daemon-owned UX/API lifecycle | Implemented for `linux-native`, `wsl2`, and `macos-vm`; native acceptance remains bounded by the host-tier rows above | [`desktop/WEB-CONTROL-PLANE.md`](desktop/WEB-CONTROL-PLANE.md), backend contract tests, and `scripts/test-desktop-real-daemon.sh`, which passes only the host-selected backend and explicitly skips unavailable host backends |
| Embedded local dashboard (`ferrocrate dashboard`) | Supported on the qualified Linux tier: the release CLI embeds the Forge frontend, starts no listener unless invoked, uses a per-launch bearer token, and requires TLS plus an explicit operator gate for non-loopback binds | [`desktop/DASHBOARD-TEST-REPORT-2026-08-25.md`](desktop/DASHBOARD-TEST-REPORT-2026-08-25.md) |
| Fleet browser control plane (`ferro-mgr fleet-ui`) | Supported on the qualified Linux manager tier: TLS by default, operator mTLS to the existing admin gRPC, certificate-bound view/operate sessions, append-only action witnesses, and host container/deploy/health controls over the existing node mTLS stream | [`fleet/FLEET-TEST-REPORT-2026-08-25.md`](fleet/FLEET-TEST-REPORT-2026-08-25.md) |

## Explicitly unsupported (fail-closed)

| Boundary | Behavior | Evidence |
|---|---|---|
| `POST /plugins/pull` | 404 with explicit message | matrix test in [`ferro-cli/tests/api_compat_matrix.rs`](../ferro-cli/tests/api_compat_matrix.rs) |
| `POST /auth` | 501 | same matrix test |
| Host-native Windows/macOS engine execution without WSL2/Linux VM | Unsupported; the supported desktop architecture runs the Linux engine through `wsl2` or `macos-vm` | host-tier rows above |

## Performance snapshot

The paired ten-feature Docker comparison lives in the
[`benchmark register`](evidence/performance/benchmark-register.md). Current
paired snapshot: `4e515d87`
([iptables](evidence/performance/2026-08-21-docker-comparison-current-head-4e515d87-iptables.md),
[nftables](evidence/performance/2026-08-21-docker-comparison-current-head-4e515d87-nftables.md)).
All numbers are host-local medians and must be refreshed per release candidate;
they are not parity or superiority claims.

## Maintenance rule

A row may change status only in the same change that adds or updates its
evidence link. Historical counts elsewhere are not status claims; when a
document and this matrix disagree, update the document or link the new
evidence here in the same commit.
