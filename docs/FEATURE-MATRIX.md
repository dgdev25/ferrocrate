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

Snapshot: 2026-08-22, `main` at `2aa9715c`.

## Host tiers

| Tier | Status | Evidence |
|---|---|---|
| Rootful Ubuntu 26.04 x86_64 (qualified baseline) | Supported | [`host-matrix/2026-08-21-four-distro-privileged-rerun-current-head-5cd9d154.md`](evidence/host-matrix/2026-08-21-four-distro-privileged-rerun-current-head-5cd9d154.md) |
| Debian 13 / Fedora 42 / Rocky 9.8 rootful network rows | Supported | same four-distro rerun witness above |
| Rootless per-distribution (doctor, PTY, published IPv4) | Partial: Rocky is gated on `SO_PEERPIDFD`; the packaged Ubuntu 24.04+ AppArmor mechanism passes with `kernel.apparmor_restrict_unprivileged_userns=1` | The [packaged-profile qualification](evidence/host-matrix/2026-08-24-ubuntu-rootless-apparmor-profile.md) supersedes the historical host-wide sysctl relaxation for Ubuntu |
| Native Windows/macOS runtimes | Unsupported (deferred) | [`verification/2026-08-21-cross-target-current-head-0d0bdf3f.md`](evidence/verification/2026-08-21-cross-target-current-head-0d0bdf3f.md) |

## Product areas

| Area | Status | Boundary / evidence |
|---|---|---|
| Image pull (warm), list, inspect, tag, remove | Supported | [`performance/benchmark-register.md`](evidence/performance/benchmark-register.md) (paired ten-feature snapshot at `4e515d87`) |
| Image save/load, export/import | Supported | [`docker-api/2026-08-21-api-endpoint-completion.md`](evidence/docker-api/2026-08-21-api-endpoint-completion.md) |
| Registry auth/TLS, transient retry (429/5xx/timeout) | Supported (local fixture scope) | [`verification/2026-08-21-registry-transient-retry-current-head.md`](evidence/verification/2026-08-21-registry-transient-retry-current-head.md) |
| External live-registry exchange (pull/push beyond fixture) | Experimental | not claimed by any current evidence; boundary recorded in registry retry evidence |
| Dockerfile build, cache identity, provenance | Supported | [`build/2026-08-22-parallel-build-graphs.md`](evidence/build/2026-08-22-parallel-build-graphs.md) |
| Dockerfile secrets/SSH mounts | Supported (root-qualified on this host) | [`build/2026-08-21-build-secrets-ssh-mounts.md`](evidence/build/2026-08-21-build-secrets-ssh-mounts.md) |
| Container lifecycle (create/start/stop/kill/wait/restart) | Supported | [`verification/2026-08-21-docker-tty-container-lifecycle-current-head.md`](evidence/verification/2026-08-21-docker-tty-container-lifecycle-current-head.md) |
| Logs, exec, attach, TTY, resize | Supported | same TTY lifecycle witness; PTY qualification [`verification/2026-08-21-pty-docker-qualification-current-head-b8d464d4.md`](evidence/verification/2026-08-21-pty-docker-qualification-current-head-b8d464d4.md) |
| Named and bind volumes, read-only mounts | Supported | [`verification/2026-08-21-rootless-shared-compose-fixed-current-head-c7c15505.md`](evidence/verification/2026-08-21-rootless-shared-compose-fixed-current-head-c7c15505.md) |
| Bridge networking via iptables and nftables | Supported | four-distro privileged rerun witness (host tiers above) |
| Published IPv4 ports (rootful and rootless) | Supported | [`verification/2026-08-19-rootless-published-port-fedora-rocky-current-head.md`](evidence/verification/2026-08-19-rootless-published-port-fedora-rocky-current-head.md) |
| DNS, firewall allow/deny, MTU, WireGuard overlay | Supported | four-distro privileged rerun witness (host tiers above) |
| IPv6 address lifecycle | Supported | [`performance/2026-08-21-docker-ipv6-comparison.md`](evidence/performance/2026-08-21-docker-ipv6-comparison.md) |
| Published IPv6 ports / global IPv6 traffic | Host-blocked: no upstream IPv6 route on any current host | [`verification/2026-08-19-rootless-ipv6-guest-boundary-current-head.md`](evidence/verification/2026-08-19-rootless-ipv6-guest-boundary-current-head.md) |
| eBPF published ports | Experimental: opt-in (`FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS=1` + two host sysctls); iptables/nftables stay the supported path | [`verification/2026-08-22-ebpf-published-port-reverse-path-resolved.md`](evidence/verification/2026-08-22-ebpf-published-port-reverse-path-resolved.md) |
| Rootless run/pull/volumes/slirp/Compose/CRI | Supported on the qualified tier; hosts denying nested user namespaces fail closed with diagnostics. Ubuntu 24.04+ uses the shipped AppArmor profile instead of a host-wide sysctl relaxation. | [`rootless/2026-08-21-context-socket-diagnostics.md`](evidence/rootless/2026-08-21-context-socket-diagnostics.md), [restricted-policy profile proof](evidence/host-matrix/2026-08-24-ubuntu-rootless-apparmor-profile.md) |
| Compose (up/down, volumes, secrets/configs, health, read-only rootfs, shared project network) | Supported on qualified tier | six-case corpus witness (volumes row above) |
| Compose profiles/scale/watch paired measurement | Not yet measured | planned row in [`performance/benchmark-register.md`](evidence/performance/benchmark-register.md) |
| Docker Engine API | Supported: 89 declared cases, 86 implemented, 0 partial, 3 explicitly unsupported | [`verification/2026-08-21-docker-tty-container-lifecycle-current-head.md`](evidence/verification/2026-08-21-docker-tty-container-lifecycle-current-head.md) (count refreshed 2026-08-22) |
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

## Explicitly unsupported (fail-closed)

| Boundary | Behavior | Evidence |
|---|---|---|
| `POST /plugins/pull` | 404 with explicit message | matrix test in [`ferro-cli/tests/api_compat_matrix.rs`](../ferro-cli/tests/api_compat_matrix.rs) |
| `POST /auth` | 501 | same matrix test |
| `POST /containers/{id}/attach/ws` | 501 | same matrix test |
| `/networks/{id}/connect` and `/disconnect` | explicit unsupported boundary | [`docker-api/2026-08-21-api-endpoint-completion.md`](evidence/docker-api/2026-08-21-api-endpoint-completion.md) |
| Remote Docker Hub image search | local catalog only | [`verification/2026-08-19-docker-image-search-current-head.md`](evidence/verification/2026-08-19-docker-image-search-current-head.md) |
| Cross-platform native execution (Windows/macOS) | deferred; cross-target compile evidence only | cross-target witness (host tiers above) |

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
