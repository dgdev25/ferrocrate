# Ferrocrate

Ferrocrate is a Linux-first container runtime and Docker-compatible local
development engine written in Rust. It provides OCI image execution, a Docker
API surface, Compose and CRI entry points, durable lifecycle state, mediated
networking, and optional AI-assisted restart/resource signals.

## Current support scope

The strongest qualified baseline is rootful Ubuntu 26.04 on x86_64 with the
tested kernel/tooling recorded in `docs/evidence/host-matrix/`. Rootful bridge,
IPv4/IPv6 lifecycle, DNS, firewall backends, MTU, WireGuard, teardown, recovery,
OCI fixtures, Docker API cases, and CRI socket fixtures have reproducible local
evidence.

Rootless image pull/run, slirp networking, cgroup discovery, volume-store
operations, and the opt-in Compose/CRI fixtures are qualified on the current
Ubuntu host. Rootless bridge provisioning on hosts that deny nested mount
namespaces, broader resource-limit enforcement, other distributions, and live
eBPF published-port checksum delivery remain qualification gates.
Published-port eBPF is fail-closed by default; use iptables or nftables for the
supported path.

## Quick start

```bash
cargo build --release -p ferro-cli
./target/release/ferro-cli images
./target/release/ferro-cli run --rm alpine:3.20 /bin/true
```

Use `scripts/verify-rootless.sh` to check rootless prerequisites. Privileged
network and host-matrix checks require a disposable Linux host and are not
implied by a successful unprivileged build.

AI behavior is local and bounded: `FERROCRATE_AI=0` disables inference,
monitoring, and adaptive lifecycle paths; predictive signals do not perform
general-purpose scheduling, and automatic cgroup changes require the separate
operator gate `FERROCRATE_AI_ACT=1` plus a configured ceiling. Training and
online data collection have independent consent and approval gates.

## Docker comparison

The latest three-round, no-skip host-local ten-feature comparison uses the
Docker Hub-independent `quay.io/libpod/alpine:latest` fixture. The
[`summary`](docs/evidence/performance/2026-08-18-docker-comparison-current-head-6ce509bc-summary.md),
[`iptables`](docs/evidence/performance/2026-08-18-docker-comparison-current-head-6ce509bc-iptables.md),
and
[`nftables`](docs/evidence/performance/2026-08-18-docker-comparison-current-head-6ce509bc-nftables.md)
measurements are archived with host, backend, image, and round metadata.
Both report command-path medians and explicitly do not claim universal Docker
parity, cross-platform support, or production superiority.

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SUPPORT.md`](SUPPORT.md), and the [support policy](docs/operations/support-policy.md),
and the [indie-release plan](docs/INDIE_RELEASE_PLAN.md). Security reports
should follow [`SECURITY.md`](SECURITY.md). GitHub workflows are intentionally
not included; reproducible local/release gates are documented in
[`docs/operations/external-ci.md`](docs/operations/external-ci.md).

## Project status

This repository is not yet declaring a universal Docker replacement. A public
license decision is still required before open-source publication; no license
is implied by this repository until that decision is recorded.
