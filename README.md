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

Rootless image pull/run, slirp networking, cgroup discovery, and volume-store
operations are qualified on matching hosts. Rootless workload-mounted volumes,
Compose/CRI end-to-end behavior, other distributions, and live eBPF published-
port checksum delivery remain qualification gates. Published-port eBPF is
fail-closed by default; use iptables or nftables for the supported path.

## Quick start

```bash
cargo build --release -p ferro-cli
./target/release/ferro-cli images
./target/release/ferro-cli run --rm alpine:3.20 /bin/true
```

Use `scripts/verify-rootless.sh` to check rootless prerequisites. Privileged
network and host-matrix checks require a disposable Linux host and are not
implied by a successful unprivileged build.

## Docker comparison

The latest host-local ten-feature comparison is in
[`docs/evidence/performance/2026-08-18-docker-comparison.md`](docs/evidence/performance/2026-08-18-docker-comparison.md).
The matching nftables run is in
[`docs/evidence/performance/2026-08-18-docker-comparison-nftables.md`](docs/evidence/performance/2026-08-18-docker-comparison-nftables.md).
Both report three-round medians and explicitly do not claim universal Docker
parity, cross-platform support, or production superiority.

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md), the [support policy](docs/operations/support-policy.md),
and the [indie-release plan](docs/INDIE_RELEASE_PLAN.md). Security reports
should follow [`SECURITY.md`](SECURITY.md). GitHub workflows are intentionally
not included; reproducible local/release gates are documented in
[`docs/operations/external-ci.md`](docs/operations/external-ci.md).

## Project status

This repository is not yet declaring a universal Docker replacement. A public
license decision is still required before open-source publication; no license
is implied by this repository until that decision is recorded.
