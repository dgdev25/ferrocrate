<p align="center">
  <img src="docs/assets/banner.svg" alt="Ferrocrate — the Docker-compatible container engine, written in Rust" width="100%">
</p>

Ferrocrate is a Rust container engine with a native CLI and a Docker-compatible
API. The real `docker` CLI conformance suite has 85 passing scenarios in both
the default BuildKit and classic build modes. See the
[feature matrix](docs/FEATURE-MATRIX.md) for the support contract and evidence.

## Scope

- Linux engine execution uses Linux namespaces, cgroups, and networking.
- Image builds and runs are limited to the host architecture. Foreign
  architecture emulation, `--platform` builds, and multi-architecture manifests
  are not supported; [Round 11](docs/remediation/ROUND-11-PLAN.md) records the
  parked work.
- The dashboard and fleet UI have separate, dated browser acceptance reports:
  [dashboard](docs/desktop/DASHBOARD-TEST-REPORT-2026-08-25.md) and
  [fleet](docs/fleet/FLEET-TEST-REPORT-2026-08-25.md).

## 🚀 Quickstart

```bash
cargo build --release -p ferro-cli
./target/release/ferro-cli run --rm alpine:3.20 /bin/true
```

Build a project the way you always have — a Dockerfile and one command:

```bash
./target/release/ferro-cli build -t myapp:1.0 .
./target/release/ferro-cli run myapp:1.0
```

Launch the embedded local dashboard in a browser:

```bash
./target/release/ferro-cli dashboard --listen 127.0.0.1:43190
```

The command starts a local daemon and prints a bearer-token URL. `--token-file
PATH` writes the token for another process. The listener exists only while the
command runs. A non-loopback bind requires `--tls-cert`, `--tls-key`, and
`--operator-gate`. The browser acceptance report covers the loopback token,
Host and Origin checks, SSE, and all 24 dashboard checks.

Run the manager-backed fleet UI against the existing operator mTLS admin gRPC
endpoint:

```bash
ferro-mgr fleet-ui --listen 127.0.0.1:8443 \
  --tls-cert manager.crt --tls-key manager.key \
  --admin-endpoint https://127.0.0.1:50052 \
  --admin-domain localhost --admin-server-ca node-ca.crt \
  --operator-cert operator.crt --operator-key operator.key
```

The UI has Hosts, Containers, Deploys, and Health screens. Certificate-bound
`view` sessions are read-only; `operate` actions are written to the witness
journal. TLS is required except for an explicit loopback test run using
`--insecure-loopback`. The fleet report covers two rootless Linux hosts,
revocation, role denial, deploy, rollback, and the displayed degraded-health
boundary.

The optional LAN image mirror announces images by mDNS and provides
digest-verified, read-only peer pulls on private IPv4. When no peer succeeds,
pull falls back to the registry. Its host/guest proof is recorded in the
[LAN mirror evidence](docs/evidence/networking/2026-08-25-lan-image-mirror.md).

The real Docker CLI can use Ferrocrate's daemon. Local Dockerfile builds use
the authenticated Buildx docker driver by default; the classic path remains
available and has the same image digest. Arbitrary LLB and `gateway.v0` are
unsupported.

```bash
export DOCKER_HOST=unix:///run/ferrocrate/docker.sock
docker build -t myapp:1.0 .
docker run myapp:1.0
```

`scripts/verify-rootless.sh` checks rootless prerequisites. The privileged
`scripts/verify-apparmor-rootless-host.sh [ferrocrate.deb]` harness qualifies
the packaged Ubuntu AppArmor mechanism with the restricted-userns sysctl
active and restores the exact initial sysctl value on exit. Privileged
networking tests need a disposable Linux host; a packaging test alone is not
host-qualification evidence.

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/how-it-works-dark.svg">
  <img src="docs/assets/how-it-works-light.svg" alt="A command from the docker or ferrocrate CLI reaches the daemon over a Docker-compatible socket; the Rust runtime prepares layers, namespaces, cgroups and networking; the container runs as a normal Linux process" width="100%">
</picture>

Your command — from `docker` or the native CLI — arrives at the daemon on a
Docker-compatible API socket. The runtime assembles the container from OCI
image layers, isolates it with Linux namespaces and cgroups, wires its
network, and starts it. There is no virtual machine in the path on Linux:
a container is a normal process tree the kernel isolates, which is where the
speed comes from.

## Benchmark evidence

<p align="center">
  <img src="docs/assets/benchmark.svg" alt="Dated host-local Docker and Ferrocrate operation medians; see the benchmark register for the current attached-run result" width="100%">
</p>

The Round 9 paired attached-run measurement records a 0.033192 s Ferrocrate
median against Docker's 0.169436 s median on the qualification host. Method,
host details, and raw numbers:
[`docs/benchmarks/`](docs/benchmarks/DOCKER-VS-FERROCRATE-2026-08-23.md) and
the [benchmark register](docs/evidence/performance/benchmark-register.md).

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.svg">
  <img src="docs/assets/architecture-light.svg" alt="Architecture — native CLI, Docker clients, Compose and CRI feed one daemon, which drives the container runtime, image store and networking stack on Linux kernel primitives" width="100%">
</picture>

The native CLI, Docker clients, Compose, and CRI connect to one daemon.
`ferro-core` owns container state and execution; the image store holds OCI
layers and build cache; `ferro-net`/`ferro-netd` provide bridges, DNS, IPv6,
WireGuard, and iptables/nftables backends. eBPF port publishing is opt-in.

## 🖥️ Platform support

| Platform | Status |
|---|---|
| Ubuntu 26.04 / 24.04, Debian 12 / 13, Fedora 42, Alpine 3.22 (x86_64, rootful) | Supported; dated rows are in the feature matrix |
| Rocky 9 (kernel 5.14), Ubuntu 20.04 HWE (kernel 5.15) | Qualified with opt-in `legacy-peercred`; default pidfd authentication remains fail-closed |
| Ubuntu 24.04 on Oracle A1 (aarch64, kernel 6.17) | Supported; dated row is in the feature matrix |
| Rootless mode | Qualified only on the host rows in the feature matrix; missing `SO_PEERPIDFD` fails closed unless legacy peercred is explicitly enabled |
| Windows 11 | Accepted desktop backend through WSL2, 24/24 browser checks ([final VM verification](docs/desktop/VM-ACCEPTANCE-2026-08-25.md#final-vm-verification----2026-08-26)) |
| macOS Tahoe | Accepted desktop backend through a QEMU-HVF Linux VM, 24/24 browser checks ([final VM verification](docs/desktop/VM-ACCEPTANCE-2026-08-25.md#final-vm-verification----2026-08-26)) |

The authoritative support contract is
[`docs/FEATURE-MATRIX.md`](docs/FEATURE-MATRIX.md) — every claim there links
dated evidence in [`docs/evidence/`](docs/evidence/), and where a feature is
experimental or unsupported, the matrix says so explicitly.

## Status

Ferrocrate is Linux-first. Windows uses a WSL2 backend; macOS uses a Linux VM
backend. The engine does not execute containers natively on Windows or macOS.
The support contract, including experimental and unsupported rows, is in the
[feature matrix](docs/FEATURE-MATRIX.md).

## CI and development

```bash
cargo test --workspace          # full suite
cargo test -p ferro-core --lib  # runtime core
bash scripts/docker-client-conformance.sh   # 85-scenario default-BuildKit gate
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), and
the [release-gate instructions](docs/operations/external-ci.md). GitHub
Actions runs build, desktop/Tauri unit, frontend, and warning gates on the
self-hosted Linux, macOS, and Windows lab runners for same-repository pushes
and pull requests. Scheduled/manual packaging canaries build Linux deb/AppImage,
macOS app/DMG, and Windows MSI/NSIS bundles. The Linux and macOS artifact
records are [here](docs/evidence/packaging/2026-08-25-linux-artifacts.md) and
[here](docs/evidence/packaging/2026-08-25-macos-dmg.md). macOS-on-VMware lab
setup is documented in [`docs/MACOS_ON_VMWARE.md`](docs/MACOS_ON_VMWARE.md).

## 📄 License

[Apache-2.0](LICENSE)
