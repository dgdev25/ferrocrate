<p align="center">
  <img src="docs/assets/banner.svg" alt="Ferrocrate — the Docker-compatible container engine, written in Rust" width="100%">
</p>

Ferrocrate is a container engine you use exactly like Docker — same commands,
same Dockerfiles, same images — implemented from scratch in Rust as a single
binary. The genuine `docker` CLI works against its daemon unmodified: the
conformance suite drives a real Docker client through 85 default-BuildKit
scenarios, and all 85 pass. Images are standard OCI, so anything Ferrocrate
builds runs under Docker, podman, or Kubernetes, and the other way round.

## ✨ Highlights

- **Docker-compatible, verified** — 85/85 default-BuildKit conformance against
  the real `docker` client, including cold base-image pulls, multi-network
  connect/disconnect, and non-readable log-driver behavior.
- **Fast** — the dated benchmark register records host-local paired results;
  Round 9 closes the previously recorded attached-run loss.
- **One binary** — daemon, native CLI, Compose, and a Kubernetes CRI endpoint
  in a single Rust executable. No shim stack.
- **Safety engineering** — destructive operations verify process identity by
  PID start-time before signaling, so a recycled PID is never killed by
  mistake; state survives daemon restarts and is reconciled on startup.
- **Qualified, not assumed** — every support claim links dated evidence from
  real hosts; desktop acceptance remains blocked while the Windows WSL engine
  rebuild completes and by a macOS VM SSH identity/known-host boundary, recorded in
  [`VM-ACCEPTANCE-2026-08-25.md`](docs/desktop/VM-ACCEPTANCE-2026-08-25.md).

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

Launch the same Forge interface used by the desktop app in an ordinary browser:

```bash
./target/release/ferro-cli dashboard --listen 127.0.0.1:43190
```

The command starts its local daemon and prints a per-launch bearer-token URL.
Use `--token-file PATH` when another process should read the token without
capturing stdout. The listener exists only while `dashboard` is running.
Non-loopback binds fail closed unless `--tls-cert`, `--tls-key`, and
`--operator-gate` are supplied together.

Or point the real Docker CLI at Ferrocrate's daemon. The default build protocol
is supported through the authenticated Buildx docker driver; the classic path
remains available and produces the same image digest:

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

## 🧭 How it works

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

## 📊 How it performs

<p align="center">
  <img src="docs/assets/benchmark.svg" alt="Dated host-local Docker and Ferrocrate operation medians; see the benchmark register for the current attached-run result" width="100%">
</p>

The Round 9 paired attached-run measurement records a 0.033192 s Ferrocrate
median against Docker's 0.169436 s median on the qualification host. Method,
host details, and raw numbers:
[`docs/benchmarks/`](docs/benchmarks/DOCKER-VS-FERROCRATE-2026-08-23.md) and
the [benchmark register](docs/evidence/performance/benchmark-register.md).

## 🏗️ Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.svg">
  <img src="docs/assets/architecture-light.svg" alt="Architecture — native CLI, Docker clients, Compose and CRI feed one daemon, which drives the container runtime, image store and networking stack on Linux kernel primitives" width="100%">
</picture>

Four client surfaces converge on one daemon. Below it, `ferro-core` owns
container state and execution, the image store holds OCI layers and the build
cache, and the networking stack (`ferro-net`/`ferro-netd`) provides bridges,
DNS, IPv6, and WireGuard overlays — with iptables and nftables backends, and
opt-in eBPF port publishing. A `ferro-cri` socket serves Kubernetes. The
workspace also builds on macOS (Linux-only paths compile out) so the code
can be developed and unit-tested there.

## 🖥️ Platform support

| Platform | Status |
|---|---|
| Ubuntu 26.04 / 24.04, Debian 12 / 13, Fedora 42, Alpine 3.22 (x86_64, rootful) | Qualified with dated evidence per distro; full matrix re-run 2026-08-25 on main 90595943, conformance 60/60 per row |
| Rocky 9 (kernel 5.14), Ubuntu 20.04 HWE (kernel 5.15) | Qualified 60/60 with the explicit `--peer-auth legacy-peercred` boundary; default pidfd authentication remains fail-closed |
| Ubuntu 24.04 on Oracle A1 (aarch64, kernel 6.17) | Qualified with dated evidence |
| Rootless mode | Partial by distribution: the packaged Ubuntu 24.04+ AppArmor userns mechanism is qualified; hosts without `SO_PEERPIDFD` fail closed unless the daemon explicitly accepts legacy peercred's PID-reuse risk |
| Windows 11 (WSL2 backend) | Native desktop/UI rebuilt on `E:`; WSL engine rebuild is pending before authenticated bridge acceptance |
| macOS Tahoe (Linux VM backend) | Blocked: QEMU/HVF and release sidecars are available, but the supervisor's default SSH identity path is absent and a stale loopback known-host entry blocks the tunnel |
| Ubuntu 20.04 (HWE kernel 5.15) | Qualified 60/60 in opt-in `legacy-peercred` mode; stock kernel 5.4 remains below the enforced 5.10 minimum |

The authoritative support contract is
[`docs/FEATURE-MATRIX.md`](docs/FEATURE-MATRIX.md) — every claim there links
dated evidence in [`docs/evidence/`](docs/evidence/), and where a feature is
experimental or unsupported, the matrix says so explicitly.

## 🩺 Status

Ferrocrate targets Linux-first local development, not (yet) a universal Docker
replacement. Coverage is strongest in lifecycle, images, and local Dockerfile
builds. Multi-network containers, pluggable log drivers, and authenticated
BuildKit session builds are qualified; arbitrary LLB and non-Dockerfile
frontends remain explicit unsupported boundaries.
AI-assisted restart/resource signals exist but are local, bounded, and off
unless enabled (`FERROCRATE_AI=0` disables everything; automatic actions
need a separate operator gate).

## 🛠️ Development

```bash
cargo test --workspace          # full suite
cargo test -p ferro-core --lib  # runtime core
bash scripts/docker-client-conformance.sh   # 85-scenario default-BuildKit gate
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), and
[`docs/operations/external-ci.md`](docs/operations/external-ci.md) for the
release gates. macOS-on-VMware lab setup for cross-platform testing is
documented in [`docs/MACOS_ON_VMWARE.md`](docs/MACOS_ON_VMWARE.md).

## 📄 License

[Apache-2.0](LICENSE)
