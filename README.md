<p align="center">
  <img src="docs/assets/banner.svg" alt="Ferrocrate — the Docker-compatible container engine, written in Rust" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/release-alpha-C2410C" alt="Alpha release">
  <img src="https://img.shields.io/badge/docker_CLI_conformance-85%2F85-15803D" alt="85 of 85 docker CLI scenarios pass">
  <img src="https://img.shields.io/badge/license-Apache--2.0-6E655E" alt="Apache 2.0 license">
</p>

Ferrocrate runs containers the way Docker does, from a single Rust binary.
Point your existing `docker` CLI, Dockerfiles, and Compose files at it and
they work unchanged; or use the native `ferro-cli` command, the desktop app,
or the fleet control plane. On Linux a container is a normal process the
kernel isolates, and that is where the speed comes from.

**Status: alpha release.** The [feature matrix](docs/FEATURE-MATRIX.md) is the
public source of truth for supported, experimental, and unsupported behavior.
All CI and release jobs use self-hosted runners only.

<p align="center">
  <img src="docs/assets/features.svg" alt="What Ferrocrate does: Docker-compatible, native Rust engine, builds both ways, desktop app on three OSes, and fleet control plane" width="100%">
</p>

## Install

Download a package from the [latest release](https://github.com/dgdev25/ferrocrate/releases/tag/v0.1.0-unsigned),
then follow the platform guide. These are local, unsigned builds: not
notarized, not code-signed, and the in-app updater is disabled until a
signed release ships.

| Platform | Package | Download | Guide |
| --- | --- | --- | --- |
| macOS 13+ (Intel) | `FerroCrate_Desktop_0.1.0_x64.dmg` | [.dmg](https://github.com/dgdev25/ferrocrate/releases/download/v0.1.0-unsigned/FerroCrate_Desktop_0.1.0_x64.dmg) | [Install on macOS](#install-on-macos) |
| Linux (x86_64, glibc) | `FerroCrate.Desktop_0.1.0_amd64.deb` or `.AppImage` | [.deb](https://github.com/dgdev25/ferrocrate/releases/download/v0.1.0-unsigned/FerroCrate.Desktop_0.1.0_amd64.deb) &#124; [.AppImage](https://github.com/dgdev25/ferrocrate/releases/download/v0.1.0-unsigned/FerroCrate.Desktop_0.1.0_amd64.AppImage) | [Install on Linux](#install-on-linux) |
| Windows 10/11 (x64) | `FerroCrate.Desktop_0.1.0_x64-setup.exe` or `.msi` | [.exe](https://github.com/dgdev25/ferrocrate/releases/download/v0.1.0-unsigned/FerroCrate.Desktop_0.1.0_x64-setup.exe) &#124; [.msi](https://github.com/dgdev25/ferrocrate/releases/download/v0.1.0-unsigned/FerroCrate.Desktop_0.1.0_x64_en-US.msi) | [Install on Windows](#install-on-windows) |

### Install on macOS

Open the `.dmg`, drag **FerroCrate Desktop** to Applications. Gatekeeper
blocks an unsigned app on the first launch: right-click the app in
Applications and choose **Open**, then confirm. Later launches open normally.

### Install on Linux

**Debian/Ubuntu:** `sudo apt install ./FerroCrate.Desktop_0.1.0_amd64.deb`

**Any distro (glibc-based):** make the AppImage executable and run it —
`chmod +x FerroCrate.Desktop_0.1.0_amd64.AppImage && ./FerroCrate.Desktop_0.1.0_amd64.AppImage`

### Install on Windows

Run the installer. Since it isn't signed, SmartScreen will show "Windows
protected your PC" — click **More info**, then **Run anyway**.

## Desktop app

The desktop app shows Compose projects as workspaces, with per-service status,
ports, CPU and memory, and one-click logs, terminal and stop. Start it from a
checkout with `scripts/dev-desktop.sh` (add `--web` to open it in a browser).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/screenshots/workspaces-dark.png">
  <img src="docs/assets/screenshots/workspaces-light.png" alt="Ferrocrate Desktop Workspaces page: a four-service Compose project named storefront with every service running, published ports, and per-service CPU and memory" width="100%">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/screenshots/images-dark.png">
  <img src="docs/assets/screenshots/images-light.png" alt="Ferrocrate Desktop Images page: local images with size, creation time and whether a container uses them" width="100%">
</picture>

## Getting started

Every command below was run as a normal user, without `sudo`, on the Linux
host that builds this repository. The native CLI needs no daemon: each command
does its own work and keeps images, containers and volumes under
`~/.ferrocrate` (`/var/lib/ferrocrate` when run as root; set `FERROCRATE_HOME`
to use another directory). If you know Docker, the commands and flags are the
same; only the binary name differs.

### What you need

- A Linux host from the [platform support](#platform-support) table. macOS and
  Windows users get the desktop app, not the CLI.
- Rust through `rustup`. The repository pins the toolchain in
  `rust-toolchain.toml`, so `rustup` installs the right version on first build.
- For rootless use: unprivileged user namespaces enabled, entries for your
  user in `/etc/subuid` and `/etc/subgid`, and the `newuidmap`, `newgidmap`,
  `slirp4netns` and `bwrap` binaries. `bash scripts/verify-rootless.sh` tells
  you what is missing.
- The `docker` CLI, only if you want step 6.

### 1. Build the CLI

```bash
git clone https://github.com/dgdev25/ferrocrate.git
cd ferrocrate
cargo build --release -p ferro-cli
install -m 755 target/release/ferro-cli ~/.local/bin/ferro-cli   # optional, puts it on PATH
```

### 2. Run a container

```bash
ferro-cli run --rm alpine:3.20 echo hello
```

This pulls the image, verifies every layer digest, runs the command and
removes the container. The first two output lines are the container id and
the runtime details; your command's output follows.

### 3. Build an image from a Dockerfile

```bash
mkdir hello && cd hello
cat > Dockerfile <<'EOF'
FROM alpine:3.20
COPY hello.sh /hello.sh
CMD ["/bin/sh", "/hello.sh"]
EOF
printf '#!/bin/sh\necho "hello from ferrocrate"\n' > hello.sh

ferro-cli build -t hello:1.0 .
ferro-cli images
ferro-cli run --rm hello:1.0
```

`build` also accepts `--build-arg`, `--secret`, `--cache-from` and
`--cache-to`, as Docker does.

### 4. Run a service with a name, a port and a volume

```bash
ferro-cli run -d --name web -p 8080:8080 -v webdata:/www busybox:1.36 \
  sh -c 'echo hello > /www/index.html; exec httpd -f -v -p 8080 -h /www'

curl http://127.0.0.1:8080/        # hello
ferro-cli ps                       # running containers; -a includes stopped ones
ferro-cli logs --tail 5 web        # -f follows
ferro-cli exec web ls /www         # run a command inside; -it for a shell
ferro-cli stop web
ferro-cli start web
ferro-cli stop web
ferro-cli rm web
ferro-cli volume rm webdata
```

### 5. Compose

```bash
cat > compose.yaml <<'EOF'
services:
  app:
    image: alpine:3.20
    command: ["sh", "-c", "echo compose says hi; sleep 3600"]
EOF

ferro-cli compose up -d
ferro-cli compose ps
ferro-cli compose logs
ferro-cli compose down
```

`compose` also has `stop`, `start`, `restart`, `pull`, `config` and `watch`.

### 6. Keep using the real Docker CLI

Start the daemon with the Docker-compatible API on, then point `DOCKER_HOST`
at its socket. The daemon shares the same state directory as the native CLI,
so images built one way are visible the other way.

```bash
# rootless
ferro-cli daemon --docker-compat --socket "$XDG_RUNTIME_DIR/ferrocrate.sock" &
export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/ferrocrate.sock"

# or as root (default socket /var/run/ferrocrate.sock)
sudo ferro-cli daemon --docker-compat &
export DOCKER_HOST=unix:///var/run/ferrocrate.sock

docker version
docker build -t hello:1.0 .
docker run --rm hello:1.0
docker ps -a
```

Docker's default BuildKit path works through this socket; see
[How it works](#how-it-works) for the limits.

### 7. Clean up

```bash
kill %1                        # stop the daemon from step 6 (as root: sudo pkill -x ferro-cli)
ferro-cli rmi hello:1.0
ferro-cli system prune         # stopped containers, unused images, build cache
ferro-cli volume prune
```

Optional: `ferro-cli dashboard --listen 127.0.0.1:43190` serves a local
browser dashboard for the life of the command and prints a one-time token URL.

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/how-it-works-dark.svg">
  <img src="docs/assets/how-it-works-light.svg" alt="A command from the docker or ferrocrate CLI reaches the daemon over a Docker-compatible socket; the Rust runtime prepares layers, namespaces, cgroups and networking; the container runs as a normal Linux process" width="100%">
</picture>

Your command, from `docker` or the native CLI, reaches the daemon on a
Docker-compatible API socket (the same protocol Docker speaks, so existing
tools do not know the difference). The runtime unpacks the image layers,
isolates the process with Linux namespaces and cgroups (the kernel features
that give a process its own view of the filesystem, network, and resource
limits), wires its network, and starts it. There is no virtual machine on
Linux and no second daemon: one binary does the work.

Builds go through the same daemon. Docker's default BuildKit path is
supported through the authenticated Buildx docker driver; the classic build
path is kept and produces the same image digest. Arbitrary LLB and
`gateway.v0` frontends are not supported.

## Benchmarks against Docker

<p align="center">
  <img src="docs/assets/benchmark.svg" alt="Median seconds per operation on the same host: Ferrocrate is faster on nine of ten operations; Docker is faster on attached run-to-exit" width="100%">
</p>

All numbers below are medians from paired runs on the same host, with both
engines unprivileged and the same image. Negative means Ferrocrate is faster.
The [benchmark method](docs/performance-baselines.md) explains how release
candidates collect and qualify fresh results.

### Paired harness, 2026-08-23

Host: Intel i9-14900K, 32 threads, 61 GB RAM, Ubuntu 26.04, kernel 7.0.0-30,
Docker 29.7.2. `alpine:latest`, `--network none`, 10 iterations (5 for pull
and build).

| Operation | Ferrocrate | Docker | Difference |
|---|---:|---:|---:|
| Start container (detached) | 0.008 s | 0.114 s | −93% |
| Stop container (`-t 1`) | 0.032 s | 1.115 s | −97% |
| Exec a command | 0.016 s | 0.064 s | −75% |
| Read 1,000 log lines | 0.007 s | 0.016 s | −52% |
| List containers (`ps -a`) | 0.007 s | 0.032 s | −76% |
| List images | 0.008 s | 0.114 s | −93% |
| Create a volume | 0.008 s | 0.016 s | −52% |
| Build, no cache (COPY-only Dockerfile) | 0.008 s | 0.264 s | −97% |
| Build, cached (COPY-only Dockerfile) | 0.007 s | 0.765 s | −99% |
| **Run to exit (attached)** | **0.364 s** | **0.164 s** | **+122% (Docker faster)** |
| Cold pull (baseline run only) | 1.474 s | 3.183 s | −54% |

These results describe that dated host and build, not the current release
candidate. Functional coverage is separate from speed; use the
[feature matrix](docs/FEATURE-MATRIX.md) for the supported surface.

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.svg">
  <img src="docs/assets/architecture-light.svg" alt="Architecture — native CLI, Docker clients, Compose and CRI feed one daemon, which drives the container runtime, image store and networking stack on Linux kernel primitives" width="100%">
</picture>

Four kinds of client, one daemon, three subsystems, one kernel:

- **Clients:** the native CLI (`ferro-cli`), any Docker client over the
  compatible API, Compose (`ferro-compose`), and Kubernetes through the CRI
  (`ferro-cri`, the interface a kubelet uses to ask a runtime for pods).
- **Daemon:** one binary that owns state and dispatches work.
- **Container runtime** (`ferro-core`): creates and supervises containers,
  with PID-identity checks so only the caller that started a container can
  act on it.
- **Image store:** OCI layers and the build cache.
- **Networking** (`ferro-net`, `ferro-netd`): bridges, DNS, IPv6, WireGuard,
  iptables or nftables backends; eBPF port publishing is opt-in.
- **Kernel:** namespaces, cgroups, seccomp, netfilter, eBPF. Ferrocrate adds
  no layer between the container and the kernel.

Around the engine: `ferro-desktop` and the Tauri app in `apps/ferro-desktop-ui`
(desktop on Linux, WSL2 on Windows, a QEMU/HVF Linux VM on macOS), `ferro-mgr`
(fleet control plane with a certificate-bound browser UI), `ferro-web` (the
shared browser transport), and `ferro-mind` (resource monitoring and anomaly
features for containers).

## Platform support

| Platform | Status |
|---|---|
| Ubuntu 26.04 / 24.04, Debian 12 / 13, Fedora 42, Alpine 3.22 (x86_64, rootful) | Supported; dated rows in the feature matrix |
| Ubuntu 24.04 on Oracle A1 (aarch64, kernel 6.17) | Supported; dated row in the feature matrix |
| Rocky 9 (kernel 5.14), Ubuntu 20.04 HWE (kernel 5.15) | Qualified with opt-in `legacy-peercred`; the default pidfd authentication fails closed on these kernels |
| Rootless mode | Qualified on the host rows in the feature matrix; a missing `SO_PEERPIDFD` fails closed unless legacy peercred is enabled |
| Windows 11 | Unsigned alpha desktop package; WSL2 runtime qualification is in progress |
| macOS Tahoe | Unsigned Intel alpha desktop package; Linux VM runtime qualification is in progress |

Images are built and run only for the host's architecture. There is no
emulation of foreign architectures, no `--platform` builds, and no
multi-architecture manifests.

The authoritative support contract is
[`docs/FEATURE-MATRIX.md`](docs/FEATURE-MATRIX.md). It states where a feature
is experimental or unsupported.

## Going further

- **Fleet UI:** `ferro-mgr fleet-ui` manages enrolled hosts over an
  operator-authenticated mTLS admin endpoint, with read-only `view` sessions
  and audited `operate` actions. Local demo: `scripts/fleet-demo.sh up`.
- **Dashboard:** the local browser dashboard uses a one-time bearer token and
  restricts Host and Origin values.
- **LAN image mirror (experimental, opt-in):** announces images by mDNS and
  serves digest-verified, read-only pulls to peers on private IPv4, falling
  back to the registry.
- **Packaging:** Linux deb and AppImage, macOS DMG, Windows MSI and NSIS. The
  macOS and Windows artifacts are not code-signed.
- **Security and hosts:** `scripts/verify-apparmor-rootless-host.sh` qualifies
  the packaged Ubuntu AppArmor profile on a disposable host; see
  [`SECURITY.md`](SECURITY.md).

## Development

```bash
cargo test --workspace                       # full suite
cargo test -p ferro-core --lib               # runtime core
bash scripts/docker-client-conformance.sh    # 85-scenario docker CLI gate
```

GitHub Actions runs the build, unit, frontend, and warning gates on
self-hosted Linux, macOS, and Windows runners; scheduled canaries build the
platform bundles. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[`docs/RELEASE.md`](docs/RELEASE.md) release guide.

## License

[Apache-2.0](LICENSE)
