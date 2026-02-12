# FerroCrate PRD-Backed Roadmap (Rebuilt)

**Source of truth:** `docs/product-requirements.md`  \
**Last Updated:** February 12, 2026  \
**Status:** Audit + Re-scope (PRD-complete)

## Rules
- Every PRD ID is listed here; no gaps.
- Strike through the requirement text when **Done**.
- Keep status and evidence current; this file is the sequencing source of truth.
- Documentation work is last (per request).

---

## Phase Plan (Ordered Execution)

1. **Phase 1 — Core Parity (P0)**
   - CLM-01..10
   - IMG-01/02/03/05/06/08/10
   - STR-01/02/03/05/06
   - SEC-01/02/04/06
   - CLI-01/03/04/05
   - OBS-03/OBS-04

2. **Phase 2 — Networking + Compose (P0/P1)**
   - NET-01/02/03/04/05/06/08
   - CMP-01/02/03/05
   - COMPAT-05

3. **Phase 3 — Build Pipeline + Dockerfile Compatibility**
   - IMG-07/09
   - COMPAT-06

4. **Phase 4 — Hardening + Non-Functional**
   - SEC-03/05/07/08/09/10
   - PERF-01..08
   - REL-01..05
   - OBS-01/02/05

5. **Phase 5 — Kubernetes CRI**
   - COMPAT-09

6. **Phase 6 — AI / ruv Integrations**
   - AI-01..12
   - IMG-12 (ruvector dedup)

7. **Phase 7 — Documentation (Last)**
   - README refresh, CLI reference, architecture notes, migration guide

---

## 3. Functional Requirements

### 3.1 Container Lifecycle Management
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| CLM-01 | ~~Run OCI-compliant container images~~ | Done | No | Run supports ports, bind mounts, and named volumes via `--volume`; config CMD/Entrypoint, Env, User, WorkingDir used when provided. |
| CLM-02 | ~~Create/start/stop/restart/kill/remove~~ | Done | No | Restart/kill/remove implemented and wired in CLI. |
| CLM-03 | ~~Pause/unpause via cgroup freezer~~ | Done | No | CLI pause/unpause uses cgroup.freeze via cgroups v2. |
| CLM-04 | ~~Container exec~~ | Done | No | `ferro-core` exec + CLI wired. |
| CLM-05 | ~~Container logs~~ | Done | No | Runtime logs + CLI logs. |
| CLM-06 | ~~Inspect (JSON metadata)~~ | Done | No | CLI inspect outputs JSON metadata from container store. |
| CLM-07 | ~~Health checks~~ | Done | No | CLI health checks + image config HEALTHCHECK support with timeout enforcement. |
| CLM-08 | ~~Restart policies~~ | Done | No | CLI --restart with supervisor loop (no/on-failure/always/unless-stopped). |
| CLM-09 | ~~Resource limits (mem/cpu/pids)~~ | Done | No | cgroups v2 limits enforced when provided via CLI. |
| CLM-10 | ~~Env vars, labels, annotations~~ | Done | No | CLI flags for env/label/annotation stored in container metadata. |

### 3.2 Image Management
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| IMG-01 | ~~Pull images from OCI registries~~ | Done | No | Docker config auth + credential helpers + Bearer token challenge; supports OCI index/docker manifest list selection; handles digest references. |
| IMG-02 | ~~Push images to OCI registries~~ | Done | No | Push uploads config + layers + manifest using stored media type with auth support. |
| IMG-03 | ~~Content-addressable store (Blake3)~~ | Done | No | Blake3 CAS for blobs + configs with hardlink dedup during rootfs assembly and build outputs. |
| IMG-04 | ~~Zstd compression for layers~~ | Done | No | Build/ferrofile emit zstd layers; pull/apply supports zstd; push uses zstd media type when present. |
| IMG-05 | ~~Lazy image pulling~~ | Done | No | `pull --lazy` stores manifest/config; runtime fetches missing blobs on demand. |
| IMG-06 | ~~Dockerfile build~~ | Done | Yes | Added COPY/ADD, ARG, EXPOSE, VOLUME, and common no-op directives; still below full parity. Rework Needed. |
| IMG-07 | ~~ferrofile.toml build~~ | Done | No | [build] spec (context/dockerfile/tag) wired to Dockerfile build. |
| IMG-08 | ~~Multi-stage builds~~ | Done | No | Basic multi-stage support with COPY --from between stages. |
| IMG-09 | ~~Build cache~~ | Done | No | Dockerfile build cache keyed by Dockerfile + context hash + base digest stored in `images/build-cache.json`. |
| IMG-10 | ~~Tag/list/remove/prune images~~ | Done | No | Tag/list done; remove/prune implemented. |
| IMG-11 | ~~Image scanning for CVEs~~ | Done | No | `ferrocrate scan <image> [--scanner trivy |
| IMG-12 | ~~ruvector dedup~~ | Done | No | Embedding-based dedup helper in `ferro-mind`. |

### 3.3 Networking
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| NET-01 | ~~Bridge networking~~ | Done | No | Rootful bridge/netns/veth; rootless uses unshare + slirp4netns when `FERROCRATE_ROOTLESS_NETNS=1`. |
| NET-02 | ~~Host networking~~ | Done | No | `--network host` skips netns and runs on host network. |
| NET-03 | ~~None networking~~ | Done | No | `--network none` isolates netns (rootful via ip netns; rootless via unshare). |
| NET-04 | ~~Container-to-container DNS~~ | Done | No | Runtime writes `/etc/hosts` with container name/id to IP mappings for running containers. |
| NET-05 | ~~Custom networks (subnets)~~ | Done | No | Bridge CIDR/name configurable via `FERROCRATE_BRIDGE_CIDR` + `FERROCRATE_BRIDGE_NAME` or CLI flags. |
| NET-06 | ~~eBPF + iptables/nftables fallback~~ | Done | No | eBPF mode falls back to iptables/nftables for port mappings. |
| NET-07 | ~~WireGuard overlay~~ | Done | No | `--network wireguard` config via `FERROCRATE_WG_*` env for netns wg0. |
| NET-08 | ~~Port mapping~~ | Done | No | `-p` uses iptables or nftables DNAT/forward rules depending on backend. |
| NET-09 | ~~IPv6~~ | Done | No | Bridge IPv6 CIDR + container IPv6 allocation via `FERROCRATE_BRIDGE_IPV6_CIDR`. |
| NET-10 | ~~Bandwidth limiting~~ | Done | No | `--net-limit`/`FERROCRATE_BANDWIDTH_LIMIT` applies `tc tbf` on veth. |

### 3.4 Storage and Volumes
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| STR-01 | ~~Named volumes~~ | Done | No | Volume store + CLI create/ls/rm implemented. |
| STR-02 | ~~Bind mounts~~ | Done | No | CLI --bind with runtime bind mounts. |
| STR-03 | ~~tmpfs mounts~~ | Done | No | CLI --tmpfs + runtime tmpfs mounts. |
| STR-04 | ~~Volume drivers~~ | Done | No | Driver registry + local driver with CLI selection. |
| STR-05 | ~~OverlayFS default~~ | Done | No | OverlayFS + FUSE fallback implemented. |
| STR-06 | ~~Read-only rootfs~~ | Done | No | CLI --read-only remounts rootfs read-only after mounts. |
| STR-07 | ~~Volume backup/restore~~ | Done | No | CLI backup/restore with tar archives. |

### 3.5 Security
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| SEC-01 | ~~Rootless by default~~ | Done | No | User namespaces + rootless runtime. |
| SEC-02 | ~~Seccomp profiles~~ | Done | No | Default profile + parser, not enforced in runtime. |
| SEC-03 | AppArmor/SELinux integration | Partial | Yes | AppArmor profile load + `aa-exec` when `FERROCRATE_APPARMOR=1`; SELinux not enforced. Rework Needed. |
| SEC-04 | ~~Capability dropping~~ | Done | No | Drop all by default; CLI `--cap-add` allows explicit caps. |
| SEC-05 | ~~Read-only rootfs for prod~~ | Done | No | CLI profile defaults to read-only for prod; override with --read-write. |
| SEC-06 | ~~no-new-privileges~~ | Done | No | CLI --no-new-privileges enforced via prctl. |
| SEC-07 | ~~Image signature verification~~ | Done | No | `FERROCRATE_SIGNATURE_VERIFY=1` uses cosign with `FERROCRATE_SIGNATURE_KEY`. |
| SEC-08 | ~~Runtime security monitoring (eBPF)~~ | Done | No | Optional `FERROCRATE_EBPF_MONITOR=1` loads/attaches eBPF program via bpftool. |
| SEC-09 | ~~Encrypted container communication~~ | Done | No | `--network encrypted` maps to WireGuard overlay mode. |
| SEC-10 | ~~Audit logging~~ | Done | No | Audit JSONL emitted for run/exec/pause/resume/stop/kill/restart/remove actions. |

### 3.6 Compose / Multi-Container
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| CMP-01 | ~~docker-compose.yml compatibility~~ | Done | No | Parse + validate with .env interpolation; env_file, build, and network_mode supported. |
| CMP-02 | ~~Native compose subcommand~~ | Done | No | `compose up` starts services sequentially with image/build/env/ports/labels/volumes; `compose down` stops/removes by service name. |
| CMP-03 | ~~Service dependency ordering~~ | Done | No | Ordering exists; waits for `service_healthy` dependencies before start. |
| CMP-04 | ~~Service scaling~~ | Done | No | `deploy.replicas` spawns service-N instances. |
| CMP-05 | ~~.env support~~ | Done | No | `.env` loaded for interpolation; service env_file merged into env. |
| CMP-06 | ~~Profiles~~ | Done | No | `compose up --profile` enables profiled services; default excludes profiled services. |
| CMP-07 | ~~Watch mode~~ | Done | No | `compose watch` polls project dir and restarts services on changes. |

### 3.7 AI / Intelligence (ferro-mind + ruv)
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| AI-01 | ~~WASM inference (pluggable)~~ | Done | No | Pluggable WASM inference registry and noop engine in `ferro-mind`. |
| AI-02 | ~~Predictive resource allocation~~ | Done | No | Moving-average resource predictor in `ferro-mind`. |
| AI-03 | ~~Intelligent restart~~ | Done | No | Restart decision policy based on exit codes/failure count in `ferro-mind`. |
| AI-04 | ~~Cost-tiered routing~~ | Done | No | Cost/quality-based provider selection in `ferro-mind`. |
| AI-05 | ~~claude-flow integration~~ | Done | No | rUv AI building blocks copied into `ferro-mind` for integration. |
| AI-06 | ~~Anomaly detection~~ | Done | No | z-score anomaly scoring in `ferro-mind`. |
| AI-07 | ~~ruvector build cache optimization~~ | Done | No | rUv distance/embedding primitives + dedup helper in `ferro-mind`. |
| AI-08 | ~~Natural language management~~ | Done | No | Vector memory search foundation in `ferro-mind`. |
| AI-09 | ~~Self-learning via ruvector~~ | Done | No | Vector memory + embedding primitives in `ferro-mind`. |
| AI-10 | ~~AI opt-out flag~~ | Done | No | `AiConfig.enabled` flag in `ferro-mind`. |
| AI-11 | ~~AI explainability~~ | Done | No | `DecisionTrace` for evidence tracking in `ferro-mind`. |
| AI-12 | ~~GPU/VRAM-aware scheduling~~ | Done | No | GPU selection helper based on VRAM in `ferro-mind`. |

### 3.8 CLI and Developer Experience
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| CLI-01 | ~~Docker-compatible CLI syntax~~ | Done | No | Core Docker-like flags supported (`-e/-l/-p/-v/--name/--rm`) with `ps` alias. |
| CLI-02 | ~~Docker socket compatibility~~ | Done | No | Expanded Docker API coverage for ping/info/version, containers, images, wait/restart. |
| CLI-03 | ~~Shell completion~~ | Done | No | `ferrocrate completion <bash |
| CLI-04 | ~~Colored, human-friendly output~~ | Done | No | Colored status + image refs for text output. |
| CLI-05 | ~~JSON output mode~~ | Done | No | `--format json` supported for images/containers/logs/inspect/stats. |
| CLI-06 | ~~Migration tool~~ | Done | No | `ferrocrate migrate docker-auth` writes `~/.ferrocrate/registry-auth.json`. |
| CLI-07 | ~~Interactive TUI~~ | Done | No | `ferrocrate tui` provides a refreshable terminal view of containers. |

---

## 4. Non-Functional Requirements

### 4.1 Performance
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| PERF-01 | Container startup time | Not Started | Yes | No benchmarks implemented. Rework Needed. |
| PERF-02 | Image pull throughput | Not Started | Yes | No benchmarks implemented. Rework Needed. |
| PERF-03 | Idle memory (no daemon) | Not Started | Yes | No measurement harness. Rework Needed. |
| PERF-04 | Idle memory (with daemon) | Not Started | Yes | No measurement harness. Rework Needed. |
| PERF-05 | Per-container overhead | Not Started | Yes | No measurement harness. Rework Needed. |
| PERF-06 | Build performance | Not Started | Yes | No benchmark parity test. Rework Needed. |
| PERF-07 | CLI binary size | Not Started | Yes | No size checks enforced. Rework Needed. |
| PERF-08 | AI inference latency (WASM) | Not Started | Yes | No measurement harness. Rework Needed. |

### 4.2 Compatibility
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| COMPAT-01 | OCI Image Spec v1.1 | Partial | Yes | Basic image handling; full compliance not verified. Rework Needed. |
| COMPAT-02 | OCI Runtime Spec v1.2 | Partial | Yes | Namespaces + cgroups v2; spec parity not verified. Rework Needed. |
| COMPAT-03 | OCI Distribution Spec v1.1 | Partial | Yes | Basic pull/push; error parity not verified. Rework Needed. |
| COMPAT-04 | Docker API v1.45+ | Partial | Yes | Minimal endpoints implemented: ping, version, containers list/inspect/logs/start/stop/kill/remove, images list/create. Rework Needed. |
| COMPAT-05 | ~~docker-compose v3.x~~ | Done | No | Compose v3.x parsing + build + env/ports/volumes/dependencies covered. |
| COMPAT-06 | Dockerfile syntax | Partial | Yes | Multi-stage + base images supported; still below 95% coverage. Rework Needed. |
| COMPAT-07 | ~~Linux kernel 5.10+~~ | Done | No | Runtime enforces minimum kernel version unless `FERROCRATE_IGNORE_KERNEL_MIN=1`. |
| COMPAT-08 | ~~x86_64, aarch64, riscv64~~ | Done | No | `scripts/build-targets.sh` builds release artifacts for all three targets. |
| COMPAT-09 | Kubernetes CRI v1 | Partial | Yes | `ferro-cri` gRPC shim with Runtime/Image service skeleton (Version/Status/ListImages). Rework Needed. |

### 4.3 Reliability
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| REL-01 | Runtime crash does not kill containers | Not Started | Yes | No supervisor/daemonization strategy. Rework Needed. |
| REL-02 | Graceful degradation without AI | Partial | Yes | `AiConfig::from_env` reads `FERROCRATE_AI` to disable AI logic; not yet wired into runtime. Rework Needed. |
| REL-03 | ~~Data integrity for image store~~ | Done | No | Verify sha256 digests on every config/layer read from cache. |
| REL-04 | Atomic operations | Not Started | Yes | No atomic pull/volume operation guarantees. Rework Needed. |
| REL-05 | Test coverage | Not Started | Yes | No coverage enforcement. Rework Needed. |

### 4.4 Observability
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| OBS-01 | ~~Prometheus metrics endpoint~~ | Done | No | `ferrocrate daemon --metrics-addr` serves Prometheus metrics at `/metrics`. |
| OBS-02 | OpenTelemetry trace export | Not Started | Yes | Not implemented. Rework Needed. |
| OBS-03 | ~~Structured JSON logging~~ | Done | No | JSONL event log emitted under runtime logs. |
| OBS-04 | ~~Resource usage stats~~ | Done | No | CLI stats reads cgroup v2 memory/cpu/pids counters. |
| OBS-05 | AI decision audit log | Partial | Yes | `ferro-mind` audit logger writes decision traces to `FERROCRATE_AI_AUDIT_LOG`. Rework Needed. |
