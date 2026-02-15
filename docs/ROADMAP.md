# FerroCrate PRD-Backed Roadmap (Rebuilt)

**Source of truth:** `docs/product-requirements.md`
**Last Updated:** February 12, 2026
**Status:** Honest Audit (Task 1.3 completed)

> **Status Definitions:**
> - **Done**: Fully implemented, tested, working
> - **Partial**: Some implementation but significant gaps (stubs, scaffolding, or missing execution)
> - **Rework Needed**: Needs significant refactoring or redesign
> - **API Designed**: Data structures and command builders exist, no execution

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
| IMG-06 | ~~Dockerfile build~~ | Done | Yes | Added COPY/ADD, ARG (including global), EXPOSE, VOLUME, and interpolation; still below full parity. Rework Needed. |
| IMG-07 | ~~ferrofile.toml build~~ | Done | No | [build] spec (context/dockerfile/tag) wired to Dockerfile build. |
| IMG-08 | ~~Multi-stage builds~~ | Done | No | Basic multi-stage support with COPY --from between stages. |
| IMG-09 | ~~Build cache~~ | Done | No | Dockerfile build cache keyed by Dockerfile + context hash + base digest stored in `images/build-cache.json`. |
| IMG-10 | ~~Tag/list/remove/prune images~~ | Done | No | Tag/list done; remove/prune implemented. |
| IMG-11 | ~~Image scanning for CVEs~~ | Done | No | `ferrocrate scan <image> [--scanner trivy |
| IMG-12 | ~~ruvector dedup~~ | Done | No | Embedding-based dedup helper in `ferro-mind`. |

### 3.3 Networking
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| NET-01 | ~~Bridge networking~~ | Partial | No | Runtime calls command builders via `run_cmd` but ferro-net has no execution layer — 95% command-builder stubs only. |
| NET-02 | ~~Host networking~~ | Done | No | `--network host` skips netns and runs on host network. |
| NET-03 | ~~None networking~~ | Done | No | `--network none` isolates netns (rootful via ip netns; rootless via unshare). |
| NET-04 | ~~Container-to-container DNS~~ | Partial | No | Runtime writes `/etc/hosts` entries but ferro-net DNS module is command-builder stubs only. |
| NET-05 | ~~Custom networks (subnets)~~ | Partial | No | Bridge CIDR/name configurable but ferro-net bridge.rs only builds commands — no execution layer. |
| NET-06 | ~~eBPF + iptables/nftables fallback~~ | Partial | No | eBPF mode silently falls back to iptables (no warning). ferro-net ebpf.rs is command-builder stubs only. |
| NET-07 | ~~WireGuard overlay~~ | Partial | No | Runtime calls `setup_wireguard` stub that returns error. ferro-net has no WireGuard execution. |
| NET-08 | ~~Port mapping~~ | Partial | No | `-p` works via runtime `run_cmd` calls but ferro-net iptables.rs/nftables.rs are command-builder stubs only. |
| NET-09 | ~~IPv6~~ | Partial | No | IPv6 CIDR config exists but allocation/wiring not fully tested. ferro-net stubs only. |
| NET-10 | ~~Bandwidth limiting~~ | Partial | No | `tc` commands built but not executed by ferro-net. Runtime shells out directly. |

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
| SEC-02 | ~~Seccomp profiles~~ | Partial | No | seccomp.rs parses JSON profiles into `SeccompProfile` struct but NEVER calls `seccomp()`/`prctl()` to apply them. Containers run with no syscall filtering. |
| SEC-03 | ~~AppArmor/SELinux integration~~ | Rework Needed | Yes | AppArmor via `aa-exec` and SELinux via `runcon` when enabled; policy enforcement still limited. |
| SEC-04 | ~~Capability dropping~~ | Done | No | Drop all by default; CLI `--cap-add` allows explicit caps. |
| SEC-05 | ~~Read-only rootfs for prod~~ | Done | No | CLI profile defaults to read-only for prod; override with --read-write. |
| SEC-06 | ~~no-new-privileges~~ | Done | No | CLI --no-new-privileges enforced via prctl. |
| SEC-07 | ~~Image signature verification~~ | Done | No | `FERROCRATE_SIGNATURE_VERIFY=1` uses cosign with `FERROCRATE_SIGNATURE_KEY`. |
| SEC-08 | ~~Runtime security monitoring (eBPF)~~ | Partial | No | Optional `FERROCRATE_EBPF_MONITOR=1` shells out to bpftool but ferro-net ebpf.rs is command-builder stubs only. |
| SEC-09 | ~~Encrypted container communication~~ | Partial | No | `--network encrypted` maps to WireGuard but `setup_wireguard` stub returns error. |
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
| AI-01 | ~~WASM inference (pluggable)~~ | Partial | No | Pluggable WASM inference registry exists but engine is NOOP — returns empty predictions. Needs wiring to `tract` (ONNX) or `synaptic-neural-wasm`. |
| AI-02 | ~~Predictive resource allocation~~ | Partial | No | Simple moving-average predictor only. No neural network. Needs wiring to `ruv-fann` or `neuro-divergent-models` for real predictions. |
| AI-03 | ~~Intelligent restart~~ | Partial | No | Static restart policy (failures > threshold). No adaptive learning. Needs `ruvector-sona` for self-optimizing restart decisions. |
| AI-04 | ~~Cost-tiered routing~~ | Partial | No | Cost/quality selection exists but no real routing intelligence — placeholder logic only. |
| AI-05 | ~~claude-flow integration~~ | Partial | No | rUv AI building blocks copied but NOT wired. Integration scaffolding only. |
| AI-06 | ~~Anomaly detection~~ | Partial | No | Static z-score computation only (16 lines). No neural network. Needs `ruv-fann` for multi-variate anomaly detection. |
| AI-07 | ~~ruvector build cache optimization~~ | Done | No | rUv distance/embedding primitives + dedup helper works correctly. |
| AI-08 | ~~Natural language management~~ | Partial | No | Vector memory uses O(n) brute-force cosine similarity. Needs `ruvector-core` HNSW for O(log n) search at scale. |
| AI-09 | ~~Self-learning via ruvector~~ | Partial | No | Vector memory + embeddings exist but NO actual learning. Needs `ruvector-sona` (LoRA + EWC++) for self-optimizing neural architecture. |
| AI-10 | ~~AI opt-out flag~~ | Done | No | `AiConfig.enabled` flag works correctly. `FERROCRATE_AI=0` disables all AI features. |
| AI-11 | ~~AI explainability~~ | Partial | No | `DecisionTrace` struct exists but not populated with real decision evidence. |
| AI-12 | ~~GPU/VRAM-aware scheduling~~ | Partial | No | 13-line stub takes VRAM requirement, returns hardcoded GPU index. No device discovery. Needs `cuda-rust-wasm` for real GPU enumeration. |

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
| PERF-01 | ~~Container startup time~~ | Partial | No | `scripts/perf/startup.sh` exists and measures latency but no optimization work done. Scripts measure only — no performance improvements implemented. |
| PERF-02 | ~~Image pull throughput~~ | Partial | No | `scripts/perf/pull.sh` measures download throughput but no optimization work done. |
| PERF-03 | ~~Idle memory (no daemon)~~ | Partial | No | `scripts/perf/idle-no-daemon.sh` reports RSS but no optimization work done. |
| PERF-04 | ~~Idle memory (with daemon)~~ | Partial | No | `scripts/perf/idle-daemon.sh` measures daemon RSS but no optimization work done. |
| PERF-05 | ~~Per-container overhead~~ | Partial | No | `scripts/perf/per-container.sh` measures RSS delta but no optimization work done. |
| PERF-06 | ~~Build performance~~ | Partial | No | `scripts/perf/build.sh` measures duration but no optimization work done. |
| PERF-07 | ~~CLI binary size~~ | Partial | No | `scripts/perf/binary-size.sh` records size but no optimization work done. |
| PERF-08 | ~~AI inference latency (WASM)~~ | Partial | No | `scripts/perf/ai-latency.sh` benchmarks decision latency but AI engine is noop — no real inference to measure. |

### 4.2 Compatibility
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| COMPAT-01 | ~~OCI Image Spec v1.1~~ | Done | Yes | Basic compliance script added; full compliance not verified. Rework Needed. |
| COMPAT-02 | ~~OCI Runtime Spec v1.2~~ | Done | Yes | Basic runtime validation script added; full parity not verified. Rework Needed. |
| COMPAT-03 | ~~OCI Distribution Spec v1.1~~ | Done | Yes | Basic distribution validation script added; full parity not verified. Rework Needed. |
| COMPAT-04 | ~~Docker API v1.45+~~ | Done | Yes | Added stats endpoint; broader parity still needed. Rework Needed. |
| COMPAT-05 | ~~docker-compose v3.x~~ | Done | No | Compose v3.x parsing + build + env/ports/volumes/dependencies covered. |
| COMPAT-06 | ~~Dockerfile syntax~~ | Done | Yes | Accepts additional common directives but still below 95% coverage. Rework Needed. |
| COMPAT-07 | ~~Linux kernel 5.10+~~ | Done | No | Runtime enforces minimum kernel version unless `FERROCRATE_IGNORE_KERNEL_MIN=1`. |
| COMPAT-08 | ~~x86_64, aarch64, riscv64~~ | Done | No | `scripts/build-targets.sh` builds release artifacts for all three targets; `ferro-desktop` crate added for host-side desktop integration scaffolding. |
| COMPAT-09 | ~~Kubernetes CRI v1~~ | Partial | No | CRI shim (ferro-cri) implements Version, Status, ListImages (with filter), ImageStatus (with verbose info), PullImage, and RemoveImage. Still missing core pod/container runtime methods such as RunPodSandbox, StopPodSandbox, RemovePodSandbox, CreateContainer, StartContainer, StopContainer, RemoveContainer, ExecSync, and most remaining CRI operations. Partial shim, not production-ready. |

### 4.3 Reliability
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| REL-01 | ~~Runtime crash does not kill containers~~ | Done | Yes | `scripts/supervise.sh` monitors orphaned containers; daemonization still needed. Rework Needed. |
| REL-02 | ~~Graceful degradation without AI~~ | Done | Yes | AI audit logger respects `FERROCRATE_AI=0` and disables AI logging. Rework Needed. |
| REL-03 | ~~Data integrity for image store~~ | Done | No | Verify sha256 digests on every config/layer read from cache. |
| REL-04 | ~~Atomic operations~~ | Done | Yes | Blob pulls now write to temp and rename for atomicity. Rework Needed. |
| REL-05 | ~~Test coverage~~ | Done | Yes | `scripts/coverage.sh` enforces coverage via cargo-tarpaulin. Rework Needed. |

### 4.4 Observability
| ID | Requirement | Status | Rework Needed | Evidence / Notes |
|---|---|---|---|---|
| OBS-01 | ~~Prometheus metrics endpoint~~ | Done | No | `ferrocrate daemon --metrics-addr` serves Prometheus metrics at `/metrics`. |
| OBS-02 | ~~OpenTelemetry trace export~~ | Done | Yes | Optional HTTP export via `FERROCRATE_OTEL_ENDPOINT` from observability logs. Rework Needed. |
| OBS-03 | ~~Structured JSON logging~~ | Done | No | JSONL event log emitted under runtime logs. |
| OBS-04 | ~~Resource usage stats~~ | Done | No | CLI stats reads cgroup v2 memory/cpu/pids counters. |
| OBS-05 | ~~AI decision audit log~~ | Done | Yes | `ferrocrate ai-audit` writes DecisionTrace to audit log when enabled. Rework Needed. |
