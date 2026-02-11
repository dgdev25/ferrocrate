# FerroCrate PRD-Backed Roadmap (Rebuilt)

**Source of truth:** `docs/product-requirements.md`  
**Last Updated:** February 11, 2026  
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
   - IMG-01/02/03/05/10
   - STR-01/02/03/05/06
   - SEC-01/02/04/06
   - CLI-01/04/05
   - OBS-03/OBS-04

2. **Phase 2 — Networking + Compose (P0/P1)**
   - NET-01/02/03/04/05/06/08
   - CMP-01/02/03/05
   - COMPAT-05

3. **Phase 3 — Build Pipeline + Dockerfile Compatibility**
   - IMG-06/08/09
   - COMPAT-06

4. **Phase 4 — Kubernetes CRI**
   - COMPAT-09

5. **Phase 5 — Hardening + Non-Functional**
   - SEC-03/05/07/08/09/10
   - PERF-01..08
   - REL-01..05
   - OBS-01/02/05

6. **Phase 6 — AI / ruv Integrations**
   - AI-01..12
   - IMG-12 (ruvector dedup)

7. **Phase 7 — Documentation (Last)**
   - README refresh, CLI reference, architecture notes, migration guide

---

## 3. Functional Requirements

### 3.1 Container Lifecycle Management
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| CLM-01 | Run OCI-compliant container images | Partial | Run pulls manifest + layers; config CMD/Entrypoint, Env, User, WorkingDir used when provided; ports/volumes not wired. |
| CLM-02 | ~~Create/start/stop/restart/kill/remove~~ | Done | Restart/kill/remove implemented and wired in CLI. |
| CLM-03 | ~~Pause/unpause via cgroup freezer~~ | Done | CLI pause/unpause uses cgroup.freeze via cgroups v2. |
| CLM-04 | ~~Container exec~~ | Done | `ferro-core` exec + CLI wired. |
| CLM-05 | ~~Container logs~~ | Done | Runtime logs + CLI logs. |
| CLM-06 | ~~Inspect (JSON metadata)~~ | Done | CLI inspect outputs JSON metadata from container store. |
| CLM-07 | ~~Health checks~~ | Done | CLI health checks + image config HEALTHCHECK support with timeout enforcement. |
| CLM-08 | ~~Restart policies~~ | Done | CLI --restart with supervisor loop (no/on-failure/always/unless-stopped). |
| CLM-09 | ~~Resource limits (mem/cpu/pids)~~ | Done | cgroups v2 limits enforced when provided via CLI. |
| CLM-10 | ~~Env vars, labels, annotations~~ | Done | CLI flags for env/label/annotation stored in container metadata. |

### 3.2 Image Management
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| IMG-01 | Pull images from OCI registries | Partial | Docker config auth + credential helpers + Bearer token challenge; not tested across registries. |
| IMG-02 | Push images to OCI registries | Partial | Docker config auth + credential helpers + Bearer token challenge; not tested across registries. |
| IMG-03 | Content-addressable store (Blake3) | Partial | Blake3 CAS for blobs + file-level hardlink dedup during rootfs assembly; storage reduction not validated. |
| IMG-04 | Zstd compression for layers | Partial | `build --compress zstd` emits zstd layers; other pipelines not wired. |
| IMG-05 | Lazy image pulling | Partial | `pull --lazy` stores manifest/config; missing blobs fetched on demand. |
| IMG-06 | Dockerfile build | Partial | Minimal FROM scratch + COPY + HEALTHCHECK build; no multi-stage or base images. |
| IMG-07 | ferrofile.toml build | Partial | Minimal [build] spec (context/dockerfile/tag) wired to Dockerfile build. |
| IMG-08 | Multi-stage builds | Not Started | Not implemented. |
| IMG-09 | Build cache | Not Started | Not implemented. |
| IMG-10 | ~~Tag/list/remove/prune images~~ | Done | Tag/list done; remove/prune implemented. |
| IMG-11 | CVE scanning | Not Started | Not implemented. |
| IMG-12 | ruvector dedup | Not Started | Not implemented. |

### 3.3 Networking
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| NET-01 | Bridge networking | Partial | Runtime can create bridge/netns/veth for rootful runs; iptables used for published ports; rootless skips netns. |
| NET-02 | Host networking | Partial | CLI `--network host` skips netns setup; not tested. |
| NET-03 | None networking | Partial | CLI `--network none` creates netns with loopback only; not tested. |
| NET-04 | Container-to-container DNS | Partial | Runtime writes `/etc/hosts` with container name/id to IP mappings for running containers; no DNS server yet. |
| NET-05 | Custom networks (subnets) | Partial | Bridge CIDR/name configurable via `FERROCRATE_BRIDGE_CIDR` + `FERROCRATE_BRIDGE_NAME`. |
| NET-06 | eBPF + iptables/nftables fallback | Partial | Port mapping supports iptables/nftables; eBPF path still stubbed. |
| NET-07 | WireGuard overlay | Not Started | Not implemented. |
| NET-08 | Port mapping | Partial | `-p` uses iptables or nftables DNAT/forward rules depending on backend. |
| NET-09 | IPv6 | Not Started | Not implemented. |
| NET-10 | Bandwidth limiting | Not Started | Not implemented. |

### 3.4 Storage and Volumes
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| STR-01 | ~~Named volumes~~ | Done | Volume store + CLI create/ls/rm implemented. |
| STR-02 | ~~Bind mounts~~ | Done | CLI --bind with runtime bind mounts. |
| STR-03 | ~~tmpfs mounts~~ | Done | CLI --tmpfs + runtime tmpfs mounts. |
| STR-04 | ~~Volume drivers~~ | Done | Driver registry + local driver with CLI selection. |
| STR-05 | ~~OverlayFS default~~ | Done | OverlayFS + FUSE fallback implemented. |
| STR-06 | ~~Read-only rootfs~~ | Done | CLI --read-only remounts rootfs read-only after mounts. |
| STR-07 | ~~Volume backup/restore~~ | Done | CLI backup/restore with tar archives. |

### 3.5 Security
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| SEC-01 | ~~Rootless by default~~ | Done | User namespaces + rootless runtime. |
| SEC-02 | ~~Seccomp profiles~~ | Done | Default profile + parser, not enforced in runtime. |
| SEC-03 | AppArmor/SELinux integration | Partial | Profile generation only. |
| SEC-04 | ~~Capability dropping~~ | Done | Drop all by default; CLI `--cap-add` allows explicit caps. |
| SEC-05 | ~~Read-only rootfs for prod~~ | Done | CLI profile defaults to read-only for prod; override with --read-write. |
| SEC-06 | ~~no-new-privileges~~ | Done | CLI --no-new-privileges enforced via prctl. |
| SEC-07 | Image signature verification | Not Started | Not implemented. |
| SEC-08 | Runtime security monitoring (eBPF) | Not Started | Not implemented. |
| SEC-09 | Encrypted container communication | Not Started | Not implemented. |
| SEC-10 | Audit logging | Not Started | Not implemented. |

### 3.6 Compose / Multi-Container
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| CMP-01 | docker-compose.yml compatibility | Partial | Parse + validate with .env interpolation; orchestration missing. |
| CMP-02 | Native compose subcommand | Partial | `compose up` starts services sequentially with basic image/env/ports/labels; `compose down` stops/removes by service name. |
| CMP-03 | Service dependency ordering | Partial | Ordering exists; waits for `service_healthy` dependencies before start. |
| CMP-04 | Service scaling | Not Started | Not implemented. |
| CMP-05 | .env support | Partial | `.env` loaded for interpolation; service env_file merged into env. |
| CMP-06 | Profiles | Not Started | Not implemented. |
| CMP-07 | Watch mode | Not Started | Not implemented. |

### 3.7 AI / Intelligence (ferro-mind + ruv)
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| AI-01 | WASM inference (pluggable) | Not Started | Not implemented. |
| AI-02 | Predictive resource allocation | Not Started | Not implemented. |
| AI-03 | Intelligent restart | Not Started | Not implemented. |
| AI-04 | Cost-tiered routing | Not Started | Not implemented. |
| AI-05 | claude-flow integration | Not Started | Not implemented. |
| AI-06 | Anomaly detection | Not Started | Not implemented. |
| AI-07 | ruvector build cache optimization | Not Started | Not implemented. |
| AI-08 | Natural language management | Not Started | Not implemented. |
| AI-09 | Self-learning via ruvector | Not Started | Not implemented. |
| AI-10 | AI opt-out flag | Not Started | Not implemented. |
| AI-11 | AI explainability | Not Started | Not implemented. |
| AI-12 | GPU/VRAM-aware scheduling | Not Started | Not implemented. |

### 3.8 CLI and Developer Experience
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| CLI-01 | Docker-compatible CLI syntax | Partial | Core commands exist; `ps` alias + `-e/-l` flags added; behavior still not Docker-equivalent. |
| CLI-02 | Docker socket compatibility | Not Started | Not implemented. |
| CLI-03 | Shell completion | Not Started | Not implemented. |
| CLI-04 | ~~Colored, human-friendly output~~ | Done | Colored status + image refs for text output. |
| CLI-05 | ~~JSON output mode~~ | Done | `--format json` supported for images/containers/logs/inspect/stats. |
| CLI-06 | Migration tool | Not Started | Not implemented. |
| CLI-07 | Interactive TUI | Not Started | Not implemented. |

---

## 4. Non-Functional Requirements

### 4.1 Performance
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| PERF-01 | Container startup time | Not Started | No benchmarks implemented. |
| PERF-02 | Image pull throughput | Not Started | No benchmarks implemented. |
| PERF-03 | Idle memory (no daemon) | Not Started | No measurement harness. |
| PERF-04 | Idle memory (with daemon) | Not Started | No measurement harness. |
| PERF-05 | Per-container overhead | Not Started | No measurement harness. |
| PERF-06 | Build performance | Not Started | No benchmark parity test. |
| PERF-07 | CLI binary size | Not Started | No size checks enforced. |
| PERF-08 | AI inference latency (WASM) | Not Started | No measurement harness. |

### 4.2 Compatibility
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| COMPAT-01 | OCI Image Spec v1.1 | Partial | Basic image handling; full compliance not verified. |
| COMPAT-02 | OCI Runtime Spec v1.2 | Partial | Namespaces + cgroups v2; spec parity not verified. |
| COMPAT-03 | OCI Distribution Spec v1.1 | Partial | Basic pull/push; error parity not verified. |
| COMPAT-04 | Docker API v1.45+ | Not Started | Not implemented. |
| COMPAT-05 | docker-compose v3.x | Partial | Parse/validate + interpolation only. |
| COMPAT-06 | Dockerfile syntax | Partial | Minimal builder; far from 95% coverage. |
| COMPAT-07 | Linux kernel 5.10+ | Not Started | No min-version checks. |
| COMPAT-08 | x86_64, aarch64, riscv64 | Not Started | No multi-arch builds verified. |
| COMPAT-09 | Kubernetes CRI v1 | Not Started | Not implemented. |

### 4.3 Reliability
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| REL-01 | Runtime crash does not kill containers | Not Started | No supervisor/daemonization strategy. |
| REL-02 | Graceful degradation without AI | Not Started | No explicit toggles or tests. |
| REL-03 | Data integrity for image store | Not Started | Checksums not verified on every read. |
| REL-04 | Atomic operations | Not Started | No atomic pull/volume operation guarantees. |
| REL-05 | Test coverage | Not Started | No coverage enforcement. |

### 4.4 Observability
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| OBS-01 | Prometheus metrics endpoint | Not Started | Not implemented. |
| OBS-02 | OpenTelemetry trace export | Not Started | Not implemented. |
| OBS-03 | ~~Structured JSON logging~~ | Done | JSONL event log emitted under runtime logs. |
| OBS-04 | ~~Resource usage stats~~ | Done | CLI stats reads cgroup v2 memory/cpu/pids counters. |
| OBS-05 | AI decision audit log | Not Started | Not implemented. |
