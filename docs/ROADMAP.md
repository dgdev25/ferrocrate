# FerroCrate PRD-Backed Roadmap

**Source of truth:** `/media/lyle/datadisk/dev/ferrocrate/docs/product-requirements.md`
**Last Updated:** February 11, 2026
**Status:** Audit + Re-scope

---

## Audit Summary (PRD Coverage)

Status legend: **Done**, **Partial**, **Not Started**

- **Core runtime + images + storage**: Partial coverage; base runtime exists, but many required features are missing (build, inspect, volumes, restart policies, healthchecks).
- **Networking**: Partial scaffolding (eBPF + iptables/nftables builders, no runtime wiring or advanced features).
- **Security**: Partial (rootless + seccomp parsing + profile generation, missing enforcement + signatures + audit).
- **Compose**: Partial (parsing + ordering + CLI, no orchestration).
- **AI / ruv integrations**: Not started.
- **Developer experience + compatibility**: Mostly not started.

---

## Workstreams (Mapped to PRD IDs)

### 3.1 Container Lifecycle Management
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| CLM-01 | Run OCI-compliant container images | Partial | Run pulls manifest + layers, constructs rootfs; chroot only when root. |
| CLM-02 | ~~Create/start/stop/restart/kill/remove~~ | Done | Restart/kill/remove implemented and wired in CLI. |
| CLM-03 | ~~Pause/unpause via cgroup freezer~~ | Done | CLI pause/unpause uses cgroup.freeze via cgroups v2. |
| CLM-04 | Container exec | Done | `ferro-core` exec + CLI wired. |
| CLM-05 | Container logs | Done | Runtime logs + CLI logs. |
| CLM-06 | ~~Inspect (JSON metadata)~~ | Done | CLI inspect outputs JSON metadata from container store. |
| CLM-07 | Health checks | Partial | CLI health checks + image config HEALTHCHECK support; timeout enforcement not wired. |
| CLM-08 | ~~Restart policies~~ | Done | CLI --restart with supervisor loop (no/on-failure/always/unless-stopped). |
| CLM-09 | ~~Resource limits (mem/cpu/pids)~~ | Done | cgroups v2 limits enforced when provided via CLI. |
| CLM-10 | ~~Env vars, labels, annotations~~ | Done | CLI flags for env/label/annotation stored in container metadata. |

### 3.2 Image Management
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| IMG-01 | Pull images from OCI registries | Partial | Docker config auth + credential helpers; not tested across registries. |
| IMG-02 | Push images to OCI registries | Partial | Docker config auth + credential helpers; not tested across registries. |
| IMG-03 | Content-addressable store (Blake3) | Not Started | No Blake3 store. |
| IMG-04 | Zstd compression for layers | Partial | zstd/gzip decompression only. |
| IMG-05 | Lazy image pulling | Not Started | No lazy pull or FUSE streaming. |
| IMG-06 | Dockerfile build | Not Started | CLI stub only. |
| IMG-07 | ferrofile.toml build | Not Started | Not implemented. |
| IMG-08 | Multi-stage builds | Not Started | Not implemented. |
| IMG-09 | Build cache | Not Started | Not implemented. |
| IMG-10 | ~~Tag/list/remove/prune images~~ | Done | Tag/list done; remove/prune implemented. |
| IMG-11 | CVE scanning | Not Started | Not implemented. |
| IMG-12 | ruvector dedup | Not Started | Not implemented. |

### 3.3 Networking
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| NET-01 | Bridge networking | Partial | Bridge + netns/veth helpers exist; not wired to runtime. |
| NET-02 | Host networking | Not Started | No CLI or runtime wiring. |
| NET-03 | None networking | Not Started | No CLI or runtime wiring. |
| NET-04 | Container-to-container DNS | Not Started | DNS config render only. |
| NET-05 | Custom networks (subnets) | Not Started | No API or state. |
| NET-06 | eBPF + iptables/nftables fallback | Partial | Builders + flags; no live backend integration. |
| NET-07 | WireGuard overlay | Not Started | Not implemented. |
| NET-08 | Port mapping | Partial | Portmap rule builders only. |
| NET-09 | IPv6 | Not Started | Not implemented. |
| NET-10 | Bandwidth limiting | Not Started | Not implemented. |

### 3.4 Storage and Volumes
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| STR-01 | ~~Named volumes~~ | Done | Volume store + CLI create/ls/rm implemented. |
| STR-02 | ~~Bind mounts~~ | Done | CLI --bind with runtime bind mounts. |
| STR-03 | ~~tmpfs mounts~~ | Done | CLI --tmpfs + runtime tmpfs mounts. |
| STR-04 | ~~Volume drivers~~ | Done | Driver registry + local driver with CLI selection. |
| STR-05 | OverlayFS default | Done | OverlayFS + FUSE fallback implemented. |
| STR-06 | ~~Read-only rootfs~~ | Done | CLI --read-only remounts rootfs read-only after mounts. |
| STR-07 | ~~Volume backup/restore~~ | Done | CLI backup/restore with tar archives. |

### 3.5 Security
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| SEC-01 | Rootless by default | Done | User namespaces + rootless runtime. |
| SEC-02 | Seccomp profiles | Done | Default profile + parser, not enforced in runtime. |
| SEC-03 | AppArmor/SELinux integration | Partial | Profile generation only. |
| SEC-04 | Capability dropping | Partial | Drop helper exists; not enforced. |
| SEC-05 | Read-only rootfs for prod | Not Started | Not implemented. |
| SEC-06 | ~~no-new-privileges~~ | Done | CLI --no-new-privileges enforced via prctl. |
| SEC-07 | Image signature verification | Not Started | Not implemented. |
| SEC-08 | Runtime security monitoring (eBPF) | Not Started | Not implemented. |
| SEC-09 | Encrypted container communication | Not Started | Not implemented. |
| SEC-10 | Audit logging | Not Started | Not implemented. |

### 3.6 Compose / Multi-Container
| ID | Requirement | Status | Evidence / Notes |
|---|---|---|---|
| CMP-01 | docker-compose.yml compatibility | Partial | Parse + validate only. |
| CMP-02 | Native compose subcommand | Partial | CLI exists; no orchestration. |
| CMP-03 | Service dependency ordering | Partial | Ordering exists; condition handling not implemented. |
| CMP-04 | Service scaling | Not Started | Not implemented. |
| CMP-05 | .env support | Partial | Interpolation works; no .env file loading. |
| CMP-06 | Profiles | Not Started | Not implemented. |
| CMP-07 | Watch mode | Not Started | Not implemented. |

### 3.7 AI / Intelligence (ferro-mind)
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
| CLI-01 | Docker-compatible CLI syntax | Partial | Core commands exist; behavior not Docker-equivalent. |
| CLI-02 | Docker socket compatibility | Not Started | Not implemented. |
| CLI-03 | Shell completion | Not Started | Not implemented. |
| CLI-04 | Colored, human-friendly output | Not Started | Not implemented. |
| CLI-05 | JSON output mode | Not Started | Not implemented. |
| CLI-06 | Migration tool | Not Started | Not implemented. |
| CLI-07 | Interactive TUI | Not Started | Not implemented. |

---

## Non-Functional Requirements (PRD §4)

### 4.1 Performance
All **Not Started** (no benchmarks, no enforced targets).

### 4.2 Compatibility
| ID | Requirement | Status |
|---|---|---|
| COMPAT-01 | OCI Image Spec v1.1 | Partial |
| COMPAT-02 | OCI Runtime Spec v1.2 | Partial |
| COMPAT-03 | OCI Distribution Spec v1.1 | Partial |
| COMPAT-04 | Docker API v1.45+ | Not Started |
| COMPAT-05 | docker-compose v3.x | Partial |
| COMPAT-06 | Dockerfile syntax | Not Started |
| COMPAT-07 | Linux kernel 5.10+ | Not Started (no enforcement) |
| COMPAT-08 | x86_64, aarch64, riscv64 | Not Started |
| COMPAT-09 | Kubernetes CRI v1 | Not Started |

### 4.3 Reliability
All **Not Started** (no daemon resilience, no atomicity guarantees, no coverage targets enforced).

### 4.4 Observability
All **Not Started** (no Prometheus/OpenTelemetry/JSON logging implemented).

---

## Execution Order (Rebuilt to PRD IDs)

1. **CLM & IMG core parity**: CLM-01/02/04/05/09 + IMG-01/02/04/10
2. **Storage + volumes**: STR-01/02/03/06 + STR-05 hardening
3. **Security enforcement**: SEC-01/02/04/06 + SEC-10
4. **Networking wiring**: NET-01/02/03/06/08
5. **Compose MVP**: CMP-01/02/03/05 + minimal orchestration
6. **Build pipeline**: IMG-06/08/09 + CLI build parity
7. **Compatibility targets**: COMPAT-01/02/03/05/06
8. **AI/ruv integrations**: AI-01/07/09 + ruvector usage
9. **Non-functional**: PERF/OBS/REL + hardened releases
10. **Kubernetes CRI**: COMPAT-09 + CRI implementation

---

## Notes
- This roadmap is intentionally PRD-complete; nothing omitted.
- Use this file as the task source of truth for sequencing and status updates.
