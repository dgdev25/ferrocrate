# FerroCrate Comprehensive Remaining Work Roadmap

<!-- Single consolidated backlog. Historical completion is preserved below; all
     forward work is sourced from the PRD-backed roadmap, completion plan,
     security audit, RVF plan, platform plan, and compatibility contracts. -->

**Maturity:** mature core with a broad, partially production-qualified platform · **Last updated:** 2026-08-16 · HEAD `52633ad`

## How to use this roadmap

This is the one forward-looking backlog for the repository. `Now` contains
release blockers and qualification gaps. `Next` contains the next product and
platform capabilities after those gates. `Later` contains strategic work that
is real but not required for the current release. Small tactical defects belong
in an audit or issue, not as new roadmap epics.

Evidence sources: `docs/ROADMAP.md`, `docs/PROJECT_COMPLETION_PLAN.md`,
`docs/REMEDIATION-PLAN.md`, `docs/SECAUDIT_TASKLIST.md`,
`docs/RVF_INTEGRATION_PLAN.md`, `docs/macos-windows-support-plan.md`,
`docs/monetization-implementation-plan.md`, `README.md`, CRI/Docker
compatibility contracts, and accepted ADRs 0013–0014.

## Now

### 1. Production network and host qualification

*Why now:* the implementation is executor-backed and green on one privileged
Ubuntu row, but the supported-host claim, broader kernel coverage, and some
network/security qualification gates remain open. *Size:* XL. *Sources:* NET-01,
NET-04–10; SEC-08/09; `docs/compatibility`; host-matrix evidence.

- [x] Define the release support matrix (distribution, kernel, architecture, rootful/rootless, required tools, unsupported combinations) in `docs/evidence/host-matrix/rows.tsv`; candidates remain non-claims until qualified.
- [ ] Run and archive bridge, custom-network, IPv4/IPv6, DNS/hosts, firewall/port-map, MTU, `tc`, WireGuard, teardown, and recovery on every supported row; `scripts/run-host-matrix.sh` now orchestrates every manifest row, archives per-row logs/results, and distinguishes blocked prerequisites from failures. The 2026-08-16 privileged rerun qualified the matching Ubuntu 26.04/kernel 7.0.0 row, including managed-overlay and authenticated two-namespace WireGuard traffic, while five distribution/kernel/architecture rows remain blocked in `docs/evidence/host-matrix/2026-08-16-run.md`.
- [ ] Qualify rootless networking, volumes, image pulls, and CRI constraints on each supported row; record strict prerequisite failures. Rootless bridge networking, image pulls, and outbound IPv4/DNS now pass on the Ubuntu 26.04 row through the opt-in `slirp4netns` path (`docs/evidence/verification/2026-08-16-rootless-slirp.md`), with IPv6 command support opt-in but inbound traffic, port mappings, rootless volumes, CRI, and other host rows remaining open.
- [ ] Complete successful kernel-backed eBPF monitoring qualification; the rootful Aya packet loader now passes verifier acceptance plus attach/detach cleanup on the qualified Ubuntu row (`docs/evidence/verification/2026-08-16-ebpf-loader.md`), while the live published-port lane still fails its reverse response path (`docs/evidence/verification/2026-08-16-ebpf-live-traffic.md`), security-monitor event delivery, and explicit fallback provenance remain open. Retain explicit iptables/nftables fallback when eBPF is unavailable.
- [ ] Complete encrypted managed-overlay packet-flow qualification across the supported host matrix; the live rootful signed-grant-to-WireGuard mutation and clean teardown now pass (`docs/evidence/verification/2026-08-16-wireguard-grant-path.md`), while stale-revision, rollback, recovery, key-rotation, and multi-row packet-flow evidence remain open.
- [ ] Decide and, only if operationally required, run FCNET-105 across physically separate machines with clock, MTU, route, endpoint, topology, and key-ID evidence (ADR-0013 currently defers this).
- [ ] Keep every network mutation, attach/detach, firewall change, and cleanup under the executor plus authorization/grant/witness protocol.
- [x] Publish a release troubleshooting and recovery runbook for capability denial, partial effects, quarantine, and operator repair (`docs/security/network-recovery.md`).

### 2. CRI production qualification

*Why now:* the lifecycle RPCs and durable state exist, but successful image/rootfs
execution, sandbox networking, restart recovery, cancellation, and kubelet-level
compatibility are not yet qualified. *Size:* XL. *Sources:* COMPAT-09,
`docs/compatibility/cri.md`, `docs/compatibility/cri-conformance.md`.

- [x] Complete pod-sandbox network reconciliation on restart; reopened state preserves readiness when the netns exists and reports `NotReady` after namespace loss.
- [x] Qualify Create/Start/Stop/RemoveContainer, ContainerStatus, and ExecSync with a real OCI image/rootfs, including exit code, stdout, and deadline behavior; broader image corpus and cancellation remain open.
- [x] Bind pod/container identity, sandbox parent, pinned image, normalized command/environment/resource execution digest, and lifecycle state into the common authorization facts and witness request digest; canonical-byte and CRI socket coverage are passing.
- [x] Add UDS conformance fixtures for the exposed lifecycle path; malformed requests, deadlines, retries, and full method idempotency remain in the qualification expansion.
- [x] Publish the supported CRI method/version/error matrix and wire-level malformed/unknown/idempotency fixtures; kubelet/containerd compatibility remains a separate qualification gate.
- [ ] Test durable sandbox/container recovery at each intent/effect/store boundary; CRI metadata now uses transactional SQLite with WAL/`synchronous=FULL` durability and legacy JSON import, no-root reopen coverage verifies persisted `Exited` state, exit code, and reason, startup reconciles a missing CRI runtime binding from the stable runtime label plus sandbox parent and fails closed on ambiguity, the real OCI socket fixture restarts the CRI daemon while a workload is running and verifies recovered identity/state, subprocess fixtures now hard-kill the actual `ferro-cri` binary after each durable sandbox/container lifecycle transition, and the rootful OCI fixture verifies StopContainer -> StartContainer on the same durable mapping with blocking-worker execution for synchronous runtime/image work. CRI authorization now uses `ContainerRun` only for the initial publication and `ContainerStart` for an existing runtime binding. A guarded rootful fault-injection fixture now kills the daemon after the runtime effect but before CRI mapping publication and verifies restart rebinding (`docs/evidence/verification/2026-08-16-cri-operation-recovery.md`). The complete CRI test suite and Clippy gate pass on the qualified Ubuntu host (`docs/evidence/verification/2026-08-16-cri-test-suite.md`), and sandbox/container mutations now roll back in-memory metadata and newly created runtime/netns effects when durable publication fails. Store-publication, sandbox/network effect-boundary fault injection, and broader kernel-effect reconciliation remain open.
- [x] Update the PRD-backed compatibility table for the currently qualified methods; kubelet/containerd compatibility remains explicitly unclaimed until its separate gate passes.

### 3. Security enforcement and dependency hygiene

*Why now:* core authorization and seccomp enforcement are implemented, while MAC
policy coverage, runtime monitoring, dependency advisories, and complete shell-out
reduction remain open. *Size:* L–XL. *Sources:* SEC-03/08/09,
`docs/SECAUDIT_TASKLIST.md`, `docs/REMEDIATION-PLAN.md`.

- [ ] Complete AppArmor and SELinux distribution qualification: profile selection/loading diagnostics are implemented and strict prerequisites are gated; the privileged 2026-08-16 run found AppArmor tooling and an enabled AppArmor kernel while FerroCrate enforcement flags remain disabled (`docs/evidence/security/2026-08-16-mac-policy.md`), so denial reporting, rootless behavior, and policy rollback still require enforcement-enabled workload evidence.
- [ ] Finish eBPF syscall/security monitoring with a production execution path, capability admission, event schema, bounded buffering, and fallback diagnostics; bounded configuration admission now rejects case-insensitive duplicate events before any command runs, with explicit bpftool checks, tracepoint verification, transactional rollback/cleanup for partial installs, and fail-loud fallback diagnostics documented in `docs/security/ebpf-monitoring.md`. The privileged host's BPF feature probe, admission tests, and network Aya loader attach/detach smoke pass (`docs/evidence/security/2026-08-16-ebpf-monitoring.md`; `docs/evidence/verification/2026-08-16-ebpf-loader.md`), while security-monitor attachment, kernel event delivery, and distribution-wide qualification remain open.
- [ ] Complete the remaining runtime shell-out audit; the current production inventory and justified exceptions are documented in `docs/security/shell-out-audit.md`, and WireGuard plus eBPF/tc probes now use the shared typed executor, while kernel qualification and workload-helper review remain open.
- [x] Formally time-box `RUSTSEC-2025-0141` (`bincode` via `ruvector-core`) in the risk-acceptance register, with dependency-path evidence and a 2026-09-30 revalidation deadline; replacement remains future work.
- [ ] Replace the remaining `sled` backends to remove `RUSTSEC-2025-0057` (`fxhash`) and `RUSTSEC-2024-0384` (`instant`), including migration and backward-compatibility tests. Volume, image, CRI metadata/replay, Compose replay, the active container runtime, and the witness journal now use SQLite at runtime; Compose's legacy importer is isolated behind the opt-in `legacy-sled` feature and image/volume/CRI-delegation/witness importers now fail closed by default behind the opt-in `legacy-sled-importers` feature (`docs/architecture/legacy-sled-importers.md`), with atomic witness cutover and readiness-marker coverage retained. The unconditional ferro-core dev-dependency has now been removed and the default workspace graph remains Sled-free (`docs/evidence/security/2026-08-16-sled-default-graph.md`); the legacy container implementation is compiled only under `legacy-sled-importers`. The remaining dependency-removal work is retiring that compatibility API and feature after the supported migration window. The schema, transaction contract, locked cutover, retry behavior, and verification gates are specified in `docs/architecture/witness-journal-sqlite-migration.md`; the post-cutover workspace run is archived in `docs/evidence/verification/2026-08-16-workspace-serial.md`.
- [ ] Complete remaining PAL/security-audit continuation runs, triage new findings, and merge accepted remediations into this roadmap. The 2026-08-16 `cargo audit --deny warnings` gate now passes after upgrading all resolvable advisory paths (`docs/evidence/security/2026-08-16-dependency-audit.md`); only the two no-fixed-release unsoundness IDs remain explicitly time-boxed in the risk register, while PAL continuation and witness-backend remediation remain open.
- [ ] Run adversarial checks for symlink/path traversal, descriptor substitution, namespace identity, profile parsing, and fail-closed authorization on every new execution surface; MAC profile generation and Docker create names now reject traversal, shell metacharacters, and oversized identifiers before file or policy-command creation, while the wider execution-surface audit remains open.

### 4. Compatibility and release qualification

*Why now:* the implementation has broad feature coverage, but OCI, Dockerfile,
Docker Engine, and release claims are still marked partial or rework-needed.
*Size:* XL. *Sources:* COMPAT-01–06, IMG-06, Docker compatibility docs,
`docs/PROJECT_COMPLETION_PLAN.md`.

- [ ] Establish full OCI Image, Runtime, and Distribution conformance suites beyond the current basic validation scripts; the repeatable repository fixture gate now runs all three smoke paths plus fail-closed malformed manifest/descriptor/platform fixtures via `scripts/oci-conformance.sh`, but upstream corpus coverage remains open.
- [ ] Close Dockerfile parity gaps: `COPY --chmod`, deterministic unsupported-flag/directive errors, and explicit host-bound `build --platform` validation are now covered; shell-form `RUN --mount=type=cache` now has validated targets/IDs, isolated persistent cache storage, and symlink rejection, repeatable `--build-context name=path` is authorization/cache-bound with traversal checks, and secret mounts now have a validated temporary-file path, while SSH mounts, cross-platform output, and full parity remain open.
- [x] Define supported Docker Engine API versions and negotiation behavior; publish the endpoint/status/error matrix from the actual socket implementation.
- [ ] Complete high-value Docker container, image, network, volume, streaming, wait, and event endpoints while preserving authorization and witness receipts; image history, container list `all`/`limit`/`since`/`before` filters with deterministic newest-first ordering, image-list reference/time filters, authorized image tagging, image-prune `dangling`/`until` filters with strict unsupported-selector rejection, network/volume inspect/list/prune (network list/prune support `name`/`driver`/`scope`/`type`, Docker network create now separates IPv4 and IPv6 IPAM entries and validates `EnableIPv6`, and network list/inspect now preserve the requested IPv6 subnet/gateway in Docker IPAM responses with public Unix-socket integration coverage; volume list/prune support exact `name`/`driver`, all with fail-closed unsupported selectors), authorized container rename with durable metadata mutation, native authorized `start` plus `/containers/{id}/start` routing (`docs/evidence/verification/2026-08-16-container-start.md`), `/containers/{id}/wait` timeout with validated `not-running`/`next-exit` conditions, pause/unpause, `/containers/{id}/top`, logs `tail`/chunked `follow=1`, `/containers/{id}/attach` strict query validation plus explicit TCP upgrade/raw follow support and stdin forwarding when a live container's `/proc/<pid>/fd/0` is available (`docs/evidence/verification/2026-08-16-docker-attach.md`), chunked stats streaming, health state in container inspect, durable bind/tmpfs mount replay across restart (`docs/evidence/verification/2026-08-16-container-mount-replay.md`), and the two-step authorized `/containers/{id}/exec` plus `/exec/{id}/start` API are wired; selected remote contexts now also route `run`, `wait`, `top`, `pull`, `rmi`, `image-prune`, non-interactive `exec`, `push`, streamed `logs --follow`, and streamed `stats --follow` through the Docker transport (`docs/evidence/verification/2026-08-16-wait-routing.md`; `docs/evidence/verification/2026-08-16-top-routing.md`; `docs/evidence/verification/2026-08-16-remote-run-routing.md`; `docs/evidence/verification/2026-08-16-remote-logs-follow.md`; `docs/evidence/verification/2026-08-16-remote-stats-follow.md`; `docs/evidence/verification/2026-08-16-remote-image-routing.md`; `docs/evidence/verification/2026-08-16-remote-exec-routing.md`; `docs/evidence/verification/2026-08-16-remote-push-routing.md`); rejected and valid create payloads, pre-start inspect/list, atomic pending-create reload, and pending removal are covered by evidence, while real OCI start/inspect execution qualification, cross-host streams, interactive attach, live registry qualification, and broader endpoint parity remain open.
- Container rename CLI and remote-context routing are verified separately in `docs/evidence/verification/2026-08-16-rename-routing.md`.
- [x] Run the current Docker API matrix and Compose contract suites against the public Unix socket, including versioned paths and explicit unsupported endpoint errors; retries and streaming expansion remain in the endpoint completion work.
- Image history is now exposed by the native CLI and selected remote contexts, with manifest-layer Docker history records verified in `docs/evidence/verification/2026-08-16-image-history-routing.md`.
- Network prune is now exposed by the native CLI and selected remote contexts, retaining built-ins and associated networks and preserving authorization-backed teardown in `docs/evidence/verification/2026-08-16-network-prune-routing.md`.
- Volume prune is now exposed by the native CLI and selected remote contexts, with authorized deletion and Docker response routing verified in `docs/evidence/verification/2026-08-16-volume-prune-routing.md`.
- Image tagging is now exposed by the native CLI and selected remote contexts, using the existing authorized content-addressed tag plan in `docs/evidence/verification/2026-08-16-image-tag-routing.md`.
- Image inspection is now exposed by the native CLI and selected remote contexts, with Docker-compatible metadata output verified in `docs/evidence/verification/2026-08-16-image-inspect-routing.md`.
- [x] Add a repeatable release-readiness gate for host evidence, Docker/CRI/security contracts, and compatibility evidence; cross-target artifacts, checksums/signatures, upgrade/rollback, and reproducible metadata remain open.
- [x] Reconcile README and PRD status claims with evidence; remaining release-gated capabilities now point to the evidence-backed roadmap rather than implying full parity.

## Next

### 5. BuildKit-class image build and distribution

*Why next:* Dockerfile/build support works for common cases but is explicitly
below full parity; secure cache and multi-platform workflows are adoption gaps.
*Size:* XL. *Sources:* IMG-06, COMPAT-06, Docker competitive-gap sequence.

- [ ] Model builds as a content-addressed dependency graph with parallel independent stages. Dockerfile preparation now validates named/numeric `COPY --from` edges, rejects forward or unknown stage references, exposes deterministic dependency lists and topological execution batches, and binds that graph into the authorization plan digest; independent stages, including `RUN` stages with isolated stage-scoped caches, now execute concurrently before dependent stages (`docs/evidence/verification/2026-08-16-build-stage-parallelism.md`).
- [ ] Add deterministic cache keys, cache import/export, remote/registry cache, pruning, and cache provenance; local cache entries now persist their key/timestamp plus context/Dockerfile/base-image provenance, reject unbound, conflicting, or malformed imported artifact metadata, re-hash layer/config artifacts and check layer size before cache-hit reuse, are published with unique create-new temporary files plus file/directory sync, prune deterministically with cache-key tie-breaking, and support validated atomic file import/export via `--cache-from`/`--cache-to` with portable layer/config artifact sidecars (`docs/evidence/verification/2026-08-16-build-cache-portability.md`); explicit `registry://` cache export/import now uses OCI manifests and authenticated blob transport (`docs/evidence/verification/2026-08-16-build-cache-registry.md`), while live registry qualification and graph-wide provenance remain open.
- [ ] Add secrets, SSH mounts, multi-platform output, and strict secret non-disclosure in logs/witnesses/cache metadata; Dockerfile secrets now use validated `--secret id=NAME,src=PATH` inputs and temporary 0400 `RUN --mount=type=secret` files, with secret-bearing builds excluded from ordinary cache read/write paths, parser/CLI leakage guards, and fail-closed symlink checks for every rootfs mount-target component. Dockerfile SSH mounts now bind only an absolute, validated host Unix socket into the isolated `RUN` namespace, restore targets on teardown, reject duplicate/traversal targets, and avoid ordinary cache paths; host qualification, multi-platform output, and full nondisclosure qualification remain open. Shell-form cache mounts persist through an isolated per-build cache directory with validated target/ID parsing and fail-closed symlink handling, while named contexts are exposed through `--build-context`, content-bound in the authorized plan/cache key, and path-safe for `COPY --from`.
- [ ] Add build cancellation, resource limits, retries, resumability, and authorization-bound source/context/image identities; Dockerfile `RUN` now supports validated per-command memory/CPU limits plus wall-clock timeout and absolute cancel-marker termination, and the CLI now supports opt-in `FERROCRATE_BUILD_RETRIES` with fresh plan/permit preparation and bounded backoff for transient failures. Per-stage checkpoints now bind cache provenance and reconstruct verified roots after interruption (`docs/evidence/verification/2026-08-16-build-resumability.md`); cache-mount restoration and full identity binding remain open.

### 6. Rootless productization and operational lifecycle

*Why next:* prerequisite diagnostics exist, but installation, service management,
contexts, support boundaries, and upgrades are not yet a complete rootless product.
*Size:* L. *Sources:* rootless verification, README, Docker rootless parity sequence.

- [ ] Ship rootless installer and upgrade flows for subordinate IDs, mapping helpers, cgroup delegation, user services, and slirp networking; `scripts/rootless-install.sh` now provides non-privileged install and explicit `--upgrade` mode with atomic binary/unit replacement, subordinate-ID/cgroup-v2/user-namespace/runtime-dir diagnostics, strict fail-before-mutation gating, dry-run mode, collision checks, systemd-unit path validation, and trust checks rejecting symlinked, non-root-owned, or writable helper binaries, with repeatable coverage in `scripts/test-rootless-install.sh` (the 2026-08-16 regression gate passes); rootless bridge setup now binds the slirp helper to exact PID/start-time rollback cleanup (`docs/evidence/verification/2026-08-16-rootless-slirp-rollback.md`), while helper provisioning and full networking qualification remain open.
- [ ] Add rootless contexts, socket discovery, diagnostics, logs, and explicit unsupported-feature messaging; Linux doctor now reports mapping/socket context, accepts only actual Unix sockets (rejecting regular-file/symlink decoys), and the CLI persists validated named contexts with context inspect availability reporting. Selected remote Unix-socket contexts now route `run`, images, pull/rmi/image-prune, non-interactive exec, push, containers, inspect, logs, non-streaming stats, network/volume listing and inspect, network/volume create and remove, pause, unpause, stop, kill, start, restart, and container remove through the Docker-compatible transport (docs/evidence/verification/2026-08-16-remote-run-routing.md; docs/evidence/verification/2026-08-16-remote-context-routing.md; docs/evidence/verification/2026-08-16-remote-image-routing.md; docs/evidence/verification/2026-08-16-remote-exec-routing.md; docs/evidence/verification/2026-08-16-remote-push-routing.md); other mutating/streaming daemon mappings and full rootless qualification remain open.
- [ ] Qualify rootless CRI, Compose, volumes, networking, image signing, and resource limits; the 2026-08-16 run now passes user namespaces, subordinate-ID helpers, cgroup v2, runtime-dir checks, `slirp4netns`, the real namespace mapping fixture, the temporary-SNAT pull/build/run/cleanup E2E path, and cross-process stop/restart ownership (`docs/evidence/rootless/2026-08-16-run.md`; `docs/evidence/rootless/2026-08-16-e2e-lifecycle.md`; `docs/evidence/verification/2026-08-16-cli-restart.md`), while cross-distribution workload-level networking/CRI/Compose qualification remains open.
- [ ] Add rootless release evidence to CI/manual host gates and document operator recovery; the release gate archives prerequisite diagnostics, and the 2026-08-16 evidence records the explicit missing-helper result, but full rootless qualification remains open.

### 7. Events, logs, and extension contracts

*Why next:* operators and integrations need durable lifecycle events and safe
provider extensions before ecosystem expansion. *Size:* L–XL. *Sources:* Docker
competitive-gap sequence; existing observability and authorization surfaces.

- [ ] Provide a complete durable, filterable event stream distinct from the witness journal; the separate fsynced JSONL stream now projects Docker's core event wire shape with nanosecond timestamps, persisted method/path/status/scope actor attributes, create-response resource IDs, bounded request labels/identity fields, label selectors, nanosecond-precision `since`/`until` bounds (`docs/evidence/verification/2026-08-16-docker-event-time-precision.md`), rejects corrupt journal records and invalid time bounds, avoids fabricating collection-operation names as resource IDs, supports type/action/scope/time/container/image/network/volume resource filters and Docker's JSON `filters` query form, and provides `/events` socket coverage including chunked `follow=1` streaming until client disconnect (`docs/evidence/verification/2026-08-16-docker-event-actor-identity.md`); broader event-attribute parity remains open.
- [x] Define versioned log-driver, volume-driver, network-driver, and plugin contracts with capability declarations; the strict v1 manifest parser validates driver kind, entrypoint safety, allow-listed permissions, bounded resource declarations, and signature metadata, with trust verification and shell-free runtime loading covered by the v1 executor (`docs/compatibility/plugin-contract.md`). Delegated lifecycle receipts and descendant cgroup isolation remain separate open items.
- [ ] Add plugin identity, signature/permission, lifecycle, retry, isolation, and resource limits; v1 now verifies canonical Ed25519 signatures, allow-listed permissions, bounded memory/PID/timeout/output declarations, owner-only trust-root loading, and a shell-free executor applying Unix address-space limits plus timeout/output bounds. The bounded `prlimit` launch no longer performs a redundant per-invocation helper probe, avoiding process-load races while still failing closed if the helper cannot launch (`docs/evidence/verification/2026-08-16-plugin-resource-limit-hardening.md`). Explicit cgroup-v2 execution applies memory/PID ceilings and kills/cleans descendants, and retry APIs now cap attempts at three and retry only transient execution I/O while preserving one delegated lifecycle receipt; host qualification remains open.
- [x] Make every plugin mutation a delegated child of a parent authorization decision with durable intent and cleanup provenance; `PluginDelegation` verifies a signed parent action/resource binding and expiry before launch, while `execute_plugin_delegated` fsyncs intent, effect (output digests only), and cleanup records in an append-only lifecycle journal. Integration callers must still provision the parent authorization signer and journal path.
- [x] Add SDK fixtures and compatibility documentation for extension lifecycle and failure behavior; the canonical v1 log-driver manifest fixture, parser regression, runtime failure table, and timeout/output/entrypoint regression tests pin the contract, while delegated lifecycle receipts remain a separate authorization-integration item.

### 8. Performance, reliability, and scale hard gates

*Why next:* benchmark scripts exist, but optimization, sustained-load, chaos, and
reliability acceptance thresholds are not yet demonstrated. *Size:* L–XL. *Sources:*
PERF-01–08, REL-02, `docs/PROJECT_COMPLETION_PLAN.md`.

- [ ] Establish baselines and enforce thresholds for startup, warm start, pull, build, idle RSS, per-container overhead, binary size, and AI latency; the repeatable collector and strict verifier now cover these metrics plus Docker/OCI/rootless evidence, the 2026-08-16 local run is archived in `docs/evidence/performance/2026-08-16-local.md`, and a rootful ten-feature Docker comparison is archived in `docs/evidence/performance/2026-08-16-docker-comparison.md`; non-skipped cross-host baselines remain open.
- [ ] Optimize image extraction, network setup, memory overhead, and parallel operations against those baselines.
- [ ] Add sustained-load tests (100+ containers), resource exhaustion, daemon crash, OOM, interrupted network, disk-full, and kernel-effect fault matrices; `scripts/reliability-matrix.sh` now passes authorization, witness disk/checkpoint, network, CRI, helper-grant, and dedicated 100-process lifecycle fixtures with dated evidence, while container-scale sustained load, real resource exhaustion, and host-kernel chaos remain open.
- [ ] Verify AI-disabled graceful degradation and ensure AI monitoring overhead stays within the published budget.
- [ ] Add backup/restore, upgrade/downgrade, disaster-recovery, and capacity-planning tests and operator runbooks. Manager SQLite restore now has executable integrity/epoch/credential-rotation tests; `scripts/capacity-plan.sh` provides an atomic, fixtureable CPU/memory/PID/disk planning gate with regression coverage in `scripts/test-capacity-plan.sh`; cross-host failover, retention, capacity alarms, and fault-injection qualification remain open.

### 9. AI runtime completion (practical scope)

*Why next:* ferro-mind has useful local components, but several PRD claims remain
partial, disconnected, or placeholder-backed. *Size:* XL. *Sources:* AI-01–06,
AI-08/09/11/12; `docs/RVF_INTEGRATION_PLAN.md`.

- [ ] Wire anomaly detection, adaptive restart, and resource prediction outcomes into the runtime lifecycle with durable per-container persistence. Anomaly, predictive-OOM, adaptive-restart, and shared eBPF kernel-reconciliation outcomes now use a shared durable JSONL logger under the configured runtime directory by default (or `FERROCRATE_AI_AUDIT_LOG`), serialize concurrent container appenders under process and OS file locks, and sync the parent directory after each record; successful adaptive restarts emit `ai_restart_applied` receipts with delay/PID evidence, bounded `ai_restart_failed` receipts record command-build, spawn, PID-state, and ownership-release failures, stale-PID recovery emits `ai_reconciliation_applied`, and shared network verify/reload outcomes emit `ai_kernel_reconciliation` records with network and container-count evidence; adaptive restart honors an AI `DoNotRestart` decision and is disabled by `FERROCRATE_AI=0`, while broader kernel-effect reconciliation persistence remains open.
- [x] Remove the placeholder WASM inference success path: the legacy `noop` engine now fails closed with an explicit unsupported-mode error; the validated `linear` engine remains available, while a true sandboxed WASM runtime remains out of scope until separately adopted.
- [ ] Implement real model/version routing, training-data collection, online-learning safeguards, and rollback gates. The training pipeline now atomically publishes model artifacts and version metadata and fails closed on duplicate/ambiguous versions or missing active artifacts; newly trained/imported artifacts are digest-bound and resolved through a fail-closed active-model router (`docs/evidence/verification/2026-08-16-ai-model-routing.md`); collection now validates model-specific samples, bounds size, deduplicates by digest, atomically publishes them (`docs/evidence/verification/2026-08-16-ai-training-data.md`), requires explicit opt-in consent before mutation (`docs/evidence/verification/2026-08-16-ai-consent.md`), and supports validated deletion, deterministic bounded pruning, explicit-cutoff age pruning, and payload-free fsynced deletion receipts (`docs/evidence/verification/2026-08-16-ai-retention.md`, `docs/evidence/verification/2026-08-16-ai-time-retention.md`, `docs/evidence/verification/2026-08-16-ai-deletion-receipts.md`); candidate activation now rejects configurable loss regression and preserves the prior active version (`docs/evidence/verification/2026-08-16-ai-rollback-gate.md`); runtime lifecycle routing, signed remote provenance/anchoring, remote erasure coordination, human approval, and full online-learning policy remain open.
- [ ] Populate explainability traces with decision inputs, model/version, confidence, and resulting action; anomaly, predictive-OOM, and adaptive-restart traces now persist structured model/version, bounded evidence, and confidence (anomaly margin or restart success estimate), while broader AI behavior coverage remains open.
- [x] Replace brute-force vector paths where scale requires it; cosine search uses the HNSW-backed `ruvector-core` index, bounded-window Euclidean/Manhattan paths remain deliberately brute-force, and the persistent backend parity workload covers 1,200 inserts and 4,000 queries (`cargo test -p ferro-mind backend_parity_workload`).
- [x] Implement truthful GPU/VRAM discovery and scheduling: `ai gpu` reports `nvidia-smi` discovery failures explicitly, emits JSON/text inventory, and selects a candidate only when requested free VRAM is available; non-NVIDIA/absent-GPU hosts remain an explicit no-capability result.
- [ ] Add end-to-end AI behavior tests and an AI overhead benchmark; keep `FERROCRATE_AI=0` fully functional. The lifecycle gates monitor startup on explicit AI enablement and a non-zero memory limit, and `ferro-mind/examples/ai_overhead.rs` plus `scripts/perf/ai-overhead.sh` now provide a bounded monitor-sample SLO with local evidence in `docs/evidence/performance/2026-08-16-local.md`; multi-container lifecycle behavior and cross-host overhead evidence remain open.

## Later

### 10. RVF integration and native cognitive images

*Why later:* these are strategic differentiators and do not block the current
container/runtime release. *Size:* XXL. *Source:* `docs/RVF_INTEGRATION_PLAN.md`.

- [ ] Upgrade and consolidate RVF dependencies and remove thin wrappers only after compatibility review.
- [ ] Decide whether replacing core CAS/signing primitives is worth the migration risk; if yes, implement versioned migration and rollback.
- [ ] Add quantization and compression with measured size/accuracy gates; the RVF scalar quantizer now reports measured original/encoded bytes, compression ratio, and maximum reconstruction error with dimension validation and regression gates, RVF publication rejects duplicate/oversized segments and atomically publishes output, and the persistent RVF vector store now exposes compression-aware creation with reopen/query coverage, while broader store-format and accuracy policy integration remains open.
- [ ] Define and implement an opt-in `.rvf` image manifest, build format, launcher, and OCI interoperability. The versioned manifest/build format is implemented, and `ferro-core::rvf_image::read_rvf_image` plus atomic `extract_layer` now provide a digest- and size-validated OCI layer handoff; `ferrocrate rvf import` validates platform/digest, publishes layer/config blobs atomically, and writes an authorization-bound OCI reference, while `run IMAGE.rvf` now imports that reference before using the normal OCI runtime path (`docs/evidence/verification/2026-08-16-rvf-import.md`); native launcher/QEMU execution remains open.
- [ ] Add optional cognitive-container policy: authority-to-seccomp mapping, token budgets, metered model proxy, and coherence pre-run gates.

### 11. Multi-host orchestration

*Why later:* orchestration depends on qualified networking, CRI, events, plugins,
and durable cluster-state semantics. *Size:* XXL. *Source:* Docker competitive-gap
sequence and FCNET-105 decisions.

- [ ] Choose a narrow secure controller model versus Swarm-compatible services.
- [ ] Implement node identity/lifecycle, desired state, scheduling, placement constraints, service discovery, health reconciliation, and rolling updates.
- [ ] Bind every reconciliation mutation to revision floors, delegated authority, durable intent, outcomes, and replay-safe recovery.
- [ ] Qualify independent-machine network paths only when the operational decision reopens ADR-0013.

### 12. Off-host witness transparency and portable delegation

*Why later:* ADR-0014 deliberately defers this beyond the current v1 local signed
checkpoint model. *Size:* XL. *Source:* ADR-0014 and witness foundation plan.

- [ ] Add independently replicated/off-host checkpoint retention and export. `ferrocrate witness export` now emits a bounded, canonical-record JSON snapshot from the read-only witness mirror with journal identity, sequence/epoch, per-record hashes, and atomic publication (`docs/security/witness-export.md`); independent remote replication, scheduling, and verifier-fleet operation remain open.
- [ ] Add Merkle inclusion/consistency proofs and external verifier tooling. Domain-separated, bounded Merkle roots, self-contained inclusion proofs, append-only consistency proofs, and Linux CLI root/proof verification over canonical witness record hashes are now available; compact frontier proofs and off-host publication remain open.
- [ ] Add attenuated, revocable delegated credentials within the existing action/resource vocabulary.
- [ ] Define key compromise, revocation, verifier-fleet rollout, and continuity procedures.

### 13. macOS, Windows, and desktop distribution

*Why later:* host-native support requires VM/WSL layers, packaging, file sharing,
networking, and release operations that are separate from the Linux runtime.
*Size:* XXL. *Source:* `docs/macos-windows-support-plan.md`.

- [ ] Deliver first-class Windows WSL2 host proxy and VM runtime image.
- [ ] Deliver macOS VM runtime, file sharing, networking, and lifecycle integration.
- [ ] Deliver Windows Hyper-V integration where WSL2 is insufficient.
- [ ] Complete desktop packaging, signing, paid/free channel behavior, upgrade, diagnostics, and cross-platform tests.

### 14. Commercial entitlements and paid distribution

*Why later:* monetization infrastructure exists but still has Phase 3 operational
work and must not weaken the local authorization boundary. *Size:* L–XL.
*Source:* `docs/monetization-implementation-plan.md`.

- [ ] Complete entitlement issuance/rotation/revocation and offline/grace-period policy.
- [ ] Harden gateway authentication, webhook/replay handling, audit events, and customer isolation.
- [ ] Integrate entitlement checks with paid artifact channels, desktop installers, and upgrade rollback.
- [ ] Add billing/entitlement failure tests that preserve free-tier operation and fail closed only for paid features.

### 15. Documentation, release, and ecosystem completion

*Why later:* documentation should follow stable behavior, but the final release
corpus is a real deliverable rather than an implicit cleanup task. *Size:* L.
*Sources:* legacy roadmap Phase 7, README, release scripts.

- [ ] Publish production deployment, high-availability, backup/DR, monitoring, alerting, capacity, security, troubleshooting, FAQ, and glossary guides. Backup/DR and capacity planning are documented in `docs/operations/disaster-recovery.md`; Compose migration report operation is documented in `docs/operations/docker-migration.md`, while HA, alerting, and full migration execution guides remain open.
- [ ] Publish CLI, Docker API, Compose, CRI, networking, rootless, plugin, and migration references; `docs/compatibility/reference-index.md` now provides a single status-aware index to the current contracts and evidence, while the individual reference guides and remaining parity gates stay open.
- [ ] Automate semantic versioning, changelog/release notes, signed artifacts, package repositories, and upgrade guides; channel packaging now rejects non-semver release tags before mutation, the tag-triggered workflow invokes the verified builder, channel verifier, and atomic grouped changelog generator, the verifier now requires an archive-bound provenance manifest and supports an explicit `--require-signatures` detached-GPG gate; the workspace warning-free quality gate also passes `cargo check`, Clippy with `-D warnings`, and all-target tests (`docs/evidence/verification/2026-08-16-quality-gates.md`); signing-key provisioning, publication repositories, and upgrade automation remain open.
- [ ] Add ecosystem examples, compatibility fixtures, support policy, and a public evidence index for every advertised platform; `docs/evidence/README.md` now indexes the dated workspace, host-matrix, performance, rootless, and MAC-policy evidence, while ecosystem examples, support policy, and full platform coverage remain open.

## Explicitly deferred decisions (not silently missing)

- Physical multi-host FCNET-105 is not a current release gate; reopen only through ADR-0013.
- Off-host witness retention, Merkle transparency, and portable credentials are not v1 requirements; reopen through ADR-0014.
- Swarm cloning, desktop marketplace work, and blind endpoint counting remain lower priority until their prerequisite contracts are stable.
- Any item marked “Done” in historical records is not repeated as forward work unless its evidence is explicitly marked partial or rework-needed above.

## Shipped history

- [x] FCNET-101 durable named-network lifecycle — completed 2026-08-16.
- [x] FCNET-102 authorized CLI/Docker network mediation — completed 2026-08-16.
- [x] FCNET-103 privileged single-host bridge qualification — completed 2026-08-16.
- [x] FCNET-104 IPv6 named-network lifecycle — completed 2026-08-16.
- [x] FCNET-105 authenticated isolated-host managed-overlay qualification — completed 2026-08-16.
- [x] Shared capability-aware network execution boundary, exact read-back, rollback, DNS/hosts atomic publication, veth MTU, firewall/tc verification, and executor-backed cleanup.
- [x] Host-matrix preflight/evidence gate and first Ubuntu 26.04/kernel 7.0 evidence bundle.
- [x] Seccomp application in the launch `pre_exec` path and rootless prerequisite diagnostics.
- [x] Durable authorized CRI sandbox/container lifecycle RPCs plus lifecycle conformance fixture.
- [x] Docker API compatibility declaration and Docker-wire/Compose authorization contract coverage.
- [x] Performance baseline harness, physical-host decision ADR, and off-host witness deferral ADR.

## Update log

- 2026-08-16 `7f36ac6` — consolidated all remaining work from the active roadmap, PRD-backed partials, security audit, RVF plan, platform plan, monetization plan, and compatibility contracts into this single Now/Next/Later backlog.
- 2026-08-16 — added a six-row host qualification manifest with candidate/qualified/blocked status semantics and a CI-validating manifest gate; only the existing Ubuntu row remains qualified.
- 2026-08-16 `9858e5f` — added a reproducible ten-feature Docker/Ferrocrate benchmark harness and archived rootful Ubuntu median timings.
- 2026-08-16 — fixed executable capability detection for strict MAC tooling and qualified a self-contained AppArmor profile load/workload launch; SELinux and denial/rollback evidence remain open.
- 2026-08-16 — wired the existing unprivileged namespace path to opt-in `slirp4netns` bridge networking, fixed rootless teardown classification, and archived pull/run/remove evidence; rootless port forwarding and broader row qualification remain open.
- 2026-08-16 — corrected rootless bridge launch to create user and network namespaces together without invoking setuid mapping helpers after `no_new_privs`; long-lived workload retention now passes locally, while live network traffic evidence remains open.
- 2026-08-16 — added explicit opt-in slirp4netns IPv6 command support with unit coverage; live IPv6 traffic remains unclaimed.
