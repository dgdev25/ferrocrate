# Task Index: Path to 100%

Last updated: 2026-02-15  
Source: `docs/ROADMAP.md` remaining `Partial` + `Done/Rework Needed` items

## How to use this file

- Open task format:
  - `- [ ] ID - Task name`
- In-progress task format:
  - `- [ ] ID - Task name (IN PROGRESS)`
- Completed task format:
  - `- [x] ~~ID - Task name~~`

## Snapshot

- Total remaining tasks: **2**
- Completed tasks: **41**
- Incomplete tasks: **2**

---

## A) Runtime + Networking (8)

- [x] ~~NET-01 - Implement real bridge networking execution path (not command-builder stubs)~~
- [x] ~~NET-04 - Implement deterministic container-to-container DNS behavior beyond `/etc/hosts` fallback~~
- [x] ~~NET-05 - Implement custom network/subnet execution (create/apply lifecycle)~~
- [x] ~~NET-06 - Implement eBPF mode with explicit fallback semantics and visibility~~
- [x] ~~NET-07 - Implement WireGuard overlay networking runtime path~~
- [x] ~~NET-08 - Consolidate and harden real port-mapping execution paths~~
- [x] ~~NET-09 - Complete and verify IPv6 allocation/wiring behavior~~
- [x] ~~NET-10 - Implement enforceable bandwidth limiting path~~

## B) Security Hardening (4)

- [x] ~~SEC-02 - Enforce seccomp profiles at runtime (not parse-only)~~
- [x] ~~SEC-08 - Implement runtime eBPF security monitoring execution path~~
- [x] ~~SEC-09 - Complete encrypted container communication behavior~~
- [x] ~~SEC-03 - Rework AppArmor/SELinux integration to production-ready policy enforcement~~

## C) Compatibility + CRI (7)

- [x] ~~COMPAT-01 - Rework OCI Image Spec v1.1 compliance from smoke-level to full conformance~~
- [x] ~~COMPAT-02 - Rework OCI Runtime Spec v1.2 compliance from smoke-level to full conformance~~
- [x] ~~COMPAT-03 - Rework OCI Distribution Spec v1.1 compliance from smoke-level to full conformance~~
- [x] ~~COMPAT-04 - Rework Docker API v1.45+ parity beyond current subset~~
- [x] ~~COMPAT-06 - Rework Dockerfile syntax compatibility to high-parity target~~
- [x] ~~COMPAT-09 - Expand CRI from partial shim to required Kubernetes runtime surface~~
- [x] ~~IMG-06 - Rework Dockerfile build behavior for full-feature compatibility and stability~~

## D) AI Stack Completion (10)

- [x] ~~AI-01 - Replace no-op WASM inference path with real inference execution~~
- [x] ~~AI-02 - Implement predictive resource allocation using non-trivial learned model~~
- [x] ~~AI-03 - Implement adaptive/intelligent restart decision engine~~
- [x] ~~AI-04 - Implement functional cost-tiered AI routing with quality/cost controls~~
- [x] ~~AI-05 - Wire claude-flow integration from scaffolding to active path~~
- [x] ~~AI-06 - Implement multi-variate anomaly detection beyond static z-score~~
- [x] ~~AI-08 - Complete natural-language management path at scale (non-bruteforce behavior)~~
- [x] ~~AI-09 - Implement real self-learning loop via vector/neural optimization path~~
- [x] ~~AI-11 - Populate explainability artifacts with real decision evidence~~
- [x] ~~AI-12 - Implement real GPU/VRAM-aware scheduling (device discovery + placement)~~

## E) Performance + Reliability (13)

- [x] ~~PERF-01 - Convert startup-time measurement to enforced startup SLO and optimization closure~~
- [x] ~~PERF-02 - Convert pull-throughput measurement to enforced SLO and optimization closure~~
- [x] ~~PERF-03 - Convert idle-memory (no daemon) measurement to enforced SLO and optimization closure~~
- [x] ~~PERF-04 - Convert idle-memory (daemon) measurement to enforced SLO and optimization closure~~
- [x] ~~PERF-05 - Convert per-container overhead measurement to enforced SLO and optimization closure~~
- [x] ~~PERF-06 - Convert build-performance measurement to enforced SLO and optimization closure~~
- [x] ~~PERF-07 - Convert CLI binary size measurement to enforced SLO and optimization closure~~
- [x] ~~PERF-08 - Convert AI latency measurement to enforced SLO and optimization closure~~
- [x] ~~REL-01 - Rework runtime crash resilience to robust container survivability semantics~~
- [x] ~~REL-02 - Rework graceful degradation behavior for AI/component failures~~
- [x] ~~REL-04 - Rework atomic operations audit and close remaining non-atomic paths~~
- [x] ~~REL-05 - Rework test-coverage enforcement to production confidence thresholds~~
- [ ] OBS-02 - Rework OpenTelemetry tracing from optional/basic to production-grade trace coverage

## F) Observability + Audit Rework (1)

- [ ] OBS-05 - Rework AI decision audit log completeness and operational usability

---

## Suggested Execution Order

1. Runtime + Networking
2. Security Hardening
3. Compatibility + CRI
4. AI Stack Completion
5. Performance + Reliability
6. Observability + Release finalization

## Completion Rule

Project reaches 100% when every item in this file is marked:

- `- [x] ~~...~~`
