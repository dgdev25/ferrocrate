# FerroCrate 100% Completion Plan

Date: 2026-02-15  
Scope: Complete remaining work from current roadmap state to production-ready v1.0

## 1. Definition of 100%

Project is considered 100% complete when all of the following are true:

1. Every roadmap requirement is either:
- `Done` with no `Rework Needed`, or
- explicitly descoped in a signed ADR and removed from v1.0 scope.

2. API/runtime compatibility is production-grade:
- Docker compatibility contract meets defined v1.45 target coverage.
- CRI compatibility supports required Kubernetes runtime flows (not image-only).
- OCI image/runtime/distribution conformance passes formal suites, not smoke scripts.

3. Security controls are enforced, not declarative:
- Seccomp actually applied.
- MAC policy behavior verified.
- eBPF monitoring path real (or hard-disabled with explicit policy fallback).

4. Performance SLOs are met and enforced in CI:
- Startup, pull, idle RSS, per-container overhead, build throughput, binary size, AI latency.

5. Reliability + observability are production-complete:
- crash resilience, graceful degradation, atomicity, coverage gate, OTEL traces, decision audit.

6. Documentation and release artifacts are complete:
- operator guide, developer guide, migration docs, compatibility matrix, runbooks, release notes.

## 2. Baseline (Current State)

Completed recently:
- API close-the-gaps list (15/15) completed.
- Docker compat routing/tests/CI gate implemented.
- CRI image operations implemented (`ListImages`, `ImageStatus`, `PullImage`, `RemoveImage`).
- RVF regression reduced to low single digits and benchmark gate passing.

Remaining roadmap debt (from `docs/ROADMAP.md`):
- `Partial`: NET-01/04/05/06/07/08/09/10, SEC-02/08/09, AI-01/02/03/04/05/06/08/09/11/12, PERF-01..08, COMPAT-09.
- `Done` but `Rework Needed`: IMG-06, SEC-03, COMPAT-01/02/03/04/06, REL-01/02/04/05, OBS-02/05.

## 3. Execution Strategy

Use 6 execution tracks in parallel with one integration lane:

1. Runtime + Networking
2. Security Hardening
3. Compatibility + CRI
4. AI Stack Completion
5. Performance + Reliability
6. Docs + Release Engineering
7. Integration lane (cross-track test gates every milestone)

Planning principle:
- Build missing execution paths first.
- Then enforce correctness/security.
- Then optimize.
- Then lock contracts and docs.

## 4. Milestones and Work Packages

## Milestone A: Runtime/Network Execution Completion (Weeks 1-3)

Goal:
- Replace remaining networking command-builder stubs with real execution plumbing and deterministic error handling.

Packages:
1. NET-01/05/08 execution layer
- Implement command execution adapters in `ferro-net` (bridge/iptables/nftables).
- Remove split behavior where runtime shells out independently.
- Add integration tests per backend mode.

2. NET-04 DNS behavior
- Replace partial `/etc/hosts`-only approach with deterministic DNS config per network mode.
- Add compose multi-service name resolution tests.

3. NET-06 fallback correctness
- eBPF-to-iptables fallback must emit explicit warning/metrics, never silent downgrade.

4. NET-07 encrypted networking
- Implement real WireGuard setup path or formally descope from v1.0 in ADR.

5. NET-09/10 IPv6 + bandwidth limiting
- Make allocation and tc application executable and tested.

Done criteria:
- No network module left as command-only stub for supported v1.0 features.
- Integration tests pass in CI for bridge/host/none/encrypted modes.

## Milestone B: Security Enforcement (Weeks 2-4, overlaps A)

Goal:
- Convert security declarations into enforced runtime controls.

Packages:
1. SEC-02 seccomp enforcement
- Wire seccomp profile application into container start path.
- Add syscall-deny behavioral tests.

2. SEC-03 MAC rework
- Formalize AppArmor/SELinux policy loading modes.
- Add policy test matrix by distro capability.

3. SEC-08 runtime monitoring
- Implement real eBPF monitor path or explicitly gate with feature flags and documented fallback.

4. SEC-09 encrypted communication completion
- Finalize with NET-07 implementation tests.

Done criteria:
- Security features fail closed where required.
- Security CI suite includes enforcement tests, not parse-only tests.

## Milestone C: Compatibility and CRI Productionization (Weeks 3-6)

Goal:
- Reach production-usable OCI, Docker, and CRI compatibility level.

Packages:
1. COMPAT-01/02/03 formal conformance
- Integrate OCI conformance suites in CI (image/runtime/distribution).
- Publish pass/fail report artifact per run.

2. COMPAT-04 Docker API expansion
- Fill high-value endpoint gaps beyond current matrix.
- Expand compatibility matrix test coverage to all supported endpoints.

3. COMPAT-06 + IMG-06 Dockerfile parity rework
- Prioritize unsupported but high-frequency directives/edge cases.
- Add fixture-based Dockerfile parity corpus.

4. COMPAT-09 CRI expansion
- Implement core pod/container runtime RPCs:
  - `RunPodSandbox`, `StopPodSandbox`, `RemovePodSandbox`
  - `CreateContainer`, `StartContainer`, `StopContainer`, `RemoveContainer`
  - `ExecSync` (+ minimum required status/list flows)
- Add kubelet-style integration tests over UDS.

Done criteria:
- CRI no longer image/runtime-subset only.
- OCI/Docker/CRI compatibility matrix published and CI-gated.

## Milestone D: AI Stack Completion (Weeks 5-8)

Goal:
- Move AI from scaffolding to functional, measurable behavior.

Packages:
1. AI-01 WASM inference
- Replace no-op engine with real inference backend.

2. AI-02/03/06 predictive + anomaly + restart intelligence
- Implement learned models and online update pipeline.
- Add calibration/accuracy metrics.

3. AI-04 routing and AI-11 explainability
- Implement decision scoring with trace payloads.

4. AI-05 integration wiring
- Wire currently copied/scaffolded components into runtime decision paths.

5. AI-12 GPU/VRAM scheduling
- Implement actual device discovery and scheduling decisions.

6. AI-08/09 memory/learning completeness
- Ensure high-performance vector retrieval paths are used consistently and learning loop is real.

Done criteria:
- AI decisions are functional, explainable, benchmarked.
- AI-off mode remains deterministic and fully supported.

## Milestone E: Performance + Reliability Hard Gates (Weeks 7-9)

Goal:
- Convert measurements into enforceable SLO compliance.

Packages:
1. PERF-01..08 SLO implementation
- Define target thresholds per metric.
- Add regression gates with historical baseline tracking.

2. REL-01 runtime crash resilience
- Implement proper daemon/supervisor lifecycle to keep containers alive across daemon failure.

3. REL-02 graceful degradation
- Fault-injection tests for AI/backend/network component failures.

4. REL-04 atomicity hardening
- Audit all state transitions and write paths for atomic guarantees.

5. REL-05 coverage gate
- Enforce minimum line/branch + critical-path coverage thresholds.

Done criteria:
- All SLO gates green in CI for 2 consecutive release candidates.

## Milestone F: Observability + Release Readiness (Weeks 9-10)

Goal:
- Production operational readiness and final docs.

Packages:
1. OBS-02 OTEL rework
- Ensure trace spans cover request lifecycle and container lifecycle critical paths.

2. OBS-05 decision audit rework
- Ensure AI decision logs are complete, queryable, and privacy-safe.

3. Documentation finalization
- Operator runbook, incident response, migration guide, API/CRI compatibility tables, tuning guide.

4. Release process
- RC checklist, signed artifacts, changelog generation, rollback playbook.

Done criteria:
- v1.0 release checklist fully green.

## 5. CI/CD Gate Matrix (Must Be Green)

1. Build/Test
- `cargo test --workspace`
- API contract tests (Docker + CRI socket integration)
- conformance suites (OCI/Docker/CRI)

2. Security
- seccomp/mac enforcement tests
- static scan + dependency audit
- privileged-path tests (rootless/rootful)

3. Performance
- startup/pull/rss/build/AI latency gates
- RVF regression gate

4. Reliability
- crash-recovery tests
- fault-injection tests
- long-running soak test

5. Docs/Contracts
- compatibility matrix freshness check
- docs lint and link checks

## 6. Ownership Model

Assign one owner per track:
- Runtime/Network owner
- Security owner
- Compatibility/CRI owner
- AI owner
- Perf/Reliability owner
- DX/Docs owner
- Release manager (integration lane)

Each owner must maintain:
- weekly burndown
- open risk register
- test debt ledger

## 7. Risk Register and Mitigations

1. CRI scope explosion
- Mitigation: prioritize kubelet-critical RPC set first, defer advanced flows via ADR.

2. AI quality instability
- Mitigation: keep deterministic fallback path and ship with calibrated confidence gating.

3. Networking portability drift
- Mitigation: backend abstraction + per-distro CI lanes.

4. Security regression risk
- Mitigation: fail-closed defaults, enforcement tests mandatory before merge.

5. Performance regressions during feature completion
- Mitigation: benchmark gates on every PR to protected branches.

## 8. 10-Week Suggested Timeline

1. Weeks 1-3: Milestone A
2. Weeks 2-4: Milestone B
3. Weeks 3-6: Milestone C
4. Weeks 5-8: Milestone D
5. Weeks 7-9: Milestone E
6. Weeks 9-10: Milestone F + RCs

## 9. Immediate Next 14-Day Sprint (Recommended)

1. Implement `ferro-net` execution layer and remove command-only stubs for bridge/iptables/nftables paths.
2. Implement seccomp enforcement in runtime start path and add behavioral tests.
3. Expand CRI with `RunPodSandbox/CreateContainer/StartContainer` first vertical slice.
4. Establish OCI conformance job in CI with artifacted report.
5. Lock performance SLO targets and encode gates for PERF-01/02/03/04 first.

## 10. Completion Checklist (v1.0 Sign-off)

1. No roadmap item remains `Partial` or `Rework Needed` for v1.0 scope.
2. Compatibility matrix shows target coverage and is CI-verified.
3. Security controls are enforced and tested.
4. Performance/reliability SLO gates stable for 2 RC cycles.
5. Operator/developer/migration docs complete and reviewed.
6. Release artifacts signed, reproducible, and rollback-tested.

