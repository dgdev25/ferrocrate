# macOS Support Extension Task List

## Scope
This plan extends macOS support without rewriting the Linux runtime for XNU. The strategy is to harden the desktop VM bridge path so user experience on macOS is near-parity with Linux.

## Success Criteria
- macOS users can reliably run day-to-day container workflows through the desktop VM path.
- Error handling is actionable (auto-recovery + clear guidance).
- Command and API parity is measured and protected by tests.
- Install/update/rollback paths are production-safe.

## Priority Overview
- **P0 (Now):** remove biggest UX/runtime gaps and parity drift risk.
- **P1 (Next):** reliability and operational hardening.
- **P2 (Later):** polish and advanced workflows.

## P0 Tasks (Immediate)

- [x] **P0-01 Auto-Bridge Command Recovery**
  - Goal: On macOS, auto-start/check VM bridge for runtime commands (`run`, `ps`, `compose`, `logs`, `inspect`) before failing.
  - Code Areas:
    - `ferro-cli/src/main.rs`
    - `ferro-desktop/src/main.rs`
  - Deliverables:
    - preflight check + optional auto-start
    - deterministic retry once bridge is ready
    - actionable error payload if recovery fails
  - Estimate: **8-12h**
  - Status: implemented in `ferro-cli/src/main.rs` (`maybe_host_desktop_forward`, `ensure_macos_vm_running`, runtime-command detection).

- [~] **P0-02 macOS Command Parity Contract Tests**
  - Goal: lock expected behavior for routed commands so parity does not regress.
  - Code Areas:
    - `ferro-cli/tests/*`
    - `tests/macos_compatibility_tests.rs`
  - Deliverables:
    - parity matrix assertions for common flows
    - required response code/message contract checks
  - Estimate: **6-10h**
  - Status: partial; runtime command detection + structured error tests added in `ferro-cli/src/main.rs` unit tests. Additional macOS host integration contracts still pending.

- [ ] **P0-03 Installer + Doctor Preflight Hardening (macOS)**
  - Goal: one-command setup with robust dependency/permission checks.
  - Code Areas:
    - `scripts/install-macos.sh`
    - `ferro-desktop/src/main.rs` (`doctor`, `phase0-check`)
  - Deliverables:
    - checks for QEMU/HVF, launch agent, socket, VM state
    - repair guidance + non-zero exits for hard blockers
  - Estimate: **6-8h**

- [ ] **P0-04 Port Forward Robustness & Conflict Detection**
  - Goal: reduce “works on Linux but not on macOS” network friction.
  - Code Areas:
    - `ferro-desktop/src/main.rs` (forwarding/bridge paths)
  - Deliverables:
    - duplicate/occupied-port detection
    - clearer conflict errors with remediation steps
  - Estimate: **5-8h**

- [x] **P0-05 Structured Error Mapping Across Bridge**
  - Goal: map backend errors to consistent, user-friendly categories.
  - Code Areas:
    - `ferro-cli/src/main.rs`
    - `ferro-desktop/src/main.rs`
  - Deliverables:
    - standardized error envelope (`category`, `hint`, `retryable`)
    - human-readable + machine-readable output modes
  - Estimate: **6-9h**
  - Status: implemented via `structured_desktop_error` + `normalize_cli_error` with text/JSON envelope support.

## P1 Tasks (Reliability Hardening)

- [ ] **P1-01 VM Lifecycle Resilience**
  - Add startup timeout handling, stale PID cleanup, and idempotent stop/start.
  - Estimate: **6-10h**

- [ ] **P1-02 Update Channel Safety Gates**
  - Add pre-switch health checks + auto-rollback on failed update boot.
  - Estimate: **8-12h**

- [ ] **P1-03 Diagnostics Bundle v2**
  - Include bridge logs, vm status, forwarding table, and actionable summary.
  - Estimate: **4-7h**

- [ ] **P1-04 macOS End-to-End Scenario Tests**
  - install -> init vm -> run -> compose -> logs -> cleanup.
  - Estimate: **8-14h**

- [ ] **P1-05 Documentation Alignment Pass**
  - Reconcile `README.md`, `docs/MACOS_LIMITATIONS.md`, `docs/MACOS_UNSUPPORTED_FEATURES.md`.
  - Estimate: **3-5h**

## P2 Tasks (Polish)

- [ ] **P2-01 Performance Profiling of VM Bridge Path**
  - baseline + bottleneck report + targeted fixes.
  - Estimate: **6-10h**

- [ ] **P2-02 macOS Security/Notarization Pipeline Completion**
  - finalize signing/notarization automation and verification checks.
  - Estimate: **8-16h**

- [ ] **P2-03 Advanced Networking UX Helpers**
  - optional pfctl integration helper + richer network diagnostics.
  - Estimate: **6-12h**

## Recommended Execution Order
1. P0-01 Auto-Bridge Command Recovery
2. P0-05 Structured Error Mapping
3. P0-03 Installer + Doctor Hardening
4. P0-04 Port Forward Robustness
5. P0-02 Parity Contract Tests
6. P1-01 VM Lifecycle Resilience
7. P1-04 E2E Scenario Tests
8. P1-02 Update Safety Gates
9. P1-03 Diagnostics Bundle v2
10. P1-05 Documentation Alignment

## Estimated Effort
- **P0 total:** 31-47 hours
- **P1 total:** 29-48 hours
- **P2 total:** 20-38 hours
- **Grand total:** **80-133 hours**

## Definition of Done (per task)
- Code implemented with tests for success and failure paths.
- macOS-specific behavior documented in user-facing docs.
- No warning regressions in touched crates.
- Task is marked complete in this file and `taskindex.md`.

## Immediate Next Step
Start with **P0-01 Auto-Bridge Command Recovery** and implement it behind a clear macOS preflight function in `ferro-cli`.

## Latest Validation Snapshot
- `scripts/verify-no-warnings.sh`: pass
- `cargo test --workspace`: pass
- `scripts/benchmark-rvf-vs-memory.sh`: pass after RVF hot-path optimization
  - RVF median: `99ms`
  - legacy median: `98ms`
  - regression: `1%` (threshold `20%`)
