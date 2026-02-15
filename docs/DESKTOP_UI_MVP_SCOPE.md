# FerroCrate Desktop UI MVP Scope

## Goal
Ship a cross-platform desktop application that gives users a Docker Desktop-like experience for core FerroCrate workflows, without duplicating runtime logic.

## Product Principles
- UI is an orchestrator, not a runtime.
- Reuse `ferro-desktop` and `ferrocrate` command/API contracts.
- Keep Linux/macOS/Windows differences behind backend adapters.
- Prioritize reliability, observability, and clear errors over feature breadth.

## MVP Outcome
A user can install the app, verify runtime health, run/pull/stop/remove containers, inspect logs, and troubleshoot failures from one interface.

## In-Scope (MVP)
- Runtime status dashboard.
- Containers list and lifecycle actions.
- Images list and pull/remove/prune actions.
- "Run Container" quick form.
- Settings for VM/daemon resources and autostart.
- Diagnostics export bundle.

## Out of Scope (Post-MVP)
- Kubernetes cluster management.
- Multi-node orchestration.
- Advanced compose graph editor.
- Extensions marketplace.
- Remote team management/SSO admin console.

## Current System Reuse
- Host bridge/daemon: `ferro-desktop`
- Runtime operations: `ferrocrate` and daemon endpoints
- Visual style guide: `docs/design/mockups/orca_style_guide.html`
- Existing docs/plans:
  - `docs/macos-windows-support-plan.md`
  - `docs/desktop-packaging-guide.md`
  - `docs/DESKTOP_COMPAT_TASKLIST.md`

## Architecture (MVP)
- Desktop shell: Tauri app (`apps/ferro-desktop-ui`).
- Frontend: React + TypeScript.
- Backend commands:
  - invoke local `ferro-desktop` for VM/daemon lifecycle status.
  - invoke `ferrocrate` for container/image operations.
- Data flow:
  - Frontend requests typed backend commands.
  - Backend executes CLI commands and returns structured results.
  - Frontend renders optimistic UI + command output/error traces.

## UX Surface (MVP)
- Overview
  - daemon up/down
  - VM up/down
  - active containers count
- Containers
  - list, run, start/stop/restart/remove
  - logs tail viewer
- Images
  - list, pull, remove, prune
- Settings
  - CPU/RAM/Disk slider values
  - backend type (qemu/hyperv/wsl)
  - autostart toggle
- Diagnostics
  - collect logs
  - include command outputs and environment snapshot

## Delivery Plan

### Phase 0: Contract Stabilization (1-2 days)
- Define desktop UI command contract with request/response envelopes.
- Identify minimum viable commands for overview/containers/images.
- Add compatibility expectations per OS.

### Phase 1: App Skeleton (1-2 days)
- Create Tauri + React project scaffold.
- Implement backend command runner wrappers.
- Add top-level navigation and empty-state UX.

### Phase 2: Runtime and Containers (3-4 days)
- Implement runtime status polling.
- Implement containers table and lifecycle actions.
- Add logs panel for selected container.

### Phase 3: Images and Run Form (2-3 days)
- Implement images table actions.
- Implement "Run Container" drawer/form.
- Input validation and actionable error display.

### Phase 4: Settings and Diagnostics (2-3 days)
- Implement VM/settings panel backed by `ferro-desktop` commands.
- Implement diagnostics bundle export.
- Add first-run onboarding checklist.

### Phase 5: Hardening (3-5 days)
- Failure mode tests and command retry policy.
- Telemetry for command latency and failures.
- Packaging and release candidates on each OS.

## Estimated Effort
- MVP build: 11-19 engineering days.
- Team assumption: 1 engineer full-time.

## Task Backlog (Execution-Ready)

## Epic A: Foundation
- [ ] A1. Create desktop UI app module and dev scripts.
- [ ] A2. Define typed backend command result contract.
- [ ] A3. Add environment detection (linux/macos/windows) in backend.
- [ ] A4. Add shared error model and user-safe messages.

## Epic B: Runtime Health
- [ ] B1. Backend command: daemon status.
- [ ] B2. Backend command: VM status.
- [ ] B3. Frontend overview cards with periodic refresh.
- [ ] B4. Last-successful-check timestamp and stale indicator.

## Epic C: Containers
- [ ] C1. Backend command: list containers.
- [ ] C2. Backend commands: start/stop/restart/remove.
- [ ] C3. Backend command: logs tail.
- [ ] C4. Frontend containers table with action buttons.
- [ ] C5. Frontend logs panel.

## Epic D: Images
- [ ] D1. Backend command: list images.
- [ ] D2. Backend command: pull image.
- [ ] D3. Backend commands: remove/prune images.
- [ ] D4. Frontend images table and pull modal.

## Epic E: Run Experience
- [ ] E1. Backend command: run container with validated args.
- [ ] E2. Frontend run form (image, ports, env, volumes).
- [ ] E3. Real-time command output for run operation.

## Epic F: Settings
- [ ] F1. Backend command: read/write desktop VM config.
- [ ] F2. Frontend settings page for CPU/RAM/Disk.
- [ ] F3. Autostart install/remove actions.

## Epic G: Diagnostics
- [ ] G1. Backend command: collect logs and command snapshots.
- [ ] G2. Bundle diagnostic archive with timestamp.
- [ ] G3. Frontend one-click "Export Diagnostics".

## Epic H: Quality and Release
- [ ] H1. Add command-level integration tests.
- [ ] H2. Add UI smoke tests for overview/containers/images.
- [ ] H3. Add packaging pipeline for desktop UI artifacts.
- [ ] H4. Add release checklist and rollback instructions.

## Acceptance Criteria (MVP)
- User can run and manage a container from UI on Linux, macOS (desktop VM path), and Windows (desktop VM/WSL path).
- Every failed action returns a structured error with next-step guidance.
- Startup diagnostics can be exported without CLI usage.
- No direct runtime logic duplicated in UI backend.

## Risks and Mitigations
- Risk: command output drift from CLI changes.
  - Mitigation: enforce structured output mode and contract tests.
- Risk: platform-specific command edge cases.
  - Mitigation: adapter layer + per-platform integration coverage.
- Risk: user confusion when runtime is unavailable.
  - Mitigation: health-first UX with prescriptive recovery actions.

## Immediate Next Actions
1. Land app scaffold and command bridge (Phase 1).
2. Implement Overview + Containers read-only views.
3. Add lifecycle actions (start/stop/remove) and logs.
