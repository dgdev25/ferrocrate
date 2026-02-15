# macOS Claude Execution Runbook (FerroCrate)

## Purpose
Run a full real-world macOS validation pass for FerroCrate, capture all findings, and push structured results to the macOS support feature branch so maintainers can pull and fix quickly.

## Target Branch
- Primary target: `feature/macos-support`
- If branch does not exist remotely, create it from latest `origin/main` and push.

## Hard Requirements
- Test on real macOS host (Apple Silicon and/or Intel).
- Execute both CLI and desktop VM paths.
- Capture command output, failures, timings, and environment details.
- Save all reports under `docs/testing/macos/`.
- Commit and push only result/report artifacts (no unrelated code changes unless explicitly fixing a bug in this run).

## Preflight

### 1. Repository and branch setup
```bash
git fetch --all --prune
git checkout feature/macos-support || git checkout -b feature/macos-support origin/main
git pull --ff-only origin feature/macos-support || true
```

### 2. System metadata capture
```bash
mkdir -p docs/testing/macos
{
  echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "macos_version=$(sw_vers -productVersion)"
  echo "macos_build=$(sw_vers -buildVersion)"
  echo "cpu_arch=$(uname -m)"
  echo "kernel=$(uname -a)"
  echo "xcode_cli=$(xcode-select -p 2>/dev/null || echo missing)"
  echo "rustc=$(rustc --version 2>/dev/null || echo missing)"
  echo "cargo=$(cargo --version 2>/dev/null || echo missing)"
  echo "node=$(node --version 2>/dev/null || echo missing)"
  echo "npm=$(npm --version 2>/dev/null || echo missing)"
} > docs/testing/macos/environment.txt
```

## Test Matrix

## A. Build and warnings gates

### A1. Workspace compile
```bash
cargo check --workspace 2>&1 | tee docs/testing/macos/a1-cargo-check-workspace.log
```

### A2. Workspace tests
```bash
cargo test --workspace 2>&1 | tee docs/testing/macos/a2-cargo-test-workspace.log
```

### A3. No-warnings gate
```bash
scripts/verify-no-warnings.sh 2>&1 | tee docs/testing/macos/a3-no-warnings.log
```

## B. Installer and preflight usability

### B1. Install script dry run / execution
```bash
bash -x scripts/install-macos.sh 2>&1 | tee docs/testing/macos/b1-install-macos.log
```

### B2. Desktop doctor checks
```bash
ferro-desktop doctor 2>&1 | tee docs/testing/macos/b2-desktop-doctor.log || true
ferro-desktop phase0-check --json 2>&1 | tee docs/testing/macos/b2-phase0-check.json || true
```

## C. Desktop VM lifecycle (human flow)

### C1. VM init
```bash
ferro-desktop vm init --backend qemu-hvf --cpus 2 --memory-mb 2048 2>&1 | tee docs/testing/macos/c1-vm-init.log
```

### C2. VM start + status
```bash
ferro-desktop vm start 2>&1 | tee docs/testing/macos/c2-vm-start.log || true
ferro-desktop vm status --json 2>&1 | tee docs/testing/macos/c2-vm-status.json || true
```

### C3. API/forwarding health
```bash
ferro-desktop vm bridge-api --bind-addr 127.0.0.1 --listen-port 4288 2>&1 | tee docs/testing/macos/c3-vm-bridge-api.log || true
```

## D. Core user workflows (as a human would use)

### D1. Image operations
```bash
ferrocrate pull alpine:latest 2>&1 | tee docs/testing/macos/d1-pull.log || true
ferrocrate images 2>&1 | tee docs/testing/macos/d1-images.log || true
```

### D2. Run/ps/logs/stop/rm flow
```bash
ferrocrate run alpine:latest sh -c 'echo hello-from-macos' 2>&1 | tee docs/testing/macos/d2-run.log || true
ferrocrate ps 2>&1 | tee docs/testing/macos/d2-ps.log || true
ferrocrate logs test-container 2>&1 | tee docs/testing/macos/d2-logs.log || true
ferrocrate stop test-container 2>&1 | tee docs/testing/macos/d2-stop.log || true
ferrocrate rm test-container 2>&1 | tee docs/testing/macos/d2-rm.log || true
```

### D3. Compose scenario
```bash
# If sample compose file exists in repo, use it. Otherwise create a minimal temp compose file.
ferrocrate compose up 2>&1 | tee docs/testing/macos/d3-compose-up.log || true
ferrocrate compose ps 2>&1 | tee docs/testing/macos/d3-compose-ps.log || true
ferrocrate compose down 2>&1 | tee docs/testing/macos/d3-compose-down.log || true
```

### D4. AI commands expected on macOS
```bash
ferrocrate ai-stats --model-type anomaly-detector 2>&1 | tee docs/testing/macos/d4-ai-stats.log || true
ferrocrate ai-train --model-type anomaly-detector --data-dir . 2>&1 | tee docs/testing/macos/d4-ai-train.log || true
```

## E. Desktop UI scaffold validation

### E1. Frontend install/build
```bash
cd apps/ferro-desktop-ui
npm install 2>&1 | tee ../../docs/testing/macos/e1-npm-install.log
npm run build 2>&1 | tee ../../docs/testing/macos/e1-npm-build.log
cd ../..
```

### E2. Tauri check (capture missing system libs if any)
```bash
cargo check --manifest-path apps/ferro-desktop-ui/src-tauri/Cargo.toml 2>&1 | tee docs/testing/macos/e2-tauri-check.log || true
```

## F. Negative and recovery tests

### F1. VM stopped command behavior
```bash
ferro-desktop vm stop 2>&1 | tee docs/testing/macos/f1-vm-stop.log || true
ferrocrate run alpine:latest echo should-fail-or-autorecover 2>&1 | tee docs/testing/macos/f1-run-when-stopped.log || true
```

### F2. Missing dependency simulation (if safe)
- Temporarily simulate missing `ferro-desktop` in PATH and verify error quality.
- Record exact error category/hint and whether guidance is actionable.

## Findings Report Format
Create the following file:
- `docs/testing/macos/MACOS_CLAUDE_FINDINGS.md`

Use this structure exactly:

```md
# macOS Claude Findings

## Execution Summary
- Date:
- Branch tested:
- Host details:
- Overall result: PASS / PARTIAL / FAIL

## Critical Issues
- [ID] Title
  - Severity: Critical
  - Area: CLI / Desktop VM / UI / Install / Docs
  - Repro steps:
  - Actual result:
  - Expected result:
  - Evidence: log file path(s)
  - Suspected root cause:
  - Suggested fix:

## High Issues
(same format)

## Medium Issues
(same format)

## Low Issues
(same format)

## Compatibility Verdict
- What works reliably now
- What is flaky
- What is blocked

## Recommended Next Actions
1. ...
2. ...
3. ...
```

## Artifacts Index
Also generate:
- `docs/testing/macos/ARTIFACT_INDEX.md`

Include every produced log/report with one-line purpose description.

## Commit and Push Procedure

### 1. Validate changed files
```bash
git status --short
```
Expected changed files should be only under:
- `docs/testing/macos/`

### 2. Commit results
```bash
git add docs/testing/macos/
git commit -m "test(macos): add Claude execution logs and findings report"
```

### 3. Push to branch
```bash
git push origin feature/macos-support
```

## Final Handoff Message (for maintainer)
Post this in the PR/issue/comment:

- Branch: `feature/macos-support`
- Commit: `<commit-sha>`
- Summary: `<pass/fail + issue counts by severity>`
- Top 3 blockers: `<IDs>`
- Reports:
  - `docs/testing/macos/MACOS_CLAUDE_FINDINGS.md`
  - `docs/testing/macos/ARTIFACT_INDEX.md`

## Notes for Claude
- Do not silently skip failed steps; record each as pass/fail with evidence.
- If a command is expected to fail on macOS by design, classify as "Expected Limitation" not bug.
- Distinguish host-kernel limitations from bridge-path bugs.
