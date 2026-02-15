# Security Audit Task List (PAL MCP + Local Validation)

Date: 2026-02-15
Scope: Entire workspace (`ferro-cli`, `ferro-core`, `ferro-cri`, `ferro-net`, `ferro-mind`)
Models requested: Gemini Pro 3, o3-mini, Grok (OpenRouter via PAL)

## Model Run Notes
- `openai/o3-mini`: completed with findings.
- `google/gemini-3-pro-preview`: PAL continuation step timed out at tool 60s deadline.
- `x-ai/grok-4.1-fast`: PAL continuation step timed out at tool 60s deadline.

## Critical

### SEC-CRIT-01: Rootfs isolation fallback to host execution
Status: Completed
Severity source: Local audit (confirmed pre-existing)

Tasks:
- [x] ~~Block non-root rootfs execution when `bwrap` is unavailable~~
- [x] ~~Return explicit error instead of unsafe host fallback~~
- [x] ~~Re-run workspace tests after behavior change~~

Evidence:
- `ferro-core/src/runtime.rs:1147`
- `ferro-core/src/runtime.rs:1148`

## High

### SEC-HIGH-01: Rootfs layer extraction symlink traversal / unsafe deletion risk
Status: Completed
Severity source: Local audit (confirmed pre-existing)

Tasks:
- [x] ~~Add parent-component symlink checks before unpack/create~~
- [x] ~~Use `symlink_metadata` for delete paths to avoid following symlinks~~
- [x] ~~Keep whiteout handling intact with safe deletion behavior~~

Evidence:
- `ferro-core/src/rootfs.rs:76`
- `ferro-core/src/rootfs.rs:82`
- `ferro-core/src/rootfs.rs:203`
- `ferro-core/src/rootfs.rs:215`

### SEC-HIGH-02: Daemon socket clobbering / weak socket mode
Status: Completed
Severity source: Local audit (confirmed pre-existing)

Tasks:
- [x] ~~Refuse to unlink pre-existing path unless it is a unix socket~~
- [x] ~~Set explicit socket mode to `0660` after bind~~
- [x] ~~Verify daemon still starts and route tests pass~~

Evidence:
- `ferro-cli/src/main.rs:3051`
- `ferro-cli/src/main.rs:3052`
- `ferro-cli/src/main.rs:3062`

### SEC-HIGH-03: CRI/socket integration coverage
Status: Already implemented (validated)
Severity source: PAL o3-mini output (re-validated as stale)

Tasks:
- [x] ~~Confirm CRI socket integration tests exist and execute~~
- [x] ~~Validate runtime + image service RPC request/response paths~~

Evidence:
- `ferro-cri/tests/socket_integration.rs:1`

## Medium

### SEC-MED-01: Seccomp semantic validation gap
Status: Already implemented (validated)
Severity source: PAL o3-mini output (re-validated as stale)

Tasks:
- [x] ~~Confirm semantic validation exists on profile parse path~~
- [x] ~~Ensure parse rejects unknown actions/architectures and contradictory rules~~

Evidence:
- `ferro-core/src/seccomp.rs:29`
- `ferro-core/src/seccomp.rs:103`

### SEC-MED-02: Build RUN isolation hardening completeness
Status: Already implemented (validated)
Severity source: PAL o3-mini output (re-validated as mostly stale)

Tasks:
- [x] ~~Confirm RUN execution uses child `pre_exec` isolation flow~~
- [x] ~~Confirm namespace setup, user namespace mapping, identity drop, capability drop, seccomp application~~
- [x] ~~Track future enhancement for replacing `chroot` with `pivot_root` (hardening backlog)~~

Evidence:
- `ferro-core/src/dockerfile_build.rs:1160`
- `ferro-core/src/dockerfile_build.rs:1195`
- `ferro-core/src/dockerfile_build.rs:1243`

## Low

### SEC-LOW-01: PATH-dependent test flakiness (security pipeline stability risk)
Status: Completed
Severity source: Local audit during remediation run

Tasks:
- [x] ~~Make process lifecycle tests use deterministic shell path~~
- [x] ~~Harden command discovery fallback for restricted PATH environments~~
- [x] ~~Re-run failing tests and full workspace suite~~

Evidence:
- `ferro-core/src/process_lifecycle.rs:179`
- `ferro-core/src/image_security.rs:122`

### SEC-LOW-02: Dependency advisories (unmaintained crates)
Status: Partially completed
Severity source: `cargo audit`

Tasks:
- [x] ~~Remove `tokenizers`/`tract` optional ONNX chain to eliminate `number_prefix`/`paste` advisories~~
- [x] ~~Disable `ruv-fann` binary/default feature path to eliminate `bincode` v1 advisory~~
- [x] ~~Upgrade `ruvector-core` from `2.0.2` to `2.0.3`~~
- [ ] Replace or isolate remaining `ruvector-core` dependency path still pulling `bincode` v2 advisory (`RUSTSEC-2025-0141`)
- [ ] Replace `sled` dependency chain pulling `fxhash` and `instant` advisories
- [x] ~~Add temporary risk-acceptance entry with owner + expiry for unresolved advisory items~~

Evidence:
- `ferro-mind/Cargo.toml`
- `ferro-mind/src/ruv/embeddings.rs`
- `ferro-mind/tests/embeddings_tests.rs`
- `docs/SECURITY_RISK_ACCEPTANCE.md`
- `cargo audit` output (2026-02-15, latest): `RUSTSEC-2025-0141` (bincode v2 via `ruvector-core`), `RUSTSEC-2025-0057` (fxhash via `sled`), `RUSTSEC-2024-0384` (instant via `sled`)

## Operational Follow-up

### SEC-OPS-01: Complete PAL parity runs for requested model set
Status: Open

Tasks:
- [ ] Re-run PAL `secaudit` continuation for Gemini when PAL timeout window permits
- [ ] Re-run PAL `secaudit` continuation for Grok when PAL timeout window permits
- [ ] Merge/triage any net-new findings into this file with severity tags

## Verification Checklist
- [x] ~~`cargo clippy --workspace --all-targets -- -D warnings`~~
- [x] ~~`cargo test --workspace`~~
- [x] ~~Targeted regressions re-tested for prior failures~~
