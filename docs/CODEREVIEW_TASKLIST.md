# Code Review Task List (PAL + Full Clippy Sweep)

Date: 2026-02-15
Scope: Entire workspace (`cargo clippy --workspace --all-targets -- -D warnings` + `cargo test --workspace`)

## Summary
- Reported issues normalized into explicit tasks: 31
- Completed: 31
- Open: 0

## Critical
- [x] ~~CRIT-01 - Harden Dockerfile `RUN` isolation with user-namespace root mapping (`unshare -r`) in `ferro-core/src/dockerfile_build.rs`~~
- [x] ~~CRIT-02 - Complete full build-step sandbox hardening (explicit UID/GID map controls, capability-bounding set, seccomp profile for build subprocess)~~

## High
- [x] ~~HIGH-01 - Harden CLI integration tests to assert stderr semantics (not only exit status) in `ferro-cli/tests/cli_integration.rs`~~
- [x] ~~HIGH-02 - Fix daemon test harness zombie-process risk in `ferro-cli/tests/api_compat_matrix.rs`~~
- [x] ~~HIGH-03 - Fix daemon test harness zombie-process risk in `ferro-cli/tests/docker_compat_integration.rs`~~

## Medium
- [x] ~~MED-01 - Remove duplicate dependency declaration (`base64`) in `ferro-core/Cargo.toml`~~
- [x] ~~MED-02 - Address `clippy::result_large_err` in CRI fs-usage helper (`ferro-cri/src/server.rs`)~~
- [x] ~~MED-03 - Address `clippy::large_enum_variant` for CLI command enum (`ferro-cli/src/main.rs`)~~
- [x] ~~MED-04 - Address `clippy::items_after_test_module` in CLI main file (`ferro-cli/src/main.rs`)~~
- [x] ~~MED-05 - Address `clippy::too_many_arguments` for `handle_run` (`ferro-cli/src/main.rs`)~~
- [x] ~~MED-06 - Address `clippy::too_many_arguments` for runtime entrypoints (`ferro-core/src/runtime.rs`)~~
- [x] ~~MED-07 - Address `clippy::too_many_arguments` for dockerfile config serialization helper (`ferro-core/src/dockerfile_build.rs`)~~
- [x] ~~MED-08 - Address `clippy::type_complexity` in cgroup CPU stat parsing (`ferro-core/src/cgroups.rs`)~~
- [x] ~~MED-09 - Address `clippy::type_complexity` in runtime network setup return typing (`ferro-core/src/runtime.rs`)~~

## Low
- [x] ~~LOW-01 - Fix compose interpolation collapsible-if/iterator style issues (`ferro-compose/src/lib.rs`)~~
- [x] ~~LOW-02 - Fix kernel compat parser `get_first`/string handling (`ferro-net/tests/kernel_compat.rs`)~~
- [x] ~~LOW-03 - Fix anomaly `manual_div_ceil` (`ferro-mind/src/ai/anomaly.rs`)~~
- [x] ~~LOW-04 - Add `is_empty` alongside `len` for RVF store (`ferro-mind/src/ai/learning/rvf_store.rs`)~~
- [x] ~~LOW-05 - Replace `map_or` patterns with `is_some_and`/`is_none_or` in training paths (`ferro-mind/src/ai/training.rs`)~~
- [x] ~~LOW-06 - Remove unnecessary casts in resource tests (`ferro-mind/src/ai/resource.rs`)~~
- [x] ~~LOW-07 - Remove unused top-level `Read` import in container exec (`ferro-core/src/container_exec.rs`)~~
- [x] ~~LOW-08 - Remove redundant local rebinding in runtime spawn flow (`ferro-core/src/runtime.rs`)~~
- [x] ~~LOW-09 - Replace vec-init-then-push patterns in AppArmor/SELinux command wrapping (`ferro-core/src/runtime.rs`)~~
- [x] ~~LOW-10 - Replace `&mut Vec<T>` arg with `&mut [T]` for iptables action mutation helper (`ferro-core/src/runtime.rs`)~~
- [x] ~~LOW-11 - Fix CLI print-literal formatting (`ferro-cli/src/main.rs`)~~
- [x] ~~LOW-12 - Replace string-empty comparison with `is_empty` in Docker path normalization (`ferro-cli/src/main.rs`)~~
- [x] ~~LOW-13 - Remove identity map in Docker port-binding parser (`ferro-cli/src/main.rs`)~~
- [x] ~~LOW-14 - Resolve dead-code clippy findings in docker auth scoped env helper (`ferro-core/src/docker_auth.rs`)~~
- [x] ~~LOW-15 - Resolve dead-code clippy findings in registry config/retry helper (`ferro-core/src/registry.rs`)~~
- [x] ~~LOW-16 - Remove unused default timeout constant (`ferro-core/src/runtime.rs`)~~
- [x] ~~LOW-17 - Resolve clippy `await_holding_lock` in CRI socket integration test (`ferro-cri/tests/socket_integration.rs`)~~
- [x] ~~LOW-18 - Resolve clippy dead-code enum variant warning in API compatibility matrix test (`ferro-cli/tests/api_compat_matrix.rs`)~~
- [x] ~~LOW-19 - Resolve clippy `unnecessary_unwrap` in image-security env fallback test (`ferro-core/src/image_security.rs`)~~

## Verification
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace`

## Remaining Work
- None from this review sweep.
