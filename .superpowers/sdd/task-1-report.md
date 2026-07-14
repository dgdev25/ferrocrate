# Task 1 Report: Typed, Fail-Closed Backend Selection

## Status

Implementation complete. Focused regressions pass. The final workspace suite has
one additional failure beyond the stated baseline; see Concerns.

## Implementation

- Added `ferro_net::NetworkBackend::{Ebpf, Iptables, Nftables}` with parsing,
  display formatting, `BackendProbe`, and `BackendError`.
- Added `NetworkBackend::ensure_available`, which fails closed with explicit
  errors for unavailable eBPF, iptables, and nftables backends.
- Re-exported the backend contract from `ferro-net`.
- Changed `ContainerRuntime::run`, `run_with_store`, and network setup to carry
  `NetworkBackend` instead of `&str`.
- Replaced the old eBPF strict/assumption environment controls and fallback
  resolver with `RuntimeBackendProbe` plus `ensure_available`.
- Removed both implicit eBPF substitutions:
  - CLI no longer changes eBPF to iptables when `--publish` is set.
  - Runtime no longer chooses nftables or iptables for an eBPF request.
- eBPF with published ports now returns the explicit existing error requiring
  `iptables` or `nftables`; it never changes the requested backend.
- Added a selection log carrying `requested_backend` and `active_backend`, with
  a debug assertion that they are equal.
- Kept CLI storage as `String` for compatibility, validated through Clap, then
  parsed into `NetworkBackend` before runtime setup.
- Added the compiler-required direct `ferro-net` dependency to `ferro-cli` and
  updated `Cargo.lock`.

## TDD Evidence

### RED

Added backend-contract tests before implementation, then ran:

```text
cargo test -p ferro-net backend -- --nocapture
```

Result: failed as expected because `BackendProbe` and `NetworkBackend` did not
exist in `ferro-net/src/backend.rs`.

```text
error[E0432]: unresolved imports `super::BackendProbe`, `super::NetworkBackend`
```

### GREEN

Implemented the smallest backend contract and propagation needed by the tests.
The first focused run found expected compiler-required migrations of existing
runtime tests and the direct CLI dependency. After applying those changes, the
final focused sequence passed:

```text
cargo test -p ferro-net backend
cargo test -p ferro-core ebpf_backend
cargo test -p ferro-cli published_port_preserves_ebpf_backend
```

Results:

- `ferro-net`: 2 passed
- `ferro-core`: 1 passed
- `ferro-cli`: 1 passed

During the final validation, wiring Clap to a validator returning `()` caused a
field downcast panic. The validator was corrected to return the validated input
`String`; the complete focused sequence was then rerun successfully.

## Commands and Results

```text
cargo test -p ferro-net backend -- --nocapture
```

RED: failed for the missing backend contract as described above.

```text
cargo test -p ferro-net backend && \
  cargo test -p ferro-core ebpf_backend && \
  cargo test -p ferro-cli published_port_preserves_ebpf_backend && \
  cargo test --workspace
```

Focused tests: passed.

Workspace suite: failed only at:

```text
ferro-core/tests/security_tests.rs::parses_default_seccomp_profile
assertion failed: left == right
left: "SCMP_ACT_ALLOW"
right: "SCMP_ACT_ERRNO"
```

The stated baseline failure,
`ferro-core image_security::tests::verify_image_signature_with_fake_cosign_failure`,
passed in this environment. No failure was observed in files changed by this
task.

## Files Changed

- `ferro-net/src/backend.rs` (new)
- `ferro-net/src/lib.rs`
- `ferro-core/src/runtime.rs`
- `ferro-cli/src/main.rs`
- `ferro-cli/Cargo.toml` (compiler-required direct dependency)
- `Cargo.lock` (manifest resolution)
- `.superpowers/sdd/task-1-report.md` (this report)

## Self-Review

- Completeness: all requested public contract types, parsing, availability
  checks, CLI regression, and runtime regression are present.
- Error quality: unavailable backends state the requested backend and missing
  prerequisite; invalid CLI values retain the existing allowed-values error.
- No fallback behavior: a targeted scan found no
  `FERROCRATE_EBPF_STRICT`, `FERROCRATE_EBPF_ASSUME_AVAILABLE`,
  `FERROCRATE_EBPF_ASSUME_UNAVAILABLE`, fallback logging, or backend-selection
  fallback variables in the changed implementation files.
- Scope: only the requested source files plus the compiler-required CLI
  manifest/lock and required report were changed.

## Concerns

- The final workspace suite differs from the supplied baseline: the stated
  cosign failure passed, while the unrelated seccomp default-profile test
  failed. This task does not modify seccomp behavior or that test.
- `RuntimeBackendProbe::artifact_available` verifies that the configured
  FerroCrate eBPF object file exists. The task contract does not define a
  cryptographic artifact-verification mechanism; stronger verification remains
  outside this task's scope.
