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
- Resolved by the review fix below: runtime artifact validation now requires a
  regular nonempty ELF file. Cryptographic artifact verification remains outside
  this task's scope.

## Review-Fix Evidence

### Changes

- Added `bpftool` to the mandatory eBPF `BackendProbe` contract check.
- Updated the eBPF unavailable error to state the exact Task 1 prerequisites:
  `tc`, `bpftool`, bpffs mounted at `/sys/fs/bpf`, and a regular nonempty ELF
  eBPF program artifact. It makes no cryptographic-verification claim.
- Replaced runtime `Path::is_file()` artifact acceptance with
  `ebpf_artifact_available`, which requires successful metadata lookup, a
  regular file, nonzero length, successful opening, and the four-byte ELF
  magic (`0x7f 45 4c 46`).
- Added independent contract tests for missing `tc`, missing `bpftool`, missing
  bpffs, invalid/missing artifact, and the all-prerequisites success path.
- Added a runtime artifact test covering missing path, directory, empty file,
  non-ELF file, and valid nonempty ELF-magic file.

### Review-Fix RED Evidence

Tests were extended before implementation and then run with:

```text
cargo test -p ferro-net backend
cargo test -p ferro-core ebpf_artifact_requires_regular_nonempty_elf_file
```

Results before the fix:

- `backend::tests::ebpf_requires_bpftool` failed because a probe with every
  other prerequisite present was accepted.
- The runtime test failed to compile because `ebpf_artifact_available` did not
  exist.

### Review-Fix GREEN Evidence

```text
cargo test -p ferro-net backend && \
  cargo test -p ferro-core ebpf_ && \
  cargo test -p ferro-cli published_port_preserves_ebpf_backend && \
  cargo test --workspace
```

Focused results:

- `ferro-net backend`: 7 passed
- `ferro-core ebpf_`: 3 passed
- `ferro-cli published_port_preserves_ebpf_backend`: 1 passed

The workspace suite again failed only at the unrelated existing test:

```text
ferro-core/tests/security_tests.rs::parses_default_seccomp_profile
left: "SCMP_ACT_ALLOW"
right: "SCMP_ACT_ERRNO"
```

The stated cosign baseline test passed in this environment.

### Ordering Confirmation

`setup_network` calls `resolve_network_backend(network_backend,
&RuntimeBackendProbe)` before it builds bridge configuration or calls
`bridge::create_bridge`, `enable_ip_forwarding`, iptables masquerading,
`ip netns add`, or veth creation. `resolve_network_backend` immediately calls
`NetworkBackend::ensure_available`, and the runtime probe performs the ELF
artifact validation. Therefore an unavailable eBPF backend is rejected before
any common bridge or veth mutation. Host, none, and wireguard modes return via
their dedicated paths and do not enter the bridge/veth setup path.

### Review-Fix Self-Review

- The contract requires all four Task 1 eBPF prerequisites; no individual
  prerequisite is optional.
- Artifact validation is limited exactly to regular/nonempty/ELF checks as
  required. Cryptographic hash, map setup, and attach transaction verification
  are not claimed or implemented here.
- The established explicit backend selection and no-fallback behavior remain
  unchanged.
- The existing direct `ferro-net` dependency in `ferro-cli` and the lockfile
  are intentionally unchanged by this review fix.
