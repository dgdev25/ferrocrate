# NET-06 Task 5 Report

## Status

Implemented the safe userspace Aya loader and transactional network lifecycle on
`feat/managed-networking` from base `3ade0bb`.

Implementation commit: `e3c6711 feat(net): load eBPF networking transactionally`

## Delivered

- Added `EbpfNetwork::load` and injectable `load_with` lifecycle paths.
- Added SHA-256 verification of the embedded object before kernel preflight.
- Added bounded ELF64 extraction and validation of the retained `ABI_VERSION` symbol.
- Made `ferro_net::ebpf_abi` public.
- Verified exact application map names, Aya map variants, key/value sizes, maximum entries,
  ABI version, and classifier names before pinning or TC attachment.
- Added fixed bpffs ownership at `/sys/fs/bpf/ferro/networks/<network-id>` with single-segment
  network IDs, symlink rejection, pre-existing transaction-root rejection, and tracked cleanup.
- Verified bpffs, interface/ifindex identity, `tc` access, and required capabilities before
  loading the object.
- Parsed `/proc/sys/net/ipv4/ip_local_reserved_ports` and proved complete inclusive SNAT-range
  coverage before Aya preflight or any network mutation.
- Populated external IPv4, external ifindex, next-hop MAC, reserved SNAT range, ABI, and the
  reservation flag as one coherent `FERRO_META` update.
- Loaded and inspected the real embedded object through Aya, pinned maps/programs under the
  owned network path, and attached `ferro_ingress` and `ferro_egress` as TC classifiers.
- Added typed endpoint, published-port, policy, metrics, removal, and detach operations without
  exposing Aya map handles.
- Added rollback for partial pin/load/attach failures and retryable, idempotent detach semantics.
- Preserved the existing security-monitor and command-builder APIs used by `ferro-core`.

## TDD Evidence

### RED 1

Command:

```text
cargo test -p ferro-net --test ebpf_integration
```

Result: exit 101. Compilation failed because `EbpfNetwork`, `EbpfNetworkConfig`, `EbpfError`,
`EbpfMetrics`, the public `ebpf_abi` module, and `ebpf_loader` did not exist.

### GREEN 1

The same command passed 11 tests covering successful load, coherent metadata, typed map writes,
ABI mismatch, missing/wrong maps, unexpected classifiers, complete reserved-range proof, hash and
path rejection, second-attach rollback, map capacity, metrics, and idempotent detach.

### RED 2

An additional test required the embedded ELF's actual ABI rather than accepting the userspace
constant. The loader target failed with an unresolved `embedded_object_abi` import.

### GREEN 2

The loader target passed after adding bounded ELF symbol extraction and using that value in Aya
object metadata:

```text
12 passed; 0 failed; 1 ignored
```

The ignored test is the real privileged `EbpfNetwork::load` smoke path. It requires root,
`CAP_BPF`, `CAP_NET_ADMIN`, bpffs, `tc`, a configured interface, and a fully reserved test SNAT
range.

## Validation

- `cargo test -p ferro-net`: PASS.
- `cargo build -p ferro-net`: PASS.
- `cargo test --workspace`: one run performed. It reached `ferro-core` and failed only at
  `runtime::tests::startup_reconcile_keeps_live_running_pid` because its temporary database lock
  returned `WouldBlock`; 175 other `ferro-core` tests passed in that suite.
- `cargo test -p ferro-core runtime::tests::startup_reconcile_keeps_live_running_pid -- --exact`:
  PASS in isolation, confirming the workspace result was a parallel lock flake.
- `git diff --check`: PASS before the implementation commit.
- Embedded object evidence from `readelf`: retained ABI object symbol, `ferro_ingress`,
  `ferro_egress`, `FERRO_META`, classifier section, maps section, and ABI rodata section present.
- Embedded object SHA-256 observed during validation:
  `39056c3710fe688ecad023e152c6dcaeb1daedd38a75af0cbb276489670b0b06`.

The crate doc-test phase emits the existing workspace warning that
`missing_crate_level_docs` was renamed to `rustdoc::missing_crate_level_docs`. No Task 5 source
warning remained.

## Self-review

### Ownership and path traversal

- Network IDs are restricted to one ASCII alphanumeric, hyphen, or underscore path segment.
- Pin paths are derived internally and must be direct children of the fixed ferro network root.
- Existing transaction roots and symlinked ownership components fail closed.
- Rollback removes only files and directories recorded as created by the current adapter.
- Shared parent directories are never recursively deleted.

### Rollback

- Metadata/schema/ABI/classifier failures drop the staged Aya object through `rollback` without
  attaching.
- Commit failures drop Aya first so attached links detach, remove a clsact qdisc only when this
  transaction created it, unlink tracked pins, and remove tracked directories in reverse order.
- Partial cleanup errors are returned and network-owned non-empty directories remain tracked for
  retry.

### Idempotence

- Successful `detach` is a no-op on subsequent calls.
- Failed detach does not mark the network detached, allowing cleanup to be retried.
- Endpoint and port removal treat an absent kernel map key as success.

## Concerns

- Privileged kernel verifier and live TC attach evidence was unavailable in this environment; the
  real Aya loader/rollback path is implemented and represented by a capability-gated ignored test.
- The one workspace run was not fully green because of the unrelated temporary database lock
  race described above; its exact failed test passed immediately in isolation.
