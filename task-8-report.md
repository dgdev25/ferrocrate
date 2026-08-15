# Task 8 report: request-bound privileged networking

## Outcome

Task 8 replaces ambient manager/netd authority with signed, bounded, single-use helper grants. Production controller desired-state and local runtime attachment paths now authorize exact child mutations, persist authorization and nonce state before effects, attest Unix peers before decoding, and correlate durable results with authorization witnesses.

## Requirement evidence

- **REQ-026:** `HelperGrant` binds request and operation IDs, closed action, canonical resource UUID and stable generation, normalized parameters and received descriptors, boot ID, wall and monotonic deadlines, nonce, issuer/key ID, precondition, and recovery recipe. Netd rejects wrong peer, executable, signature, key, boot, generation, action, parameters, descriptors, expiry, cleanup provenance, and replay.
- **REQ-030:** the runtime obtains opaque authorization from the real gate/durable-intent boundary; the manager attenuates it into one exact child operation. Controller desired revisions carry an atomically persisted signed authorization bundle for every exact diff child. Whole revisions fail on denial; there is no hidden deletion or aggregate grant.
- **REQ-031:** cleanup authority is deletion-only and derives from the successful creation receipt. Runtime, manager ledger, and netd independently bind origin request, live identity, canonical resource, generation, boot, and ownership. Legacy/unverifiable records are quarantined instead of receiving mutation authority.
- **REQ-035:** enforce/shadow/disabled composition shares a canonical service mode. Enforcing sockets reject legacy traffic; disabled traffic uses an explicit versioned envelope and dedicated configuration. Controller and agent use custody-checked no-follow keys and bounded overlap keyrings.

## Durability and recovery

- Parent and child ledgers use exclusive OS locks and fsynced atomic replacement. A nonce moves through pending, consumed-before-effect, and succeeded/failed/outcome-unknown states before it can mutate the host.
- Production controller state and its authorization bundle are appended atomically by revision.
- Netd persists the concrete overlay/endpoint effect target. Startup observes kernel and ownership state and records recovered success, determinate failure, or quarantine on conflict; it never automatically replays an ambiguous mutation.
- Controller and local mutations share a durable order-safe allocator. Coverage includes controller revision 1, local children, controller revision 2, another local child, and restart.

## Transport and key custody

- Manager and netd authenticate `SO_PEERCRED` before reading a length or body, retain a pidfd, validate executable and process start time, bound frames before allocation, and reject `SCM_RIGHTS` when no operation accepts descriptors.
- Signing-key files are opened with no-follow semantics and checked by file descriptor for owner, mode, and link count before reading. Verification keyrings support bounded active/overlap keys and explicit retirement.

## Verification

- `LIBRARY_PATH=$PWD/.superpowers/toolchain/lib cargo test -p ferro-netd --all-targets` — passed: library, binary, seven grant authorization tests, and six socket-security tests.
- `LIBRARY_PATH=$PWD/.superpowers/toolchain/lib cargo test -p ferro-mgr --all-targets --quiet` — passed: 16 manager unit tests and every integration target, including production controller/runtime/manager/netd Unix composition.
- The cross-stack attach and cleanup test obtains opaque authority through real `RuntimeAuthorization`, `AuthorizationGate`, required `WitnessJournal`, and `DurableIntent`; it contains no fabricated grant claims or supplied peer UID.
- Focused core authorization, witness journal, managed-overlay, controller store, manager restart/multiprocess ledger, cleanup provenance, mode negotiation, descriptor injection, and cross-stack tests passed throughout red/green development.
- All newly split netd modules are at or below 500 lines (`grants.rs` 495, `server.rs` 496).
- Task-scoped clippy completes with warnings inherited from existing `ferro-net`, `ferro-core`, and older composition code. `-D warnings` stops on those pre-existing warnings before Task 8 validation.
- Workspace-wide `cargo fmt --check` reports extensive pre-existing formatting drift in unrelated crates; every Task 8 file was formatted directly with `rustfmt` and passes `git diff --check`.

The untracked `.superpowers/toolchain/` linker support and `docs/research/` material are pre-existing workspace artifacts and are intentionally excluded.
