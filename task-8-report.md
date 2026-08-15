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

## Round 4 production composition

- `AdminService.PublishDesired` is a real authenticated gRPC mutation API. The production listener derives an administrator principal from mTLS, rechecks role, method, cluster and active node, then invokes the exact-diff controller issuer and atomically stores state plus its bundle. Empty desired state authorizes deletion of the final overlay rather than hiding it.
- Controller semantic revisions no longer enter netd policy ordering. Every controller child and local child reserves one globally monotonic durable netd sequence; the controller `(epoch, revision, child)` mapping is idempotent across restart.
- Manager and netd frames bind lowercase authorization mode, optional policy digest and boot instance. Both services invoke `AuthorizationServiceMode::require_match` before mutation. Production disabled mode uses a signed, bounded prost desired-state envelope; netd applies exact nonempty state and removes it on a later signed empty state. Enforcing netd rejects this legacy envelope.
- The binary and cross-stack test share the library production accept-one handler. It derives `SO_PEERCRED`, pins a pidfd and executable/start time, rejects ancillary descriptors, bounds length before allocation, and revalidates the process before dispatch.
- Every armed operation persists an action-specific `EffectReceipt`. Overlay receipts bind generation, peer/public-key digest, address digest, route digest and netd policy epoch/revision. Endpoint receipts bind generation, overlay/master digest and observed netns inode. Restart requires the exact receipt, ownership record and live kernel link to agree; missing or partial receipt state is quarantined rather than reported as success.
- `RealNetKernelOps` recomputes that receipt from live `wg show ... dump`, `ip -j addr`, `ip -j route`, bridge-master link data, netns inode and peer-link presence. Any command/parse/permission failure is `Unknown` and quarantines. The persistent deterministic backend models every field independently; tests remove peers, addresses and routes and substitute the endpoint master to prove no partial state becomes `Succeeded`. A result-persist fault followed by restart demonstrates exact live state becoming `Recovered` without replay.

Round 4 verification:

- `cargo test -p ferro-netd --all-targets --quiet` — passed: 6 library tests, 2 binary tests, 7 grant tests and 6 socket tests.
- `cargo test -p ferro-mgr --all-targets --quiet` — passed: 19 manager unit tests and every integration target, including authenticated PublishDesired, global sequence restart, matching/mismatching handshakes, disabled nonempty-to-empty reconciliation, and real Unix cross-stack mutation.

## Production topology correction

- Each canonical overlay now derives two stable, collision-resistant Linux interface identities: `fb<12 hex>` for the bridge and `fw<12 hex>` for WireGuard. Both are 14 bytes, below `IFNAMSIZ`, and are bound into controller grants, normalized request parameters, effect receipts and persisted ownership.
- Desired state carries an explicit signed `wireguard` mode. Netd creates the bridge first, then the distinct WireGuard link when required, configures addresses/peers and routes on the mode-selected interface, and always enslaves endpoint veths to the bridge. Removal reverses that order and proves both links absent.
- Production WireGuard apply/remove fails closed when key configuration is unavailable. Bridge-only mode is explicit rather than inferred from missing configuration.
- Live and deterministic observations verify the bridge and WireGuard link kinds independently. Stale WireGuard state prevents successful deletion recovery; a wrong bridge master, missing topology link, peer/address/route mismatch, or link-name kind collision cannot become an idempotent success.
- Ownership journals written before interface identities were recorded deserialize as legacy and are quarantined for operator reconciliation rather than mutated under guessed topology.
- The deterministic command recorder asserts ordered, distinct `ip link add ... type bridge`, `ip link add ... type wireguard`, `wg set`, route, veth, and bridge-master effects. The unprivileged test environment cannot safely run an actual root-namespace fixture.

Topology verification:

- `cargo test -p ferro-netd --all-features --quiet` — passed: 9 library tests, 2 binary tests, 7 grant tests and 6 socket tests.
- `cargo test -p ferro-mgr --all-targets --quiet` — all unit and integration targets passed.
- `cargo test -p ferro-core managed_overlay --quiet` — stable interface identity test passed.
- Task-owned netd modules remain at or below 500 lines (`server.rs` 496, `kernel_deterministic.rs` 500, `grants.rs` 499).

Focused review corrections:

- Updates snapshot prior ownership. A persistence failure cleans up only topology created by that request; existing topology is retained with its prior durable receipt so restart observation quarantines any partial live transition instead of deleting a working network.
- Mode transitions remove obsolete routes from the prior interface and remove the WireGuard link on WireGuard-to-bridge-only changes. Bridge-only receipts name the expected-absent WireGuard link, so stale extras cannot be accepted as exact state.
- Overlay deletion retains ownership until route, address, WireGuard and bridge effects all finish. Persistence failure restores the ownership/tombstone view for deterministic recovery.
- Quarantine is enforced before grant consumption. Omitted protobuf mode is rejected, while explicit `Some(false)` is the only bridge-only representation.
- The routed topology is explicit: the bridge owns container gateway addresses, WireGuard remains a distinct L3 peer device, remote routes target WireGuard, and WireGuard mode requires IPv4 forwarding. Address/route placement and forwarding are grant- and receipt-bound; WireGuard is never incorrectly enslaved to the bridge.

Transactional mutation follow-up:

- Desired overlays now carry explicit bridge gateway addresses end-to-end; the controller no longer emits an empty hard-coded address set.
- Overlay apply/remove writes a durable mutation intent containing operation ID, action, prior receipt, desired receipt, routes, addresses, and phase before the first kernel call. The ownership state and terminal intent phase are written together.
- Any granted failure after entering the effect boundary is recorded as `OutcomeUnknown`, never `Failed`. Same-process ambiguity is quarantined immediately. Restart compares the desired and prior complete receipts: exact desired state is committed as recovered, exact prior state is retained as not-applied, and partial/unverifiable state is quarantined.
- Disabled legacy mutations use the same durable intent record and are blocked by canonical-resource quarantine checks.
