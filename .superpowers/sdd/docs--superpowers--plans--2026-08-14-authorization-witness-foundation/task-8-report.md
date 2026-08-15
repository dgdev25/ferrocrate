# Task 8 implementation report

## Outcome

Implemented request-bound, signed, single-use authorization grants for `ferro-netd`.

- Added a domain-separated Ed25519 `HelperGrant` with a closed action vocabulary and bindings for request ID, canonical UUID/generation, normalized parameter and descriptor digest, boot ID, wall and monotonic deadlines, nonce, issuer, key ID, and cleanup provenance.
- Added grant envelopes to the bounded netd protocol. Legacy directly signed helper requests are now rejected with `MissingGrant` after their existing desired-state signature is checked.
- Added a single-writer durable grant ledger. A complete signed claim is persisted and fsynced before mutation, replay remains rejected after restart, and successful results are durably correlated to request ID, nonce, and result identity. Failure to persist a result is reported as an ambiguous `Busy` result and is never replayable.
- Kept the existing manager desired-state signature validation and policy validation in addition to helper-grant validation.
- Added production grant public-key/key-ID/issuer/boot/journal configuration.
- Hardened the Unix listener with mode `0660`, kernel peer UID, mandatory pidfd, exact executable identity, and process start-time availability before frame-body decode.
- Added an explicit `ManagedOverlayClient::request_authorized` path which can mint only from an `AuthorizedRequest` plus `DurableIntent`; no caller-provided role or ambient helper authority is accepted by the grant issuer.
- Cleanup grants have no create/attach representation, require origin request and live-identity evidence, and remain bound to the exact signed resource, generation, operation parameters, and descriptors.
- Production runtime calls now carry an opaque parent delegation through the manager local API. The manager verifies the parent grant and attenuates it to exactly one attach or detach endpoint mutation; enforcing mode has no ungranted client path, while compatibility requires the explicit disabled mode.
- Grant claims use bounded, versioned canonical binary signing input and include operation, request-decision, precondition, and recovery-recipe digests. Key material is loaded only from owned regular files without group/other access, and verifier keyrings support overlap and retirement.
- The nonce ledger has an exclusive OS writer lock and durable `Pending -> ConsumedBeforeEffect -> OutcomeUnknown -> Succeeded` transitions, preventing cross-process replay and preserving ambiguous outcomes for reconciliation.

## TDD evidence

The initial test command failed because `ferro-netd/src/grants.rs` did not exist. The captured RED output is `task-8-red.txt` in this workspace.

Final adversarial coverage includes:

- direct request without a helper grant;
- wrong UID before decoding;
- mandatory pidfd and wrong executable rejection;
- bad signature/key ID;
- nonce replay, including after journal reopen;
- parameter and FD identity substitution;
- wrong canonical UUID or generation;
- wrong boot and expired wall/monotonic deadline;
- cleanup create/escalation and missing cleanup provenance;
- durable request/result correlation and conflicting-result protection.
- a real Unix ancillary-data boundary that rejects missing/extra descriptors (all descriptors are forbidden because current netd operations consume none);
- exclusive cross-process ledger ownership, verifier-key overlap/retirement, and a real granted-envelope server mutation;
- production runtime-to-manager delegation wiring and exact attach/detach child attenuation.

## Verification

- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo test -p ferro-netd` — PASS (2 unit, 6 grant integration, 6 socket/policy integration tests).
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo test -p ferro-mgr` — PASS (all unit, integration, and doc tests).
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo check -p ferro-core -p ferro-mgr -p ferro-netd` — PASS.
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo build -p ferro-netd` — PASS.
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo test -p ferro-core managed_overlay` — PASS.
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo clippy -p ferro-netd --all-targets` — PASS with pre-existing warnings; output captured in `task-8-clippy.txt`.
- `cargo clippy ... -- -D warnings` remains blocked only by pre-existing `ferro-net`/`ferro-core` warnings outside Task 8.
- `git diff --check` — PASS.
- `cargo test -p ferro-core --lib` — 274 passed, 1 ignored; one pre-existing SIGKILL barrier test remained flaky (`run did not reach bind-effect`) and failed identically on retry.
- Task-file secret/shell/unsafe/TODO scan — PASS.
- New modules are below 500 lines (`helper_grant.rs`: 303; `grants.rs`: 310).

No new architecture decision was introduced beyond ADR-0008 through ADR-0011.

## Review hardening rounds

Round-two hardening added an exclusive, fsynced manager parent-delegation ledger. Parent request ID, operation ID, and nonce are consumed before IPAM or child minting; the proposed child identity is persisted first, completed responses survive restart, and in-progress replay cannot obtain a fresh nonce.

Durable helper minting now verifies the journaled canonical request digest against the `AuthorizedRequest`, requires the exact requested overlay to be present in authorized network facts, and opens signing keys with `O_NOFOLLOW` before descriptor-based owner/mode/type/link-count checks.

A controller-signed, revision-bound `DesiredAuthorizationBundle` transport and enforcing agent consumer were added. The agent verifies the desired-state digest and exact apply/remove transition, then forwards only the provided per-operation `GrantedEnvelope` values. Legacy reconciliation is available only through explicit disabled mode. Because the controller currently has neither a legitimate root per-overlay grant issuer nor persisted authorization bundles, non-empty production desired state fails closed instead of exercising ambient authority; completing that producer requires extending controller authorization and persistence.

The final hardening pass completed that producer: a custody-checked controller issuer evaluates the complete exact diff, denies the whole revision when any resource lacks canonical policy authorization, issues unique per-child grants, and atomically persists the desired state with its signed bundle. RPC retrieves the same stored pair and the agent accepts a bounded overlap key during controller rotation.

Successful endpoint creation now fsyncs cleanup provenance including the attach child request, canonical resource generation, overlay/container/netns, and netd-compatible live identity. Detach accepts only a deletion-only cleanup parent matching that provenance. Disabled compatibility uses an explicit versioned `mode=disabled` envelope and requires both authenticated peer transport and disabled server policy.

Netd production configuration now loads a bounded verification keyring rather than a single ambient key. Accepted endpoint syscall/storage failures are durably recorded as failed results, while a restart with an armed unknown effect writes a correlated quarantine outcome and never makes the nonce replayable.

Additional verification:

- `cargo test -p ferro-mgr --lib` — PASS (7 tests, including restart and separate-process ledger exclusion).
- `cargo test -p ferro-core authorization:: --lib` — PASS (46 tests).
- `cargo test -p ferro-core witness::journal --lib` — PASS.
- `cargo check -p ferro-mgr --lib --bin ferro-agent` — PASS.
- `cargo test -p ferro-netd` — PASS (15 tests, including real server/granted-wire, ancillary FD rejection, replay/restart, key overlap, and unknown-effect quarantine).
- `cargo test -p ferro-mgr` — PASS (all unit/integration/doc tests; 14 focused authorization tests).
- `cargo clippy -p ferro-core -p ferro-mgr -p ferro-netd --all-targets` — PASS with documented pre-existing warnings.

## Cross-stack closure

Netd is now a library plus a composition-only production binary. Every bridge, veth, namespace, route, WireGuard, and observation effect passes through a private `NetKernelOps`; production uses `RealNetKernelOps`, while a non-default test-support feature provides a persistent deterministic backend, bounded one-request Unix service, redacted receipts, and one-shot effect/persistence faults. All netd source modules remain below 500 lines.

Controller reconciliation and local delegated mutations share one fsynced `NetdSequence`. Controller success advances it, each local child durably reserves its next tuple before sending, concurrent reservations remain unique, restart retains the high-water mark, and failed calls may consume a safe gap but cannot reuse a stale revision.

The cross-stack E2E covers controller policy/issuer/store and signed bundle delivery, enforcing agent reconciliation, a real Unix netd connection, a real manager Unix local API connection, endpoint attach, fsynced provenance, cleanup-only detach, distinct parent/child nonces, kernel snapshots, correlated receipts, replay without a new send/sequence, direct legacy bypass rejection, explicit disabled negotiation, and injected post-effect state-persistence failure with durable failure receipt and no orphan endpoint. Netd’s focused restart test separately verifies that an armed grant-ledger unknown effect becomes a correlated quarantine receipt and remains non-replayable.

- `cargo test -p ferro-netd --all-features` — PASS (library, binary, authorization, socket, and doc tests).
- `cargo test -p ferro-mgr --all-targets` — PASS, including `authorization_cross_stack`.
