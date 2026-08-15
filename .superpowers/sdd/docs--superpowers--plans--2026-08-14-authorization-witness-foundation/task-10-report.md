# Task 10 implementation report

## Result

Implemented the policy, witness, verification, checkpoint/key-rotation, and local-console emergency CLI in commit `feat(cli): operate authorization witnesses`.

## Delivered behavior

- `policy check` emits stable allow/reason/rule/version/digest fields after protected, bounded policy validation.
- `policy reload` is host-administrator authenticated, authorized through an unforgeable surface permit, durably witnessed when authorization is enabled, atomically installed, generation-monotonic, and requires an exact separately authorized rollback artifact for decreases.
- `witness show` reads sealed plus active evidence, filters by sequence/stage, emits only redacted structural fields, and enforces a 1–1,000 record bound.
- `witness verify` requires an explicit out-of-band trust bundle, pinned journal ID, explicit minimum checkpoint, and explicit checkpoint lineage. It streams journal evidence and reports integrity, lifecycle consistency, completeness, freshness, and checkpoint age separately.
- `witness checkpoint` uses the core capture → sign → atomic publish/fsync → journal-bind coordinator and exposes durable pending-binding reconciliation with `--recover-pending`.
- `witness rotate-key` creates a protected successor key and publishes the core dual-signed rotation checkpoint. Output exposes key IDs only.
- Emergency activation is limited to a physical local console, real/effective UID 0 in the initial user namespace, a closed safety-action set, one bounded resource, current boot, nonce, and exact bounded monotonic deadline. It requires an offline Ed25519 recovery approval and a pre-provisioned independent append sink.
- The emergency receipt is synced before active state. Missing/full/insecure sinks deny activation. State is replay/boot bound and blocks normal commands across restart until a same-sink reconciliation receipt is synced.
- Added the security/operator runbook covering threat guarantees, rotation, key loss, trust reset, freshness, disk-full behavior, pending binding, reserve rules, and quarantine.

## TDD evidence

The initial command-level test run failed because `policy`, `witness`, and `emergency` did not exist. The first green cycle established the command tree, mandatory verifier inputs, and remote-emergency denial. Subsequent cycles added policy rollback, real checkpoint/verification/rotation, restart gating, and emergency adversaries.

## Verification

- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo test -p ferro-cli --test witness_cli` — PASS (8/8).
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo test -p ferro-cli --lib authorization_admin` — PASS (2/2).
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" FERROCRATE_SKIP_ROOT_TESTS=1 cargo test -p ferro-cli` — PASS across all CLI unit, integration, compatibility, property, security, and doc suites; only the repository's explicitly ignored privileged container E2E cases remained ignored.
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo build -p ferro-cli` — PASS.
- Changed-target clippy with `-D warnings` — PASS for the library, binary (with the binary's two pre-existing `too_many_arguments` exemptions), and `witness_cli` target. The repository-wide all-target command still reports pre-existing unrelated warnings in `tests/property_image_reference.rs` and two existing binary functions.
- `rustfmt --check` on every new source/test module — PASS. The existing `main.rs` baseline is not globally rustfmt-clean, so it was not mechanically reformatted.
- Task-file secret/shell/unsafe/TODO scan and `git diff --check` — PASS.

Pre-existing dependency warnings in `ferro-net` and `ferro-core` were not changed.

## Review hardening

Follow-up commits `bfb6d40` and `7eeb33d` close the production-path review findings. Policy authorization now hashes and installs bytes held by one protected descriptor, uses the fixed runtime policy path, and refreshes existing runtime policy pins from atomic installs (including separately authorized rollback). Enabled production runtimes use one required journal and require a valid fixed checkpoint within the coordinator's five-minute age plus one-minute grace; stale or missing evidence denies new mutation while stop/delete cleanup remains available.

Checkpoint and rotation commands now require the runtime's fixed journal/artifact and pass the native administrative authorization action using that already-open required journal, producing durable intent and outcome around the high-level publication coordinator. Emergency execution binds the independent sink outcome to the main-journal sequence range and reconciliation requires matching terminal action evidence. Sink validation is performed from the same `O_NOFOLLOW|O_APPEND` descriptor (owner, mode, regular type, single link, header, and activation-bound device/inode).

The accidental `main.rs` whole-file rustfmt churn in `bfb6d40` was reversed in `7eeb33d`; the remaining diff is scoped to the new command behavior.

Review verification: `cargo check -p ferro-cli` passed; `witness_cli` passed 8/8; emergency unit tests passed 2/2; live policy refresh and checkpoint admission cleanup tests passed. Commands used the repository-local `LIBRARY_PATH=.superpowers/toolchain/lib` seccomp shim.

## Review hardening round 2

- Replaced timestamp-only production mutation admission with a shared verifier-backed `MutationAdmission`. Runtime and surface authorization now validate the pinned journal, explicit trust bundle, explicit minimum checkpoint, checkpoint key lineage, witnessed head, signature, branch, and age before admitting new user mutations. Cleanup and the separately authorized checkpoint repair actions remain available during stale-evidence recovery.
- Split checkpoint publication, pending-binding recovery, and key rotation into distinct authorization actions and witness actions. Rotation authorization binds the old/new key identities and predecessor checkpoint digest.
- Added an opaque, single-use `EmergencyAuthority` bound to the exact action, container identity and generation, boot, monotonic deadline, principal, policy digest, and deterministic operation ID. Emergency reconciliation now requires the exact request/operation and terminal event IDs in both the independent sink and main witness journal. Activation rejects unimplemented network and volume scopes.
- Replaced the append-path full mirror rewrite with incremental framed appends. Mirror failure preserves the already-durable mutation and creates a durable reader-stale marker. Read-only verification pins the opened length, bounds every frame, and validates journal ID, sequence continuity, and the full previous-record hash chain without taking the writer lock.
- Hardened recovery approval reads to use one held `O_NOFOLLOW` descriptor with owner/mode/type/link checks; retained sink identity correlation uses the activation-bound device and inode.

Fresh round-2 verification: `cargo check -p ferro-cli` passed; `cargo test -p ferro-cli --test witness_cli` passed 8/8; the mirror chain-corruption regression failed before the reader validation and passed after it. Repository-global `cargo fmt --check` remains unavailable as a completion gate because unrelated pre-existing files are not rustfmt-clean; no broad formatting rewrite was applied.

## Residual hardening

The incremental read mirror now rotates before a 128 MiB production bound into ordered read-only segments. The reader snapshots all segment descriptors plus the active descriptor, validates framing and journal identity for every part, and uses global sequence and record-hash continuity to reject missing, overlapping, reordered, or substituted evidence. Startup validates and reuses retained segments rather than deleting them or rebuilding overlapping evidence. A reduced test bound exercises multiple rotations, restart, complete streaming, and deletion-gap rejection without a 128 MiB allocation.

Production emergency activation, execution, and reconciliation now require the held sink file to prove Linux `FS_APPEND_FL` via `FS_IOC_GETFLAGS`; an unsupported filesystem or ordinary appendable file fails closed. Existing descriptor owner/mode/type/link and activation-bound device/inode checks remain mandatory. A regression test proves an otherwise valid preprovisioned file is rejected when the kernel append-only capability is absent.

The sink path now uses an explicit `AppendOnlySink` capability interface. `FsAppendOnlySink` retains the validated file descriptor through revalidation, header verification, append, and `fsync`; the deterministic backend verifies capability-denial behavior without weakening production. Linux `openat2` traversal from the root descriptor applies `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS` to sink, approval, and recovery-key opens, and production state directories must already exist with owner-only permissions. Ancestor and final-component symlink regressions are covered.

Emergency state and nonce persistence use a retained `SecureDirectory` descriptor. Reads are bounded `openat(O_NOFOLLOW)` operations; nonce creation is `O_EXCL`; state replacement is a same-dirfd temporary write, file `fsync`, `renameat`, and directory `fsync`; reconciliation uses `unlinkat` and directory `fsync`. A directory-replacement regression proves writes remain attached to the originally validated directory inode rather than a subsequently substituted path.

Final verification: `cargo check -p ferro-cli` passed; emergency hardening tests passed 6/6; `witness_cli` passed 8/8; and `FERROCRATE_SKIP_ROOT_TESTS=1 cargo test -p ferro-cli` passed all runnable CLI unit, integration, property, security, and documentation tests (five explicitly privileged container E2E cases remained ignored).

## Review hardening round 3

Admission evidence is described by a versioned `AdmissionSnapshotManifest` in a retained secure directory. It binds the generation, journal, exact trust/minimum/ordered-chain artifact names and SHA-256 digests, trust key IDs, and latest checkpoint time. The runtime performs bounded dirfd-relative reads and confirms the manifest bytes and generation did not change during loading. Checkpoint publication, pending-binding reconciliation, and key rotation append the newly bound checkpoint artifact and atomically advance the manifest.

Stale-checkpoint cleanup no longer depends on an action-name allowlist. Ordinary user stop and delete requests are denied like other mutations; checkpoint repair has a distinct authority class, and reserved cleanup requires an opaque internal `ReservedCleanupAuthority`.

Emergency commands now use one `EmergencyStateStore` holding the retained secure-directory descriptor for the complete read/transition/write or unlink transaction. State carries a monotonic generation, and every transition performs a generation CAS before the dirfd-relative atomic replacement. A stale concurrent transition is rejected.

Round-3 verification: admission and reserved-cleanup focused tests passed; emergency transaction tests passed 7/7; `witness_cli` passed 8/8 including atomic admission generation advancement; and the full runnable `ferro-cli` suite passed with `FERROCRATE_SKIP_ROOT_TESTS=1` (five privileged container E2E cases explicitly ignored).

## Executable Unix sink lifecycle

The explicit `filesystem|unix` sink selection now drives activation, execution, and reconciliation. Unix activation pins the endpoint, receipt public key, journal ID, and server UID. Each canonical activation/intent/outcome/reconcile record is sent with the expected sequence and head, and the returned signed receipt is exact-binding checked and CAS-persisted in the emergency state before the next transition. Execute and reconcile reconstruct their client from the pinned state after process restart; no path fallback exists. The service durably stores both canonical record bytes and their signed receipt, re-verifies their hash binding on restart, returns the same receipt for an identical retry, and rejects sequence/head forks and nonce/operation replay forks.

The feature-gated `test-console` target exists only to exercise local-console commands as unprivileged CI subprocesses; it does not replace the runtime executor. Its production-command E2E launches actual `ferro-cli emergency sink-serve` processes, uses an enforce policy plus Required journal and verifier-backed admission, proves an ordinary stop denial, rejects a forged receipt signer and an unavailable server, activates through the Unix sink, restarts every client and server process between transitions, performs an emergency-authorized stop of a real fixture process, requires exact main-witness correlation, keeps normal commands blocked until reconciliation, and proves the normal gate is restored afterward.

Verification: `cargo test -p ferro-cli --lib authorization_admin::emergency` passed 11/11 after the stored-record corruption regression was added; `cargo test -p ferro-cli --test witness_cli` passed 8/8; and `cargo test -p ferro-cli --features test-console --test emergency_unix_e2e` passed 1/1 using the real command dispatcher, Unix sockets, durable sink store, Required witness journal, admission artifacts, and runtime stop executor.

## Crash-recovery review closure

`IntentDurable` and `Unknown` are now resumable observation states. A retry never invokes the runtime executor again: it searches the Required journal for the one exact operation/action outcome, rejects multiple terminals, durably appends the recovered sink outcome, and advances to `Terminal`; absence of terminal evidence moves the grant to explicit quarantine. The process E2E now deliberately stops the sink after intent, lets the real runtime effect and witness outcome complete, observes the outcome append failure, restarts both processes, and proves recovery without replaying the stopped process.

Reconciliation advances to a CAS-persisted `Reconciled` marker after accepting the signed receipt and before unlink. A retry from that marker only performs the idempotent unlink and does not require a live sink. Activation authenticates a signed head query and initializes local sequence/head from the durable service, so a second complete grant on the same sink journal extends rather than forks the chain; the restart test now executes two full activation/execution/reconciliation lifecycles.

The sink restart loader is bounded to 128 MiB and validates canonical JSON byte form, nonce, transition vocabulary, action/resource bounds, and the transition operation derivation in addition to receipt signature and chain hashes. Store and signing-key opens use no-symlink `openat2` descriptors and validate owner, mode, type, size, and link count on the same descriptor. Secure admission directories and bounded artifact reads now enforce effective-UID ownership and safe modes. Added regressions cover oversized stores, stored-record corruption, symlinked store/key paths, writable store files, sequential lifecycles, outcome outage recovery, and reconciliation retry state.

Final review-fix verification: emergency tests 13/13, `witness_cli` 8/8, core authorization tests 63/63, and the real-process E2E 1/1.
