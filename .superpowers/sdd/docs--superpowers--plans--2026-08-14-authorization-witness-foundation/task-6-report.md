# Task 6 implementation report

## Outcome

Implemented explicit checkpoint trust, external Ed25519 key custody, durable flushed-head capture, bounded atomic checkpoint artifacts, trusted dual-sign rotation, explicit epoch discontinuities, pinned-minimum rollback detection, and checkpoint-age grace behavior. No CLI wiring, runtime mediation, journal reclamation, new cryptography, or dependencies were added.

## TDD evidence

- Red evidence: `task-6-red.txt` records the unresolved checkpoint/key/trust API imports before implementation.
- Green focused tests: 8 checkpoint integration tests, 25 journal integration tests, and 11 witness-vector tests pass.
- Tests cover owner-only key creation and stable public-key IDs, no-follow symlink rejection, bounded framed round trips, explicit trust roots, pinned-minimum truncation, captured flushed heads, dual-sign rotation, untrusted branches, explicit authorized trust reset, failed atomic replacement, and max-age/grace cleanup behavior.

## Implementation

- `KeyStore` stores raw Ed25519 signing material outside sled, uses unpredictable create-new temporary files, mode 0600, no-follow opens, file/directory owner validation, durable file sync, atomic hard-link publication, and parent sync. Key IDs are SHA-256 digests of public keys.
- `WitnessJournal::flushed_head` serializes against appends, flushes sled, and returns one captured `(journal_id, epoch, sequence, head)` value for signing.
- Checkpoint V1 uses fixed discriminants, big-endian integers, a domain separator, an 8-byte magic plus bounded length frame, canonical decode, and Ed25519 signatures.
- `CheckpointCoordinator` publishes by create-new temporary write, file fsync, rename, and parent-directory fsync. Failed replacement removes temporary data and leaves the prior target intact.
- `TrustBundle` requires an expected journal ID and pinned initial public key; a minimum retained checkpoint is signature-validated and cannot be satisfied by a shorter or conflicting branch.
- Rotation is signed by the currently trusted key and countersigned by the successor. Periodic checkpoints after rotation use the successor. Journal-discovered keys alone never establish trust.
- Key loss/rollback recovery requires an operator-authorized new-epoch public key and a signed trust-reset artifact naming the previous epoch. Reports count discontinuities explicitly.
- Integrity, lifecycle consistency, checkpoint completeness, tail freshness, and discontinuities remain separate report fields. Checkpoint-age plus grace stops user mutations while reserved cleanup stays available.

## Verification

- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo test -p ferro-core --test witness_checkpoint` — 8 passed.
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo test -p ferro-core --test witness_journal --test witness_vectors` — 36 passed.
- `LIBRARY_PATH="$PWD/.superpowers/toolchain/lib" cargo build -p ferro-core` — passed.
- `cargo clippy -p ferro-core --tests --no-deps -- -D warnings` reaches only pre-existing unrelated warnings in `runtime.rs` and `ai_runtime.rs`; Task 6 code emits none. Dependency-inclusive clippy additionally reaches pre-existing `ferro-net` findings.
- Task Rust files were formatted directly with `rustfmt`; repository-wide fmt is not a usable gate because it proposes unrelated pre-existing formatting changes.
- `git diff --check` and the task-local unsafe/credential/debug-output scan pass.
- Production files remain below 500 lines (`checkpoint.rs` 454, `keys.rs` 161).

## Scope notes

- Sealed segments remain retained under Task 5's no-reclaim posture; Task 6 adds no deletion or retention receipt.
- Publication-record binding is intentionally left to the later runtime/witness integration that can append the next canonical journal event; this task durably publishes the separate artifact first.
- CLI commands remain Task 10; the read-only core interfaces required by them are now available.

## Review fix round 1

Checkpoint verification now requires the actual ordered Task 5 record stream. It composes with `verify_stream`, validates every checkpoint's exact journal head against the supplied bytes, requires the immediately following closed `CheckpointPublished` journal event to bind the artifact digest, and refuses missing, corrupt, gapped, divergent, cross-journal, or reordered evidence. Pinned minima must occur on that exact verified ancestry; a higher sequence alone is insufficient.

Checkpoint artifacts now sign and frame first sequence, schema ID, hash-algorithm ID, and predecessor-checkpoint digest. Periodic/rotation checkpoints stay in one epoch; trust reset must be linked to a verified predecessor and advance exactly one epoch. A rotated-key minimum is accepted only after its dual-signed rotation lineage is verified from the independently pinned initial key.

Publication is fsynced before `WitnessJournal::append_checkpoint_publication` appends and flushes the next canonical event. The new closed action/stage validates a SHA-256 artifact digest and participates in normal stream sequence/hash verification. Freshness is an explicit Current/Stale/UnknownTail dimension, future timestamps are rejected, and grace evaluation rejects future checkpoint times.

Key custody now opens the private 0700-or-stricter owner directory once and performs key create/open/link/unlink relative to that descriptor with no-follow flags. It validates effective-UID ownership, exact file mode 0600, regular-file type, and link count one, rejecting public roots, symlinks, and hardlinks without path re-resolution after opening the directory.

Correction verification passes 11 checkpoint tests, 25 journal tests, 11 witness-vector tests, and the ferro-core build. New production files remain below 500 lines. Task-local clippy, formatting, diff, and disclosure scans are clean; only documented pre-existing unrelated warnings remain.

## Review fix round 2

Witness encoding is now explicitly V2 with epoch in the canonical bytes, parsed record, hash domain, stream trust, lifecycle binding, and journal-created records. Epoch changes cannot relabel old evidence, and journal sequence remains globally monotonic across the explicit durable epoch advance. Trust-reset publication is the first record in the new epoch while its signed discontinuity head names the authenticated final head of the predecessor epoch.

Periodic checkpoint creation now has `sign_after`; tests verify four linked checkpoints with periodic heads before and after a dual-signed key rotation. Checkpoint schema/domain/magic are V2. Checkpoint age is reported independently as Current/Stale, while tail freshness remains UnknownTail without a later independent anchor.

`verify_iter` accepts borrowed record bytes without cloning the journal payload. Verification builds one bounded evidence index and performs ordered epoch-group lifecycle/hash checks with globally contiguous sequences; checkpoint state is capped at 4096. Exact head/publication lookups are O(1), making the combined path O(records + checkpoints).

The coordinator now exposes one safe capture→artifact fsync/rename→journal bind/flush operation. It returns `PendingBinding` after post-publication journal ambiguity, and reconciliation is idempotent by event ID, epoch, stage, and artifact digest. Authenticated trust reset similarly publishes, durably advances epoch, and binds without resetting sequence.

Key roots use `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` from a trusted root anchor before descriptor-relative key operations. Publication uses the same component-safe resolution and descriptor-relative temporary creation/rename, and requires a pre-provisioned private effective-UID directory. Tests reject symlink ancestors, final symlinks, hardlinks, and public roots.

Round 2 verification passes 17 checkpoint tests, 25 journal tests, 12 witness-vector tests, and build. Task-local clippy/diff/format/security checks are clean; changed production modules remain below 500 lines except the pre-existing Task 5 journal coordinator file, whose Task 6 additions are narrowly scoped epoch assignments/state and do not add a second writer.

## Review fix round 3

Journal evidence verification is now a genuinely streaming state machine: each record is decoded, hash/lifecycle checked, and matched against an ordered bounded checkpoint cursor once. Epoch transitions are accepted only at the exact publication binding for an externally authorized TrustReset, advance exactly one epoch, and cannot return to an earlier epoch. The verifier requires the observed discontinuity count to equal the authorized lineage.

Pinned minima now identify the exact signed checkpoint artifact in the verified, publication-bound lineage, including epoch and artifact digest. Checkpoint age remains separate from an explicitly UnknownTail freshness result.

The coordinator owns deterministic PendingBinding identity and expected epoch/sequence, supports idempotent reconciliation, and provides safe periodic, trust-reset, and dual-signed rotation capture→publish→bind workflows. Raw artifact publication is crate-private.

Key creation now requires a pre-provisioned private root. Journal trees are explicitly V2, while discovery of V1 trees returns UnsupportedVersion with a migrate-or-new-epoch diagnostic instead of silently opening disjoint storage.

Round 3 focused verification passes 18 checkpoint tests, 26 journal tests, and 12 witness-vector tests.

## Review fix round 4

Trust bundles now explicitly pin genesis epoch 1, rejecting supplied lineages that begin at an arbitrary epoch. Stream verification has an operator-configurable record ceiling (default one million) in addition to the 4096-open-lifecycle ceiling, bounding the global duplicate-ID sets; larger retained ranges must be verified as independently anchored chunks.

After artifact fsync, the coordinator atomically persists a bounded, checksummed pending-binding frame containing the exact checkpoint and canonical publication record before attempting the journal append. Restarted coordinators discover and validate the sidecar against the artifact, reconcile without caller-held state, reject tampering and cross-journal replay, and remove the sidecar only after durable/idempotent binding. Only the journal's indeterminate post-append outcome is returned as PendingBinding; deterministic append failures remain explicit errors while the durable sidecar preserves recovery state.

Round 4 verification passes 21 checkpoint tests, 26 journal tests, 13 witness-vector tests, and the ferro-core build. Journal-root first creation remains a tracked Task 5 durability minor; Task 6 continues to require a pre-provisioned private checkpoint publication directory and key root.

## Final review fix round 5

Checkpoint publication now durably transitions `Prepared → Published → Bound`: the deterministic binding sidecar is fsynced before the artifact, reset epoch advancement occurs only after both durable Prepared and Published states, and Bound is fsynced before durable sidecar removal. Recovery safely republishes Prepared state, binds Published state, and idempotently finishes Bound state. A sidecar preflight rejects every new periodic, rotation, or reset workflow with `PendingExists` until recovery completes.

Linux sidecar create/read/replace/unlink operations are descriptor-relative beneath an `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` directory handle. Reads require O_NOFOLLOW, effective-UID ownership, regular type, mode 0600, link count one, and a hard byte bound. The checksum detects corruption only; trust continues to come from pinned checkpoint keys and journal identity. Recoverability is encoded separately from state; indeterminate append results remain recoverable, while definite nonretryable journal validation/configuration failures clear the sidecar and surface their exact error.

Bounded verification now supports an explicit independently trusted chunk boundary containing journal ID, epoch, first sequence, predecessor record hash, signed checkpoint artifact, and verifying key. Chunk checkpoints sign their actual first sequence. Genesis remains epoch 1, sequence 1, zero predecessor. Duplicate uniqueness is exact within each bounded chunk; continuity across chunks is supplied by the independently pinned predecessor hash and signed checkpoint commitment.

## Exceptional final trust correction

Every publication workflow now checks deterministic journal availability before preparing or replacing any artifact. A known Disabled journal therefore leaves an existing bound artifact untouched and creates no pending sidecar.

Definite nonretryable failures discovered after publication no longer erase their explanation. The coordinator durably transitions the sidecar to `BindingFailed` with `OperatorRequired` recoverability, preserves the unbound artifact, surfaces the terminal status after restart, blocks all new publications, and refuses ordinary reconciliation. This fail-closed state requires explicit operator quarantine handling rather than an automatic retry loop. The independently pinned chunk-boundary constructor also documents that all boundary tuple fields, signed artifact, and key must arrive out of band and never be learned from journal evidence.

Final correction verification passes 25 checkpoint tests, 26 journal tests, 13 witness-vector tests, and the ferro-core build.
