# Task 7 report: mediated container lifecycle

All eight container lifecycle mutations now normalize once, pass through the
authorization gate once, reserve durable state, consume an opaque authorized
request, record the effect observation, durably append a terminal witness, and
only then clear the reservation. Denials append a terminal denial and execute
no side effect. Disabled witness mode retains compatibility behavior.

Crash recovery enumerates journal pending operations and the independent
lifecycle-operation tree. Recovery uses action-specific process, freezer,
execution-generation, exec-result, run-resource, and deletion-tombstone facts.
Unapplied and failed runs are removed through a durable tombstone and cannot
leave phantom container records. Arbitrary caller-selected reconciliation is
excluded by opaque, recipe-bound recovery evidence.

Store updates during lifecycle operations use operation/generation CAS;
unconditional writers reject active reservations. Bind sources in enforce mode
must reside beneath configured `FERROCRATE_APPROVED_MOUNT_ROOTS` and are opened
with `openat2` beneath/no-magic-link/no-symlink resolution. Public proc-fd
sources remain rejected while the executor consumes retained runtime-owned
descriptors.

Pause, resume, stop, and kill persist their post-kernel state through an exact
operation/generation/pre-state CAS. A post-effect persistence ambiguity writes
`OutcomeUnknown` and retains the reservation for startup truth collection.
Recovery evidence construction and reconciliation are crate-private; the public
pending-operation view cannot mint a classification. Live run effects found
before an effect marker are quarantined with their provenance and reservation
intact rather than being mistaken for an unapplied candidate. Shadow mode binds
the same mount-root approval fact and records its hypothetical denial while
retaining compatibility execution.

The run, exec, and remove crash matrix uses an injected phase adapter which
returns before any later lifecycle or wrapper cleanup and then drops the daemon
handles. Fresh store and journal adapters are opened for recovery. This models
hard process loss while keeping the test deterministic, and covers all five
decision-to-clear durability boundaries (15 interruption/reopen cases).

Run and restart now use a supervised launch lease. The launcher installs
`PDEATHSIG(SIGKILL)`, obtains a pidfd, and stops before executing the workload.
The container record and lifecycle operation atomically bind the new PID and
kernel starttime before `SIGCONT` releases user code. Persistence failure kills
the stopped child. Real subprocess tests SIGKILL the daemon on both sides of
identity persistence for run and restart and prove that no workload marker can
execute early or survive as an unowned replacement.

The parent-death lease is reinstalled after all UID/GID/capability transitions
and the captured parent is checked again immediately before the launch stop.
The independent run resource journal now records the operation ID plus planned
and applied rootfs, mount, network, cgroup-generation, and process identities.
Writes use no-follow create, file fsync, atomic rename, and parent-directory
fsync. Startup consumes an incomplete resource journal even when a candidate
container record exists; it performs ownership-proven rollback and retains
unverifiable resources for operator repair. A real public-API subprocess matrix
SIGKILLs run and restart at network, cgroup, stopped-spawn, and durable-identity
barriers, then opens a fresh runtime and checks for replay and orphaned effects.

Resource recovery now uses closed `ResourcePlan` and `AppliedResource` variants
for bind mounts, tmpfs mounts, readonly-rootfs transitions, network allocations,
cgroups, and supervised processes. Applied path identities bind mount ID,
device, inode, and ownership generation. Recovery walks applied resources in
reverse order, reopens mount targets beneath the retained rootfs without
creating components, verifies the live identity, and uses deletion-only detached
unmounts. Exact PID/starttime and cgroup identities are verified before cleanup;
mismatches quarantine the ledger. `remove_dir_all` is forbidden while mountinfo
shows any live mount below the container directory, and the ledger is removed
only after the linked recovery witness is durable.

The effect-to-marker window is also classified from the durable plan. Mount
plans bind the pre-effect target mount ID/device/inode, bind-source identity,
expected tmpfs/readonly transition, operation ID, and generation. On reopen an
unchanged baseline is `NotApplied`; an exact planned transition is promoted to
trusted observed-applied cleanup; every other state is quarantined. Cgroup and
network plans bind their operation/allocation identities and classify an
unmarked live object conservatively. Dedicated kernel-effect barriers exist
immediately after bind, tmpfs, readonly, network, and cgroup syscalls and before
their applied marker.

Cleanup entry now mints a private `CleanupAuthority` only after validating one
operation ID and generation across every typed plan and applied index. A live
candidate must have matching pending state or creation intent and matching
runtime/journal/boot/resource provenance. With no candidate, the independent
lifecycle operation plus the retained provenance must match. Mixed IDs,
duplicate applied indexes, stale generations, legacy ledgers, and cross-runtime
replays are quarantined before any cleanup effect. Resource-ledger recovery now
runs before lifecycle reconciliation so the independent tombstone cannot be
acknowledged before cleanup consumes it.

Verification on 2026-08-15:

- `runtime_authorization`: 24 passed, including separately named required-mode
  evidence for all eight lifecycle actions and four post-effect
  persistence-failure/reopen cases, plus the 3x5 crash/reopen matrix.
- `witness_journal`: 28 passed; recovery entry is now private and exercised by
  runtime startup tests rather than the public integration API.
- `ferro-core --lib`: 275 passed, 1 ignored. Entitlement tests now serialize
  their process-global environment and the repeated full run is stable.
- Recovery API compile-fail doctest: passed.
- `cargo build -p ferro-core`: passed.
- Strict workspace dependency clippy remains blocked by pre-existing warnings
  in `ferro-net` and unrelated existing warnings in `ferro-core`; the Task 7
  store lint findings introduced in this round were corrected.
