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

Verification on 2026-08-15:

- `runtime_authorization`: 24 passed, including separately named required-mode
  evidence for all eight lifecycle actions and four post-effect
  persistence-failure/reopen cases, plus the 3x5 crash/reopen matrix.
- `witness_journal`: 28 passed; recovery entry is now private and exercised by
  runtime startup tests rather than the public integration API.
- `ferro-core --lib`: 269 passed, 1 ignored. Entitlement tests now serialize
  their process-global environment and the repeated full run is stable.
- Recovery API compile-fail doctest: passed.
- `cargo build -p ferro-core`: passed.
- Strict workspace dependency clippy remains blocked by pre-existing warnings
  in `ferro-net` and unrelated existing warnings in `ferro-core`; the Task 7
  store lint findings introduced in this round were corrected.
