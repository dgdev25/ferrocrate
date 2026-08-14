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

Verification on 2026-08-14:

- `runtime_authorization`: 9 passed.
- `witness_journal`: 30 passed.
- `ferro-core --lib`: 259 passed, 1 ignored.
- `cargo build -p ferro-core`: passed.
- Strict workspace dependency clippy remains blocked by pre-existing warnings
  in `ferro-net` and unrelated existing warnings in `ferro-core`; the Task 7
  store lint findings introduced in this round were corrected.
