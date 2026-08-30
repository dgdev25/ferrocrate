# Closeout roadmaps — 2026-08-30

## S162

Source: `bench/tickets/S162.md` and the 2026-08-30 s161-162 boundary supplied by the user.
Done when: every box below is ticked and all acceptance commands pass.
Test command: `cargo test --workspace && scripts/verify-no-warnings.sh && scripts/docker-client-conformance.sh` in both modes, followed by `bash scripts/merge-gate.sh`.

- [x] S1: Map the bridge, Docker contracts, and failing cases — trace every frontend resource attribute to the classic executor and capture Docker's exact accepted values and diagnostics.
- [x] S2: Forward `shm-size` with Docker semantics — add a failing regression, implement the bridge handoff, verify, and commit separately.
- [x] S3: Forward cgroup and resource attributes with Docker semantics — add failing regressions, implement the bridge handoff, verify, and commit separately.
- [x] S4: Forward ulimit attributes with Docker semantics — add a failing regression, implement the bridge handoff, verify, and commit separately.
- [x] S5: Implement complete Docker-compatible invalid-option diagnostics — add failing diagnostic cases, implement validation, verify, and commit separately.
- [x] S6: Repair the dockerd forwarder if it blocks product verdicts — reproduce and fix the accept-loop crash only if encountered.
- [x] S7: Close S162 precisely and run every acceptance gate — update the boundary honestly, build the isolated release binary, run all requested gates, and commit the ticket closeout.

## S161

Source: `bench/tickets/S161.md`, especially the 2026-08-30 remaining boundary.
Done when: every box below is ticked and the S161 census plus merge gate pass.
Test command: `bash scripts/merge-gate.sh`

- [x] S1: Confirm upstream platform contracts — Recorded BuildKit's OS-version expression and multi-platform exporter/provenance behavior plus the local blast radius at upstream `2a684cd90798b5cade3cfef31b4981cf33920526`.
- [x] S2: Evaluate TARGETOSVERSION at the frontend boundary — Red/green regressions cover stage expansion, target image configuration, cache identity, and matching base OS-version inheritance.
- [x] S3: Represent supported multi-platform exporter metadata — Gateway/export regressions preserve `refs.platforms`, platform-scoped image configs, and duplicate native-platform reference maps while rejecting distinct targets the classic bridge cannot execute.
- [ ] S4: Close the S161 census and acceptance gates — Run the focused upstream census, all required conformance modes, and `scripts/merge-gate.sh`; close the ticket only if the remainder passes.
