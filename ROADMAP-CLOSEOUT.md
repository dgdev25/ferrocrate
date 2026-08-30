# Closeout roadmap — 2026-08-30

Source: `bench/tickets/S162.md` and the 2026-08-30 s161-162 boundary supplied by the user.
Done when: every box below is ticked and all acceptance commands pass.
Test command: `cargo test --workspace && scripts/verify-no-warnings.sh && scripts/docker-client-conformance.sh` in both modes, followed by `bash scripts/merge-gate.sh`.

- [x] S1: Map the bridge, Docker contracts, and failing cases — trace every frontend resource attribute to the classic executor and capture Docker's exact accepted values and diagnostics.
- [x] S2: Forward `shm-size` with Docker semantics — add a failing regression, implement the bridge handoff, verify, and commit separately.
- [ ] S3: Forward cgroup and resource attributes with Docker semantics — add failing regressions, implement the bridge handoff, verify, and commit separately.
- [ ] S4: Forward ulimit attributes with Docker semantics — add a failing regression, implement the bridge handoff, verify, and commit separately.
- [ ] S5: Implement complete Docker-compatible invalid-option diagnostics — add failing diagnostic cases, implement validation, verify, and commit separately.
- [ ] S6: Repair the dockerd forwarder if it blocks product verdicts — reproduce and fix the accept-loop crash only if encountered.
- [ ] S7: Close S162 precisely and run every acceptance gate — update the boundary honestly, build the isolated release binary, run all requested gates, and commit the ticket closeout.
