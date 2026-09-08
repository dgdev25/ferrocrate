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
- [x] S4: Close the S161 census and acceptance gates — The focused census retained S161 with a narrower boundary; warnings, both 85/85 client-conformance modes, and the merge gate pass, with the workspace's single filesync load flake audited and non-blocking.


## Closeout 2026-09-08 — Full UI testing and simpler setup

Source: user's full-feature Chrome DevTools UI test request, manual-configuration usability feedback, and live findings in `docs/evidence/verification/2026-09-08-full-ui/`.
Scope: the current desktop/browser and Fleet work; historical completed sections above remain unchanged.
Done when: every task below is checked, all applicable UI journeys have actual evidence, all discovered defects are fixed and retested, and verification passes. Blocked or untested integration journeys do not count as passed or 100% complete.
Test commands: `npm --prefix apps/ferro-desktop-ui test`, `npm --prefix apps/ferro-desktop-ui run typecheck`, `npm --prefix apps/ferro-desktop-ui run lint`, `npm --prefix apps/ferro-desktop-ui run build`; `cargo test -p ferro-cli -p ferro-desktop -p ferro-mgr`; Tauri backend tests/build for changed bridge code; final Chrome DevTools verification against rebuilt candidates.
Journey inventory: [all 123 local journeys](docs/evidence/verification/2026-09-08-full-ui/local-journeys.md), machine-readable `local-journeys.json`, area result files, and [Fleet checklist](docs/evidence/verification/2026-09-08-full-ui/fleet-checklist.md). `coverage-current.json` is the merged execution view. Every pending/partial/failed journey remains in scope; platform-specific checks must be explicitly qualified.

- [x] S1: Save the complete remaining scope and visible tracker — consolidate existing findings, pending journeys and acceptance gates in this dated section.
- [ ] S2: Finish the simpler launcher — preset-first setup, automatic ports/storage, Custom image, Advanced, clear labels, fresh defaults after success; verify all three presets and custom validation through the UI.
- [ ] S3: Verify image-pull recovery — real pull/repeat/failure, malformed-response regression, honest unconfirmed result, original native failure qualification.
- [ ] S4: Exercise container lifecycle and port conflicts — start/stop/remove/prune, mappings/env/limits, named and bind storage, known/unknown conflicts, automatic alternatives and confirmed replacement; LOCAL016–044 and061–063.
- [ ] S5: Repair and verify logs and terminals — idle stdin timeout, early-exit attached-state race, unsupported-options errors before upgrade, streams/filter/copy/export, terminal commands/resizing/retargeting; LOCAL045–063.
- [ ] S6: Finish images, volumes and networks — digest usage, visible removal controls, in-use behavior, creation/validation/removal/prune and attachment protection; LOCAL064–090 resource journeys.
- [ ] S7: Finish Compose and build workflows — valid/invalid files, build success/failure/retry, lifecycle/resource retention, stale inspector fix and target-switching; LOCAL071–077 and091–100.
- [ ] S8: Close Fleet regressions with live evidence — roles, run/inspect/logs, deploy/rollback/revoke, stale selections, TTL and responsive controls; commit verified fixes and evidence.
- [ ] S9: Finish shell, Doctor and responsive/accessibility checks — search/filter/navigation/focus/theme, offline/retry, Doctor toggles, daemon lifecycle, mobile controls and affected-route visual/performance gates; LOCAL001–015 and106–110.
- [ ] S10: Qualify account, registry, licensing and platform-only features — exercise all reversible local cases, provision isolated real integrations where available, retain explicit evidence for any required external credentials/native platform; LOCAL101–105 and111–123.
- [ ] S11: Run final verification and clean up owned fixtures — rebuild every affected candidate, run regression/type/lint checks and final UI retests; stop only owned processes and remove only owned test resources after evidence capture.
- [ ] S12: Reconcile and commit the completed roadmap — merge all journey results, inspect evidence, commit all task changes with corresponding checked items, and report the exact completion state without inflating coverage.

### Current findings that must close

- Pull handler dereferences null/malformed result (fixed in source; actual browser/native qualification remains).
- Compose Follow logs retains previous details/terminal/revealed environment (fixed in source; final UI retest remains).
- Tagged image usage misses digest-backed containers (fixed in source; live retest underway).
- Row action menus clipped by scroll containers and mobile CSS hides account/registry actions (fixed; affected controls retesting).
- Fleet retains revoked host selections and accepts unsupported login TTL (fixed; live Fleet evidence exists).
- Interactive terminal inherits five-second HTTP timeout (fixed CLI; final idle browser test remains).
- Terminal-ended can arrive before start reply and leave attached state (fixed handler; final UI retest remains).
- Unsupported terminal overrides are rejected after protocol upgrade (fix underway).
- Container launch uses ordinary 60-second browser timeout despite image downloads (fixed helper; real retest remains).
- Successful preset launch retains stale ports/volume and clears required generated credentials (fresh-draft fix underway).
- Development binary misses installed AppArmor profile; isolated candidate now runs under the existing profile, without policy changes, for preset qualification.
- In-use image removal and external-network attachment need disposition from actual backend semantics; no unsafe blanket prune before that check.
