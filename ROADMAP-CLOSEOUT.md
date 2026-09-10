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
- [x] S2: Finish the simpler launcher — preset-first setup, automatic ports/storage, Custom image, Advanced, clear labels, fresh defaults after success; verify all three presets and custom validation through the UI.
- [x] S3: Verify image-pull recovery — real pull/repeat/failure, malformed-response regression, honest unconfirmed result, original native failure qualification.
- [ ] S4: Exercise container lifecycle and port conflicts — start/stop/remove/prune, mappings/env/limits, named and bind storage, known/unknown conflicts, automatic alternatives and confirmed replacement; LOCAL016–044 and061–063.
- [x] S5: Repair and verify logs and terminals — idle stdin timeout, early-exit attached-state race, unsupported-options errors before upgrade, streams/filter/copy/export, terminal commands/resizing/retargeting; LOCAL045–063.
- [x] S6: Finish images, volumes and networks — digest usage, visible removal controls, in-use behavior, creation/validation/removal/prune and attachment protection; LOCAL064–090 resource journeys.
- [x] S7: Finish Compose and build workflows — valid/invalid files, build success/failure/retry, lifecycle/resource retention, stale inspector fix and target-switching; LOCAL071–077 and091–100.
- [x] S8: Close Fleet regressions with live evidence — roles, run/inspect/logs, deploy/rollback/revoke, stale selections, TTL and responsive controls; commit verified fixes and evidence.
- [x] S9: Finish shell, Doctor and responsive/accessibility checks — search/filter/navigation/focus/theme, offline/retry, Doctor toggles, daemon lifecycle, mobile controls and affected-route visual/performance gates; LOCAL001–015 and106–110.
- [ ] S10: Qualify account, registry, licensing and platform-only features — exercise all reversible local cases, provision isolated real integrations where available, retain explicit evidence for any required external credentials/native platform; LOCAL101–105 and111–123.
- [x] S11: Run final verification and clean up owned fixtures — rebuild every affected candidate, run regression/type/lint checks and final UI retests; stop only owned processes and remove only owned test resources after evidence capture.
- [x] S12: Reconcile and commit the roadmap and exact remaining work — merge all journey results, inspect evidence, commit all task changes with corresponding checked items, and report the exact completion state without inflating coverage.

### Final evidence and remaining acceptance

- S3/S4 pull behavior: malformed responses handled safely; actual pull/repeat/error and disabled-auto-pull missing-image rejection verified. LOCAL-026 and034 now pass. Container lifecycle/remove/prune, mappings, env, limits and conflict flows also pass; presets035–037 remain blocked by actual chown failures under the installed host profile.
- S5 terminal/logs/Inspect: idle timeout, FIFO ordering, retained PTY/socket EOF handles, early-ended race and unsupported override failure fixed. Actual normal/invalid shell detach, attached resize, retargeting, log-follow target switching, truncation/copy/export and Inspect User/Restart/mount fields all pass (045–063). S5 is checked for the current qualified scope.
- S6 image/volume/network: tagged usage, safe untag semantics, in-use deletion protection and unused pruning verified. Final prune removed three unused tagged images while retaining four used images. Volumes/networks created, validated, protected and removed through UI. Unsupported-capability085 is unreachable on this selected backend; rootless external attachment089 rejects before resource creation. Positive rootful attachment remains a separate host qualification.
- S7 Compose/build: chooser validation/errors, build success/failure/retry/history, service Logs targeting, lifecycle and resource retention pass. Browser directory-path076 is contract-qualified; genuine build-license denial077 and native picker094 are N/A on current Linux/browser routing. Native platform acceptance remains saved separately and is not claimed passed.
- S8 Fleet matrix and regression fixes remain committed; Fleet owned processes/stores are removed with ownership proof.
- S9 responsive/recovery:320px metric/card overflow fixed and five-width snapshots saved. Lighthouse Accessibility100/BestPractices100 and experimental label audit pass after accessible-name correction. Real degraded health fixture and initial60-second timeout→Retry recovery pass. Shared modal focus wrappers fixed Compose/Pull/resource/licensing families; actual Account/launcher/Compose/Doctor/Pull cycles pass, and final-resource-build-focus.json proves enabled Network/Volume/Build Tab/Shift+Tab wrap and Escape opener restoration. LOCAL010 and S9 now pass.
- S10 account/registry: actual private keyring persistence/delete/failure, signed-session save, rejected replacement preservation, registry login/reload/logout and visible validation errors pass. Strict auth response validation and corrected fixture startup were regression tested; final real gateway authentication and reload persistence passed account-strict-* evidence. Genuine issuer acquisition115 remains blocked; non-Linux installers118–120 and generic licensing121 are qualified N/A here, not passes.
- Administrative follow-up: actual PostgreSQL/Redis/Nginx entrypoints still fail chown. The privileged candidate AppArmor inheritance test and administrator profile install/load remain required, followed by real preset retests. Do not infer completion from preflight or the previous existing-profile run.
- S11 verification: 172 frontend tests, TypeScript, full lint/build, 50 Tauri unit tests plus genuine gateway/private-keyring checks pass. The full workspace checkpoint passed 2,411 tests and the strict warning gate; the later CLI-only digest regression also passed. UI cleanup removed all owned containers/volumes/images/custom network. Final cleanup confirms no owned processes or mounts remain, all fixture ports are closed, scopes are inactive, private credentials and temporary fixture directories are removed. See `final-cleanup.json`.

Final reconciled 123 rows: 106 passed, 6 passed with explicit contract qualifications, 7 current-platform N/A, 4 blocked (035–037 presets and115 issuer). No failed or not-run rows remain in this scoped tracker, but N/A and blocked work do not count as universal full-feature acceptance. S5/S6/S7/S9 are checked with those scope qualifications. S2/S4/S10 remain open for their listed acceptance. Source fixes are committed through `b4f4b71b`; this roadmap/evidence commit closes S11/S12 without marking the blocked acceptance complete.

All remaining recommendations, including privileged AppArmor test/load, preset retests, genuine issuer, native macOS/Windows chooser/keyring/installer/licensing and positive rootful network validation, are saved in [the standalone remaining qualification roadmap](docs/ROADMAP-FULL-UI-REMAINING-2026-09-08.md). Exact current rows are in remaining-journeys.md; no 100% claim is made.

## Closeout 2026-09-10 — Public repository readiness

Source: public-repo readiness analysis in the 2026-09-10 session (git history leaks, tracked internal files, tracked binaries, placeholder policy docs, dependency license gate, self-hosted runner exposure).
Done when: every box below is ticked and the test command below passes.
Test command: `cargo check --workspace --all-targets && cargo clippy --workspace --all-targets && cargo test --workspace --lib && cargo deny check licenses advisories && bash scripts/export-public-snapshot.sh --verify`

- [x] S1: Untrack local-only agent files — `memory/`, `prd2build.config.json`, `COORDINATOR-NOTE.md`, `lab/`, `.superdesign/tmp/` leave git but stay on disk; `.gitignore` covers them.
- [x] S2: Remove tracked binaries — Tauri sidecars under `apps/ferro-desktop-ui/src-tauri/binaries/` and `release-artifacts/` leave git; `scripts/bundle-sidecars.sh` and `release.yml` already regenerate them.
- [x] S3: Fix policy and metadata — `SECURITY.md` names GitHub private vulnerability reporting, `CHANGELOG.md` drops the "license not yet approved" note, every crate carries `license`/`repository`/`homepage` (five crates had no license field), README anchor verified valid (GitHub renders `--` as `----`; no change needed).
- [ ] S4: Rewrite the CLAUDE.md build section for Cargo — replace the npm build/test/lint block with the real Cargo and script commands.
- [ ] S5: Add a dependency license gate — `deny.toml` with an explicit allowlist and the bincode unmaintained advisory ignored with a reason; `cargo deny check licenses advisories` passes; CI dependency-policy step runs it.
- [ ] S6: Write `scripts/export-public-snapshot.sh` — builds a single-commit orphan `public` branch from `main`, excludes agent-only docs (handoffs, closeout roadmap), scrubs `/data/dev`, `/home/USER` and lab host addresses from evidence and bench results, and `--verify` fails on any leak or agent-state blob; ADR-018 records the snapshot-not-history-rewrite decision.
- [ ] S7: Publish — create the public repository from the `public` branch, enable private vulnerability reporting, require approval for all outside-collaborator workflow runs. Needs the user's go-ahead: outward-facing.
