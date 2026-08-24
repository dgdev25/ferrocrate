# Task 2 report — Doctor completion and host copy

## Status

Complete. Doctor runs now close the run dialog from the completion-safe `finally` path. Successful runs mark focus pending, and a post-render effect focuses the results table after the dialog has closed. The results table accepts a ref and is programmatically focusable. The CLI platform-scope row now derives its copy from the compile target.

## RED evidence

- `node --test --test-name-pattern='Doctor results table accepts' src/systemPages.test.mjs`
  - Failed with `actual undefined` for the expected results-table ref, proving the table did not expose the requested focus target.
- `cargo test -p ferro-cli doctor_platform_scope_copy_names_the_current_host -- --exact`
  - Failed to compile with `cannot find function doctor_platform_scope_message`, proving host-derived platform copy was absent.

## GREEN evidence

- Focused UI regression: `node --test --test-name-pattern='Doctor results table accepts' src/systemPages.test.mjs` — 1 passed.
- Focused CLI regression: `cargo test -p ferro-cli doctor_platform_scope_copy_names_the_current_host` — 1 passed.
- Desktop suite: `npm test` — 80 passed, 0 failed.
- Desktop production build: `npm run build` — passed.
- Doctor CLI tests: `cargo test -p ferro-cli doctor_` — 7 passed, 0 failed.
- CLI build check: `cargo check -p ferro-cli` — passed.
- Patch whitespace: `git diff --check` — passed.

## Notes

- The desktop build retains the existing Vite warning for a JavaScript chunk over 500 kB and npm reports the existing `globalignorefile` configuration warning.
- Workspace-wide `cargo fmt --check` remains blocked by pre-existing formatting drift in files outside Task 2; the Task 2 Rust additions themselves match rustfmt output.
- Existing untracked files `docs/superpowers/plans/2026-08-24-desktop-followup.md` and `memory/bugfix-impact-20260824-2005.md` were not touched or staged.
