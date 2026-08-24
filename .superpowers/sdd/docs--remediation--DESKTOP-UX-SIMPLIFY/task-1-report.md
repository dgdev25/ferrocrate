# Task 1 report — Images table + pull dialog

## Implementation

- Replaced the raw Images JSON panel and permanently visible pull/remove/prune controls with one Images table (`Repository`, `Size`, `Created`, `In use`).
- Added the sole page primary action, `Pull image`, which opens a dialog containing the image reference input and pull status/progress text.
- Moved image removal to each row’s overflow menu and image pruning to the toolbar overflow. The toolbar also retains refresh, build-image, and registry-access capabilities; build and registry forms now open as dialogs.
- Added safe parsing and byte-size formatting for the `ferrocrate images --format json` snapshot output.

## Files changed

- `apps/ferro-desktop-ui/src/App.tsx`
- `apps/ferro-desktop-ui/src/styles.css`
- `apps/ferro-desktop-ui/src/imageView.mjs`
- `apps/ferro-desktop-ui/src/imageView.d.mts`
- `apps/ferro-desktop-ui/src/imageView.test.mjs`

## TDD evidence

### RED

Command:

```sh
cd apps/ferro-desktop-ui && npm test -- src/imageView.test.mjs
```

Observed result: 21 passing and 1 failing test. The new `images page presents a table, pull dialog, and overflow actions instead of permanent controls` test failed on the expected missing `const imageRows = useMemo(() => parseImageRows` assertion. This confirmed the existing UI was still the raw JSON/forms layout.

### GREEN

Command:

```sh
cd apps/ferro-desktop-ui && npm test -- src/imageView.test.mjs
```

Observed result: `# tests 22`, `# pass 22`, `# fail 0`.

## Build verification

Command:

```sh
cd apps/ferro-desktop-ui && npm run build
```

Observed result: Vite transformed 46 modules and completed successfully (`✓ built in 825ms`). Vite emitted its pre-existing-size-style warning that the minified JavaScript chunk is over 500 kB; it did not fail the build.

## Self-review

- The page has exactly one data table when images exist and a teaching empty state with a single Pull image CTA when it does not.
- Pull, remove, prune, build, registry login/logout/status, and image refresh remain reachable.
- The Forge shell and its design tokens remain intact; only the Images view and supporting styles were changed.
- `git diff --check` passed. The unrelated user changes listed in the remediation ledger were left untouched and will not be staged.

## Concerns

- The runtime pull command currently returns one final `CommandResult`, rather than streaming progress frames. The dialog provides immediate indeterminate progress and then displays the returned command output, but cannot show layer-by-layer progress without a backend event.
- This task deliberately did not change the existing app-wide raw runtime-error banner; friendly daemon/licensing error mapping remains a cross-cutting follow-up if not handled by another remediation item.
