# Task 2 — Registry sign-in in title bar

## Outcome

Registry access now lives in the title bar immediately after the daemon pill. Signed-out users see a **Sign in** button; signed-in users see an initial avatar and their registry username. The Images overflow now contains only image actions.

## TDD evidence

### RED

1. `node --test src/registryAuth.test.mjs` failed after the compact title-bar label expectation was added:
   - expected: `alice`
   - actual: `Signed in to registry.example.com as alice`
2. The rendered account-control test then failed before the component was implemented:
   - expected `RegistryAccountControl` to be a function
   - actual: `undefined`

### GREEN

After implementing the compact label and rendered title-bar control:

```text
node --test src/registryAuth.test.mjs
2 passed, 0 failed

npm test
26 passed, 0 failed

npm run build
vite build succeeded
```

The focused production test renders both states with React SSR, asserting the real button’s signed-out accessible name and signed-in avatar/name markup. It does not inspect source text.

## Capability reachability

- The title-bar button opens the existing registry credentials dialog and refreshes its status.
- The existing **Check status**, **Login**, and **Logout** controls remain in that dialog.
- Startup status refresh remains in place, and successful login/logout still refresh the displayed account state.
- The Images overflow no longer offers registry access; its remaining actions are refresh, prune, and build.

## Files changed

- `apps/ferro-desktop-ui/src/App.tsx`
- `apps/ferro-desktop-ui/src/registryAuth.mjs`
- `apps/ferro-desktop-ui/src/registryAuth.d.mts`
- `apps/ferro-desktop-ui/src/registryAuth.test.mjs`
- `apps/ferro-desktop-ui/src/styles.css`
- `.superpowers/sdd/docs--remediation--DESKTOP-UX-SIMPLIFY/task-2-report.md`

## Self-review

- Preserved the Forge shell, existing tokens, registry command paths, and detailed dialog status copy.
- Kept the new control a native button with an accessible name and the established focus-visible styling.
- Used the established title-bar placement and visual tokens; no new design system was introduced.
- Verified the patch with `git diff --check`.
- Did not stage or alter the pre-existing changes in `docs/compatibility/parity-scoreboard.md`, `docs/evidence/docker-client-conformance/2026-08-23-parity-scoreboard.tsv`, or `scripts/dev-desktop.sh`.

## Concerns

- Vite reports its existing advisory that the minified JavaScript chunk is larger than 500 kB; the build succeeds.
- Validation covers real SSR output and the complete UI unit suite. A live Tauri click-through was not run in this environment.
