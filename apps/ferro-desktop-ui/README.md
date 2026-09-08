# FerroCrate Desktop UI

The production frontend is being integrated with the approved Folded Forge workspace design. Release qualification remains open in the active production roadmap.

## Current status
- Tauri backend command bridge implemented.
- React frontend shell implemented.
- Runtime/containers/images read-only snapshot view implemented.
- Dark/light mode toggle with persisted theme preference implemented.
- UI tokens aligned to the approved rust / patinated-steel workspace mockup and `.superdesign/design-system.md`.
- Action controls implemented for VM start/stop, image pull/remove/prune, container start/stop/remove/logs.
- Paid auth panel implemented:
  - backend endpoint configuration (`release_base_url`, `token_endpoint`)
  - secure session token storage via OS keyring
  - session/entitlement status summary
- Installer + doctor operations integrated:
  - run paid full-stack bootstrap from UI (dry-run and confirmed execution)
  - invoke `ferrocrate doctor` with `--fix/--bootstrap/--dry-run/--yes` controls
  - machine-readable doctor JSON surfaced in UI

## Dev prerequisites
- Rust toolchain
- Node 20.19+ or 22.12+
- Tauri build dependencies (per OS)

## Run locally
```bash
cd apps/ferro-desktop-ui
npm install
npm run tauri:dev
```

## Notes
- Backend currently shells out to `ferro-desktop` and `ferrocrate`.
- Backend uses keyring for secure token storage and reads/writes `~/.ferrocrate/desktop-ui-auth.json` for endpoint config.
