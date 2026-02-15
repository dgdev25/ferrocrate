# FerroCrate Desktop UI (MVP Scaffold)

This app is the initial Desktop UI scaffold for FerroCrate.

## Current status
- Tauri backend command bridge implemented.
- React frontend shell implemented.
- Runtime/containers/images read-only snapshot view implemented.
- Dark/light mode toggle with persisted theme preference implemented.
- UI tokens aligned to `docs/design/mockups/orca_style_guide.html`.

## Dev prerequisites
- Rust toolchain
- Node 20+
- Tauri build dependencies (per OS)

## Run locally
```bash
cd apps/ferro-desktop-ui
npm install
npm run tauri:dev
```

## Notes
- Backend currently shells out to `ferro-desktop` and `ferrocrate`.
- Next iteration should switch to fully typed parsing instead of raw stdout rendering.
