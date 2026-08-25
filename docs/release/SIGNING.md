# Release signing

Tag pushes matching `v*.*.*` build the five CLI targets and the Tauri bundles. The release workflow requires these repository secrets:

- `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, and `TAURI_UPDATER_PUBLIC_KEY`: minisign-compatible Tauri updater keypair. CI injects the public half into the release-only configuration before packaging.
- `OSX_CODESIGN_ROLE` and `CODESIGN_S3_BUCKET`: OIDC role and certificate bucket consumed by `block/apple-codesign-action`. The workflow builds unsigned, notarizes/signs, replaces the app and DMG, then rebuilds and signs the updater archive.
- `WINDOWS_PFX_BASE64` and `WINDOWS_PFX_PASSWORD`: Authenticode certificate and password used by `signtool.exe` for MSI and NSIS installers.

Never expose signing material through `VITE_*` variables. Canary values are searched recursively in every desktop bundle. Release assets include SHA-256 sums, per-archive provenance, GitHub artifact attestations, updater signatures, and `latest.json`.
