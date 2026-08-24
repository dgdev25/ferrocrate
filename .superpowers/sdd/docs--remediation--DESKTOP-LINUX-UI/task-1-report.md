# Item 1 — Streamed Logs Report

## Implementation

- Replaced the one-shot desktop `container_logs` action with a single active `ferro-desktop exec --follow` proxy path that accepts only `ferrocrate logs --follow` / `-f` requests.
- The proxy forwards child output incrementally and terminates the followed daemon process when the desktop-side client disconnects.
- Tauri starts/stops that bridge process and emits each received log line to React.
- React appends every line, pauses only the rendered slice while keeping the stream buffered, applies a client-side substring filter, and supports copy and text-file export.

## TDD evidence

### RED

1. `cargo test -p ferro-desktop follow_proxy_only_accepts_ferrocrate_logs_with_follow_flag -- --exact`
   failed as expected with `E0432`: `is_log_follow_command` was unresolved.
2. `PKG_CONFIG_PATH=/tmp/ferro-tauri-sysroot.v0bIly/root/usr/lib/x86_64-linux-gnu/pkgconfig:/tmp/ferro-tauri-sysroot.v0bIly/root/usr/share/pkgconfig cargo test log_follow_uses_the_desktop_exec_bridge -- --nocapture`
   failed as expected with `E0432`: `log_follow_command` was unresolved.

### GREEN

1. `cargo test -p ferro-desktop follow_proxy_only_accepts_ferrocrate_logs_with_follow_flag -- --nocapture`
   passed: 1 passed, 0 failed.
2. `PKG_CONFIG_PATH=/tmp/ferro-tauri-sysroot.v0bIly/root/usr/lib/x86_64-linux-gnu/pkgconfig:/tmp/ferro-tauri-sysroot.v0bIly/root/usr/share/pkgconfig cargo test log_follow_uses_the_desktop_exec_bridge -- --nocapture`
   passed: 1 passed, 0 failed.

## Required gates

- `cargo test -p ferro-desktop` — passed: 24 passed, 0 failed.
- `npm run build` from `apps/ferro-desktop-ui` — passed.
- `PKG_CONFIG_PATH=/tmp/ferro-tauri-sysroot.v0bIly/root/usr/lib/x86_64-linux-gnu/pkgconfig:/tmp/ferro-tauri-sysroot.v0bIly/root/usr/share/pkgconfig cargo build` from `apps/ferro-desktop-ui/src-tauri` — passed.

## Files changed

- `ferro-desktop/src/main.rs`
- `apps/ferro-desktop-ui/src-tauri/src/main.rs`
- `apps/ferro-desktop-ui/src/App.tsx`
- `apps/ferro-desktop-ui/src/types.ts`
- `.superpowers/sdd/docs--remediation--DESKTOP-LINUX-UI/task-1-report.md`

## Self-review and concerns

- The proxy is intentionally restricted to the known `ferrocrate logs --follow` daemon command; it does not create a general remote process-streaming surface.
- The UI permits one active follow operation, disabling conflicting container lifecycle actions until it ends or the user stops it.
- The required build and unit gates passed. A live daemon/container emitting one line per second was not available in this environment, so that acceptance scenario was not manually exercised here.
