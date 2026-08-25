# Windows backend remediation report

## Changed files

- `ferro-desktop/src/backend/mod.rs` — added a direct WSL Unix-socket transport over `wsl.exe`/`socat`, including duplex terminal transport and bounded HTTP requests.
- `ferro-desktop/src/backend/wsl2.rs` — aligned the default distro to Ubuntu, removed the unshipped relay lifecycle, and routed execution and transport to the guest socket.
- `ferro-desktop/src/main.rs` — forced named-pipe/default-distro requests directly through `wsl.exe` so they cannot select the desktop backend recursively.
- `ferro-desktop/tests/backend_contract.rs` — replaced relay/token expectations with direct WSL lifecycle, socket, transport, and tokenless-selection contracts.
- `ferro-cli/src/main.rs` — routed Windows CLI forwarding to the installed `ferrocrate` named pipe instead of an unprovisioned TCP listener.
- `scripts/install-windows.ps1` — introduced one shared Ubuntu distro setting, provisioned `socat`, configured the daemon socket, and started the direct WSL named-pipe proxy.
- `scripts/test-desktop-backend-contracts.sh` — tightened installer contracts for distro agreement, guest socket dependencies, and direct pipe routing.

## Red evidence

- `bash scripts/test-desktop-backend-contracts.sh` — failed with `missing shared Ubuntu distro default contract`.
- `CARGO_BUILD_JOBS=6 cargo test -p ferro-desktop --test backend_contract wsl2_uses_a_real_subprocess_lifecycle -- --exact` — failed because the backend started `ferrocrate-desktop-relay` and used no guest socket.
- `CARGO_BUILD_JOBS=6 cargo test -p ferro-desktop --bin ferro-desktop a_default_wsl_distro_forces_direct_guest_execution` — failed because `printf must-not-run-on-host` executed successfully on the host.

## Green evidence

- `bash scripts/test-desktop-backend-contracts.sh` — passed: `desktop backend provisioning contracts passed`.
- `CARGO_BUILD_JOBS=6 cargo test -p ferro-desktop` — passed: 62 tests, 0 failures (45 binary tests and 17 backend contracts).
- `CARGO_BUILD_JOBS=6 cargo check -p ferro-desktop -p ferro-cli --target x86_64-pc-windows-gnu` — passed.
- `git diff --check` — passed.

## Commit

- This report is part of the single `feat(backends): ...` commit; its final hash is returned in the task handoff and is obtainable with `git rev-parse HEAD` (a commit cannot embed its own hash without changing that hash).

## Concerns

- The Linux host can compile-check the Windows GNU target but cannot execute the WSL installer, named pipe, or `wsl.exe` transport; native Windows 11/WSL2 acceptance remains required.
- `Wsl2Config` retains the legacy public `relay_addr` and `relay_token` fields for source compatibility, but the direct socket backend intentionally ignores them and no token is required.

## Review round 1/5 — Important findings

### Changes

- Refactored Tauri registry login and network/volume mutations to emit `ferrocrate` CLI commands through the existing `exec -- ferrocrate ...` bridge. A clean WSL guest therefore needs only the `ferrocrate` executable already provisioned by `install-windows.ps1`; it no longer invokes an absent guest `ferro-desktop` for these operations.
- Added a cancelable response deadline for WSL socket requests. Response parsing runs in a worker, the caller waits at most five seconds, and timeout cancellation closes stdin and kills the owned `wsl.exe`/`socat` child. Long-lived terminal streams remain outside this request deadline.

### Red evidence

- `CARGO_BUILD_JOBS=6 cargo test --manifest-path apps/ferro-desktop-ui/src-tauri/Cargo.toml guest_proxy_builders_only_invoke_the_installed_ferrocrate_binary` — failed because registry login produced `program = "ferro-desktop"`.
- `CARGO_BUILD_JOBS=6 cargo test -p ferro-desktop --lib transport_response_timeout_returns_before_a_blocking_read_finishes` — failed after the full 200 ms blocking read, exceeding the 150 ms contract bound.

### Green evidence

- `CARGO_BUILD_JOBS=6 cargo test --manifest-path apps/ferro-desktop-ui/src-tauri/Cargo.toml` — passed: 46 tests, 0 failures.
- `CARGO_BUILD_JOBS=6 cargo test -p ferro-desktop` — passed: 63 tests, 0 failures (1 library timeout test, 45 binary tests, 17 backend contracts).
- `CARGO_BUILD_JOBS=6 cargo check -p ferro-desktop -p ferro-cli --target x86_64-pc-windows-gnu` — passed.
- `git diff --check` — passed.

### Additional concern

- `cargo check --manifest-path apps/ferro-desktop-ui/src-tauri/Cargo.toml --target x86_64-pc-windows-gnu` reaches the Tauri build script but cannot complete because `apps/ferro-desktop-ui/src-tauri/icons/icon.ico` is absent. This packaging input is outside the two backend findings; the portable Tauri tests and Windows backend/CLI source checks above pass.
