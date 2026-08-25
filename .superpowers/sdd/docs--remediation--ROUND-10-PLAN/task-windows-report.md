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
