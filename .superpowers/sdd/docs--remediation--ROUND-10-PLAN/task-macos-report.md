# macOS backend remediation report

## Changed files

- `ferro-desktop/src/backend/macos_vm.rs` — aligned runtime defaults with the installer VM state, user, key, and ports; launched the provisioned VM state; replaced the nonexistent relay with direct SSH forwarding to the guest daemon Unix socket; and reported the guest socket path.
- `ferro-desktop/src/main.rs` — added explicit QEMU TCG backends for hosts without HVF and reserved the QEMU host API port for the SSH Unix-socket tunnel.
- `ferro-desktop/tests/backend_contract.rs` — added portable macOS layout/lifecycle/socket contracts and replaced obsolete relay expectations.
- `scripts/install-macos.sh` — unified canonical VM overrides, added vfkit DHCP/SSH reachability, selected TCG without HVF, provisioned and enabled the guest daemon service, and forwarded the daemon Unix socket directly over SSH.
- `scripts/test-desktop-backend-contracts.sh` — tightened macOS provisioning contracts for shared configuration, vfkit reachability, daemon supervision, direct socket forwarding, and software emulation.

## Red evidence

- `bash scripts/test-desktop-backend-contracts.sh` — failed first with `missing guest daemon socket contract`, then exposed the missing vfkit DHCP reachability and canonical runtime override contracts.
- `CARGO_BUILD_JOBS=6 cargo test -p ferro-desktop --test backend_contract macos_vm_prefers_vfkit_and_stops_the_owned_vm -- --exact` — failed because the backend passed a desktop state file to `--config` and launched the nonexistent `ferrocrate-desktop-relay`.
- `CARGO_BUILD_JOBS=6 cargo test -p ferro-desktop --bin ferro-desktop qemu_tcg_fallback_does_not_require_hvf` — failed because `qemu-tcg-x86_64` was unsupported.
- `CARGO_BUILD_JOBS=6 cargo test -p ferro-desktop --bin ferro-desktop qemu_reserves_only_ssh_for_the_guest_socket_tunnel` — failed because QEMU also bound port 4288, conflicting with the required SSH socket tunnel.

## Green evidence

- `bash -n scripts/install-macos.sh && bash scripts/test-desktop-backend-contracts.sh` — passed: `desktop backend provisioning contracts passed`.
- `CARGO_BUILD_JOBS=6 cargo test -p ferro-desktop` — passed: 66 tests, 0 failures (1 library, 47 binary, 18 backend contracts).
- `git diff --check` — passed.
- `CARGO_BUILD_JOBS=6 cargo check -p ferro-desktop --target x86_64-apple-darwin` — attempted but host-blocked before FerroCrate checking: Linux `cc` rejects Apple `-arch` and `-mmacosx-version-min` flags because no Apple SDK/cross C toolchain is installed.

## Commit

- This report is part of the single `feat(backends): ...` commit; the immutable final hash is returned in the task handoff and is obtainable with `git rev-parse HEAD`.

## Concerns

- This Linux host cannot execute vfkit, QEMU/HVF, macOS DHCP lease discovery, Homebrew provisioning, or the native SSH tunnel. Native macOS acceptance remains required.
- vfkit is selected only when Apple virtualization is available and the operator supplies the required kernel/initrd bundle; otherwise the installer uses accelerated QEMU or explicit TCG software emulation.
