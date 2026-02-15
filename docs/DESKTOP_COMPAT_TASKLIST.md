# FerroCrate macOS/Windows Compatibility Task List

Date: 2026-02-15
Primary reference: `docs/macos-windows-support-plan.md`

## Goal
Deliver practical macOS/Windows usability by keeping FerroCrate runtime Linux-only and adding a host proxy + Linux guest layer (WSL2/VM).

## Architecture Decision
- [x] ~~Confirm Linux-runtime-in-guest architecture (no native kernel-porting of cgroups/namespaces/seccomp)~~
- [x] ~~Confirm WSL2-first on Windows, VM layer on macOS~~
- [x] ~~Document that VM is security boundary~~

## Phase 0: Windows WSL2 First-Class (In Progress)

### P0-01 Host Proxy Hardening (`ferro-desktop`)
- [x] ~~Restrict daemon bind address to loopback by default~~
- [x] ~~Add `--allow-remote` explicit escape hatch~~
- [x] ~~Add request size limit for daemon input parsing~~
- [x] ~~Keep existing exec protocol backward-compatible~~

Evidence:
- `ferro-desktop/src/main.rs`

### P0-02 WSL2 Readiness and Diagnostics
- [x] ~~Add structured phase readiness command (`phase0-check`)~~
- [x] ~~Detect WSL distro availability and selection~~
- [x] ~~Probe selected guest for kernel + `ferrocrate` binary presence~~
- [x] ~~Add machine-readable JSON output option~~

Evidence:
- `ferro-desktop/src/main.rs`

### P0-03 Basic Test Coverage
- [x] ~~Add tests for loopback binding policy~~
- [x] ~~Add tests for command validation~~
- [x] ~~Add tests for phase0-check path on current host~~

Evidence:
- `ferro-desktop/src/main.rs`

### P0-04 Remaining Phase 0 Gaps
- [x] ~~Add Windows named-pipe listener option in `ferro-desktop` (instead of TCP only)~~
- [x] ~~Add `ferro-cli` Windows forwarding mode to call `ferro-desktop` automatically~~
- [x] ~~Implement host<->WSL port-forward manager for `-p` parity~~
- [x] ~~Add integration tests on Windows runner (`exec`, `phase0-check`, WSL forwarding)~~

## Phase 1: macOS VM Layer
- [x] ~~Select backend (QEMU/HVF first, AVF follow-up)~~
- [x] ~~Add VM lifecycle command scaffolding in `ferro-desktop` (`vm init/start/stop/status`)~~
- [x] ~~Add persistent VM state/config file support and QEMU command builder~~
- [x] ~~Add VM image build scaffold script (`scripts/build-desktop-vm-image.sh`)~~
- [x] ~~Build reproducible minimal Linux VM image containing ferro runtime + deps~~
- [x] ~~Implement host proxy bridge to guest API socket~~
- [x] ~~Implement virtiofs mounts and host port forwarding~~
- [x] ~~Add macOS CI integration test lane~~

## Phase 2: Windows Hyper-V Parity (Optional)
- [ ] Add Hyper-V backend if WSL2 path is insufficient for enterprise policy constraints
- [ ] Reuse Linux VM image + proxy protocol from macOS path

## Phase 3: Packaging & UX
- [x] ~~Windows MSI installer + service wiring~~
- [x] ~~macOS package + launch agent wiring~~
- [x] ~~Auto-start/runtime lifecycle management in host daemon~~
- [x] ~~Upgrade and rollback-safe VM image updates~~

Evidence:
- `ferro-desktop/src/main.rs` (`autostart` command family; `vm update-image`)
- `docs/desktop-packaging-guide.md`
- `scripts/package-macos-app.sh`
- `scripts/package-windows-msi.ps1`
- `.github/workflows/desktop-packaging.yml`

## What Not To Do
- [x] ~~Do not port Linux isolation primitives directly to native macOS/Windows runtime paths~~
- [x] ~~Do not block Phase 0 on GUI/Desktop UX~~
