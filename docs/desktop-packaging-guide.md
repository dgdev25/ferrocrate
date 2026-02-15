# Desktop Packaging and Autostart Guide

This guide documents the current host-side desktop packaging and lifecycle wiring for FerroCrate.

## Packaging Artifacts
### macOS `.app` + `.dmg`
Build release binary then package:

```bash
cargo build -p ferro-desktop --release
scripts/package-macos-app.sh
```

Outputs:
- `dist/macos/FerroCrate Desktop.app`
- `dist/macos/ferro-desktop.dmg`

### Windows `.msi`
Build release binary and package with WiX:

```powershell
cargo build -p ferro-desktop --release
scripts/package-windows-msi.ps1 -BinaryPath .\\target\\release\\ferro-desktop.exe -OutputDir .\\dist\\windows -ProductVersion 0.1.0
```

Outputs:
- `dist/windows/ferro-desktop-0.1.0.msi`
- `dist/windows/ferro-desktop.wxs`

## macOS Launch Agent
Generate a launchd plist:

```bash
cargo run -p ferro-desktop -- autostart install-macos --addr 127.0.0.1:4288
```

Default output path:
- `~/Library/LaunchAgents/io.ferrocrate.desktop.plist`

Load/start it:

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.ferrocrate.desktop.plist
launchctl enable gui/$(id -u)/io.ferrocrate.desktop
launchctl kickstart -k gui/$(id -u)/io.ferrocrate.desktop
```

## Windows Service Script
Generate PowerShell installer script:

```powershell
cargo run -p ferro-desktop -- autostart install-windows --addr 127.0.0.1:4288
```

Default output path:
- `%LOCALAPPDATA%\\ferrocrate\\install-ferro-desktop-service.ps1`

Run generated script in elevated PowerShell to register/start service.

## VM Image Update with Backup/Rollback Safety
Update VM disk image in-place with automatic backup:

```bash
cargo run -p ferro-desktop -- vm --state-file ~/.ferrocrate/desktop-vm.json update-image --image-path /path/to/new.qcow2
```

Behavior:
- Refuses update while VM is running.
- Creates backup next to current image as `*.qcow2.bak` unless `--no-backup` is set.
- Copies new image into configured VM disk path and resets state to initialized.

## Remaining Packaging Work
- Signing and notarization for macOS package distribution.
- Signing for Windows MSI and upgrade-code/versioning policy hardening.
- Release-channel update policy (stable/canary) and automated rollback orchestration.
