# FerroCrate Monetization Plan and Implementation

## Objective
Implement enforceable monetization aligned to strategy:
- Public channel: `ferrocrate` CLI (free core)
- Paid channel: desktop and advanced AI capabilities

## Tier Model
- Free
  - Core CLI/runtime workflows
  - Basic/local AI workflows
- Pro
  - Desktop feature access
  - Advanced AI orchestration (`claude-flow` path)
- Enterprise
  - All Pro features
  - Reserved for future fleet/compliance/support feature flags

## Feature Flags
- `desktop`
- `ai_advanced`
- `ai_cloud`
- `fleet`
- `compliance`
- `priority_support`

## Enforcement Architecture
1. Signed entitlement file
- Path: `FERROCRATE_ENTITLEMENT_FILE` (default `~/.ferrocrate/entitlement.lic`)
- Public key env: `FERROCRATE_ENTITLEMENT_PUBKEY` (base64 ed25519 public key)
- Envelope JSON:
  - `payload`: base64(json `Entitlement`)
  - `signature`: base64(ed25519 signature over payload bytes)

2. Runtime checks
- CLI checks paid features at command boundary.
- Desktop daemon checks paid features before handling VM/daemon/forwarding commands.

3. Distribution defaults
- macOS installer defaults to CLI-only install.
- Desktop install/bootstrap is explicit opt-in (`--with-desktop-bin`, `--with-desktop-bootstrap`).

## What Is Implemented (Phase 1)
- New entitlement subsystem in `ferro-core` with signature verification and plan/feature resolution.
- CLI feature gates:
  - Desktop host-forward path requires `desktop` entitlement.
  - `ai orchestrate` requires `ai_advanced` entitlement.
  - New `ferrocrate entitlement status` command.
- Desktop feature gate:
  - `ferro-desktop` requires `desktop` entitlement for runtime commands.
- Installer defaults aligned to public CLI distribution.

## What Is Implemented (Phase 2)
- Channel-aware installers:
  - macOS: `--channel <public|paid>` with paid source override via `PAID_RELEASE_BASE_URL`
  - Windows: `-Channel <public|paid>` with paid source override via `-PaidReleaseBaseUrl` / `PAID_RELEASE_BASE_URL`
- Installers fail closed when desktop binary is explicitly requested but unavailable in selected channel artifacts.
- Channel-aware release packaging script:
  - `scripts/build-release-artifacts.sh --channel public|paid --version <tag>`
  - Public channel emits CLI-only artifacts and checksums.
  - Paid channel emits CLI + desktop artifacts and paid checksums.
- CI workflows for artifact generation:
  - `.github/workflows/release-public.yml`
  - `.github/workflows/release-paid.yml`
- CI release assertions:
  - `scripts/verify-release-channel-artifacts.sh` enforces:
    - public artifacts include `ferrocrate` and exclude `ferro-desktop`
    - paid artifacts include both `ferrocrate` and `ferro-desktop`
- Linux entitlement integration CI:
  - `ferro-cli/tests/entitlement_linux_integration.rs`
  - executed in `.github/workflows/rust-no-warnings.yml` on `ubuntu-latest`
- Paid installer smoke CI:
  - `.github/workflows/paid-installer-smoke.yml`
  - boots ephemeral paid gateway and validates paid-channel installer logic on `macos-latest` and `windows-latest`.

## What Is Implemented (Phase 3 - Bootstrap + Gateway Wiring)
- One-command paid bootstrap defaults:
  - `scripts/install-macos.sh --channel paid` now defaults to desktop binary install + VM bootstrap.
  - Added explicit `--full-stack` and `--cli-only` controls.
- Host dependency remediation in installer:
  - installs/validates `qemu`, `virtiofsd`, and `ssh` on macOS.
- Installer token flow for paid channel:
  - macOS and Windows installers support `PAID_RELEASE_TOKEN` and `PAID_RELEASE_TOKEN_ENDPOINT`.
  - Installers now also support session-based issuance via `PAID_SESSION_TOKEN`.
  - token exchange uses entitlement envelope file (`PAID_ENTITLEMENT_FILE`) and release tag header.
- Authenticated artifact host implementation:
  - `scripts/paid-artifact-gateway.py` provides:
    - `POST /v1/token` entitlement validation and short-lived token issuance.
    - `GET /v1/releases/<tag>/<asset>` bearer-token protected artifact delivery.
  - Auth modes: `session`, `entitlement`, `hybrid` with optional TLS/rate-limit/audit/revocation controls.
- CLI compatibility doctor command:
  - `ferrocrate doctor [--fix] [--bootstrap] [--json]` with macOS-focused checks for:
    - desktop binary presence
    - host dependencies (`qemu-img`, `qemu-system-*`, `virtiofsd`, `ssh`)
    - desktop VM running state
    - guest SSH reachability
    - guest ferrocrate runtime availability
  - `--bootstrap` can trigger full paid installer bootstrap path automatically when standard remediation is insufficient.

## Remaining Work (Phase 3)
- Entitlement issuance service and key management rotation policy hardening
- Offline enterprise license tooling and revocation strategy
- UI-level entitlement UX in desktop app (login/status/renewal)

## Entitlement Payload Example
```json
{
  "plan": "pro",
  "subject": "acme-corp",
  "issued_at": 1760000000,
  "expires_at": 1791536000,
  "features": ["desktop", "ai_advanced"]
}
```

## Operational Notes
- Free workflows do not require entitlement files.
- Paid features fail closed when entitlement is missing/invalid/expired.
- Error messages instruct operators to set entitlement env vars.
