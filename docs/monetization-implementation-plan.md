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

## Remaining Work (Phase 3)
- Paid artifact hosting and authenticated download gateway wiring (installer token flow)
- Entitlement issuance service and key management rotation policy
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
