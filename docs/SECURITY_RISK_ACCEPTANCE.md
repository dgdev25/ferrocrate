# Security Risk Acceptance Register

Date: 2026-02-15
Owner: Platform Runtime Team

This register tracks known dependency advisories that are currently accepted with mitigation and a required revalidation deadline.

## RA-2026-001: `RUSTSEC-2025-0141` (`bincode` unmaintained via `ruvector-core`)
- Status: Accepted (temporary)
- Severity: Low (maintenance risk, no active CVE exploit advisory in current scan)
- Affected path: `ruvector-core` -> `bincode` v2
- Why not removed immediately:
  - `ruvector-core` currently has an unconditional `bincode` dependency.
  - Replacing `ruvector-core` requires broad `ferro-mind` vector-memory subsystem migration.
- Compensating controls:
  - Keep `ruvector-core` pinned to latest patch (`2.0.3`).
  - Continue `cargo audit` in CI and fail on new critical/high CVE advisories.
- Expiry / review date: 2026-05-15
- Required action by expiry:
  - Migrate off `ruvector-core` or upstream/fork patch to remove `bincode` dependency.

## RA-2026-002: `RUSTSEC-2025-0057` (`fxhash` unmaintained via `sled`)
- Status: Accepted (temporary)
- Severity: Low (maintenance risk)
- Affected path: `sled` -> `fxhash`
- Why not removed immediately:
  - `sled` is used by multiple core stores (`container_store`, `image_store`, `volume_store`).
  - Migration to a maintained backend (e.g., `redb` or sqlite) is non-trivial and touches runtime persistence logic.
- Compensating controls:
  - Existing storage operations are strongly typed and covered by workspace tests.
  - No direct exposure of this dependency to remote input parsing paths.
- Expiry / review date: 2026-05-15
- Required action by expiry:
  - Complete persistent-store backend migration plan and begin phased replacement of `sled`.

## RA-2026-003: `RUSTSEC-2024-0384` (`instant` unmaintained via `sled`)
- Status: Accepted (temporary)
- Severity: Low (maintenance risk)
- Affected path: `sled` -> `parking_lot` 0.11 -> `instant`
- Why not removed immediately:
  - Same migration constraint as RA-2026-002 (`sled` dependency chain).
- Compensating controls:
  - Same controls as RA-2026-002.
- Expiry / review date: 2026-05-15
- Required action by expiry:
  - Land `sled` replacement and remove transitive `instant` dependency.
