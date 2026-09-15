# Contributing to Ferrocrate

Thanks for helping improve Ferrocrate. The project is currently Linux-first and
rootful by default; rootless, cross-distribution, and Docker-compatibility
claims must match `docs/FEATURE-MATRIX.md`.

## Before opening a change

- Read `CLAUDE.md` and the relevant design and security documentation.
- Keep changes focused and include a regression test for behavior changes.
- Do not commit credentials, generated runtime state, host captures, or private
  registry material.
- Preserve fail-closed behavior for unsupported host capabilities.

## Local verification

From the repository root, run the narrowest relevant tests first, then the
release gate when touching runtime, networking, CRI, compatibility, or release
behavior:

```bash
cargo test --workspace --all-features --offline
cargo clippy --workspace --all-features --all-targets --offline -- -D warnings
cargo deny check licenses advisories
bash scripts/verify-release-readiness.sh
```

Privileged and host-dependent checks must be run only on an approved disposable
Linux host. Record the distribution, kernel, architecture, backend, and any
explicit skips outside the public repository.

## Pull requests

Explain the user-visible behavior, security impact, test commands and results,
and any host or privilege assumptions. A change is not considered release-ready
until its advertised support scope has reproducible evidence.
