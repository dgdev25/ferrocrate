# Changelog

This file records release-level changes. Detailed implementation evidence lives
under `docs/evidence/`.

## Unreleased

- Rootless bind mounts and read-only root filesystems now execute inside a
  bubblewrap boundary when the host provides the required user and mount
  namespaces; unsupported hosts fail closed with diagnostics.
- Refreshed the ten-feature Ferrocrate-versus-Docker benchmark on Ubuntu
  26.04/kernel 7.0.0 with three median rounds and no skipped rows.
- Release-readiness verification continues to qualify rootful Linux, Docker API,
  OCI, CRI, security, and rootless prerequisite gates while keeping live eBPF
  published-port checksum delivery explicitly open.

Release dates and compatibility guarantees will be added once a license and
public release policy are approved.
