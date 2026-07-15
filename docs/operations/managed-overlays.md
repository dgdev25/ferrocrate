# Managed overlays

The manager, agent, and `ferro-netd` helper form the managed-overlay control plane.

## Required manager configuration

`FERROCRATE_CLUSTER_ID` identifies the cluster. `FERROCRATE_MANAGER_SIGNING_KEY` is a base64-encoded 32-byte Ed25519 seed used only for desired-state signatures. `FERROCRATE_MANAGER_TLS_CERT` and `FERROCRATE_MANAGER_TLS_KEY` configure server TLS. `FERROCRATE_NODE_CA_CERT` and `FERROCRATE_ADMIN_CA_CERT` configure the separate node-control and administrator trust roots. `FERROCRATE_MANAGER_DB` selects the SQLite state path.

The enrollment listener serves `FERROCRATE_MANAGER_ADDR` (default `127.0.0.1:50051`). Node-mTLS control serves `FERROCRATE_CONTROL_ADDR` (default `127.0.0.1:50053`). Administrator mTLS serves `FERROCRATE_ADMIN_ADDR` (default `127.0.0.1:50052`).

## Required netd configuration

`FERROCRATE_AGENT_UID` must match the unprivileged agent UID. `FERROCRATE_NETD_SIGNING_KEY` is the manager desired-state verification key. `FERROCRATE_CLUSTER_ID`, `FERROCRATE_NODE_ID`, and `FERROCRATE_NETD_SOCKET` are required. `FERROCRATE_NETD_STATE` enables the mode-0600 ownership journal. `FERROCRATE_NETD_WG_PRIVATE_KEY_PATH` and `FERROCRATE_NETD_WG_LISTEN_PORT` enable WireGuard programming.

The helper authenticates Unix peer credentials before decoding frames, requires signed leases and monotonic revisions, and restricts runtime capabilities after binding its socket.

## Recovery

Stop the manager before restoring a backup. Restore to a new path with `ferro_mgr::recovery::restore_backup`; the operation verifies SQLite integrity, advances the cluster epoch, expires tokens, revokes active node records, and writes a recovery audit row. Never replace the live database in place.

After a netd restart, its ownership journal is reconciled against current kernel interfaces. Missing records are discarded; repeated remove operations are safe.

## Release gates

Run `scripts/test-managed-overlay.sh` from the repository root. The script always runs the manager, netd, core, and CLI focused tests. Its privileged section additionally requires root, a configured test interface, and a configured WireGuard key path; it refuses to guess those values.
