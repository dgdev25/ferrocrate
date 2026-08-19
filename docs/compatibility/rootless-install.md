# Rootless installation prerequisites

`scripts/rootless-install.sh` never escalates privileges or silently installs
host helpers. It reports the prerequisites that determine whether a rootless
deployment can be qualified:

- `newuidmap`, `newgidmap`, and `slirp4netns` availability. Each helper must
  resolve to a regular, non-symlink executable owned by root and not writable
  by group/other;
- a subordinate-ID range for the invoking user in `/etc/subuid` and `/etc/subgid`;
- a mounted cgroup-v2 hierarchy;
- enabled user namespaces; and
- a writable `XDG_RUNTIME_DIR`.

Use `--dry-run` to inspect the diagnostics and generated user unit without
writing files. Use `--strict` to fail before any installation or upgrade
mutation if one or more prerequisites are missing. Missing helpers still need
operator or distribution provisioning; the installer deliberately does not
invoke a package manager or `sudo`.

Bridge networking remains fail-closed by default. Pass
`--rootless-network` when installing or upgrading to persist
`FERROCRATE_ROOTLESS_NETNS=1` in the generated user service and opt into the
validated `slirp4netns` bridge path. The installer regression verifies both
the explicit opt-in and the default-disabled behavior.
