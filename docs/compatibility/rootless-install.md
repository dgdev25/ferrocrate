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

Rootless bridge networking is enabled by default for non-root callers and
fails closed with a capability diagnostic when the host cannot provide the
required namespaces. Set `FERROCRATE_ROOTLESS_NETNS=0` for an explicitly
network-isolated deployment. The `--rootless-network` installer option remains
available for compatibility and persists `FERROCRATE_ROOTLESS_NETNS=1` in the
generated user service; upgrades preserve an existing explicit setting.

## Optional IPv6 egress

Set `FERROCRATE_ROOTLESS_IPV6=1` to request slirp4netns IPv6 support. If the
host has a routed IPv6 address that should be used for outbound traffic, also
set `FERROCRATE_ROOTLESS_OUTBOUND_IPV6` to that address. Ferrocrate validates
the value and passes it as slirp4netns `--outbound-addr6`; it does not allocate
or route an address on the host. A host with only link-local IPv6 will therefore
remain unable to provide global IPv6 egress or published IPv6 traffic.
