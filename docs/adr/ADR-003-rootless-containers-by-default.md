# ADR-003: Rootless Containers by Default

## Status

**Accepted**

## Context

Traditional container runtimes (Docker, early containerd) require a daemon running as root. This creates a significant attack surface:

**Security Risks of Root-based Containers:**
- Container escape grants immediate root access to host
- Daemon vulnerabilities expose entire system
- Privileged containers can modify host kernel parameters
- Setuid binaries in containers can escalate privileges

**Rootless Container Mechanisms:**
- User namespaces: Map container UID 0 to unprivileged host UID
- Subordinate UID/GID ranges: `/etc/subuid` and `/etc/subgid` allocation
- cgroups v2 delegation: Allow unprivileged users to manage cgroups
- Rootless OverlayFS: FUSE-based or kernel support (5.11+)

**Industry Trend:**
- Podman made rootless a primary feature
- Docker added rootless mode (requires explicit configuration)
- containerd added nerdctl with rootless support
- Kubernetes supports rootless via user namespaces (beta in 1.25+)

Target users (from PRD):
- Security Sarah: Rootless by default is a primary requirement
- DevOps Dana: Wants reduced attack surface for compliance
- Startup Steve: Should not need to understand root vs rootless

## Decision

**Containers run rootless by default. No root daemon required.**

Implementation:
1. User namespace mapping configured automatically on first run
2. Subordinate ID ranges allocated from `/etc/subuid`, `/etc/subgid`
3. cgroups v2 delegation set up via systemd user session
4. Rootless OverlayFS for storage (kernel 5.11+) or FUSE fallback
5. Network namespace created without root via `slirp4netns` or similar

Users may opt into rootful mode via explicit `--rootful` flag for:
- Binding to privileged ports (<1024)
- Accessing host devices directly
- Performance-critical networking (rootless has ~10% network overhead)

## Consequences

### Positive

- **Security**: Container escape does not grant host root access
- **Compliance**: Meets security requirements without special configuration
- **Multi-tenancy**: Unprivileged users can run containers (shared development servers)
- **No setuid binary**: FerroCrate binary itself does not require setuid

### Negative

- **Network performance**: Rootless networking has ~10% overhead vs root-based bridge
- **Port binding**: Cannot bind to ports <1024 without explicit rootful mode
- **Storage complexity**: Rootless OverlayFS requires newer kernel (5.11+) or FUSE
- **Setup requirements**: Requires `/etc/subuid`, `/etc/subgid` configuration

### Neutral

- **User education**: "Rootless by default" differs from Docker expectations; requires documentation

## Alternatives Considered

### Rootful by Default (Docker-compatible)

**Pros:**
- Identical behavior to Docker
- No network performance penalty
- Simpler storage (standard OverlayFS)
- No subordinate ID setup required

**Cons:**
- Major security vulnerability for default usage
- Does not meet Security Sarah's requirements
- Requires root for all container operations

**Decision**: Rejected. Security is a core value proposition; rootful as default contradicts this.

### Rootless Optional (Flag Required)

**Pros:**
- Docker compatibility for users who expect rootful
- Simpler initial setup

**Cons:**
- Most users run default (insecure) configuration
- Security requires explicit opt-in (often skipped)
- Does not differentiate from Docker

**Decision**: Rejected. Security should be the default, not an option.

## Implementation Notes

**Subordinate ID Setup:**
```bash
# /etc/subuid
username:100000:65536

# /etc/subgid
username:100000:65536
```

**cgroups v2 Delegation:**
```bash
# Via systemd user session
systemctl --user daemon-reload
# Delegates to /sys/fs/cgroup/user.slice/user-$(id -u).slice/
```

**User Namespace Mapping:**
```
uid map: 0 (container) -> 100000 (host) + 65536 range
gid map: 0 (container) -> 100000 (host) + 65536 range
```

**Required Kernel Features:**
- `CONFIG_USER_NS=y`
- `CONFIG_OVERLAY_FS=y` (5.11+ for unprivileged)
- `CONFIG_FUSE_FS=y` (fallback)

## References

- [Rootless Containers](https://rootlesscontaine.rs/)
- [Podman Rootless](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)
- [Linux User Namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- PRD Requirements: SEC-01, SEC-04, SEC-06
