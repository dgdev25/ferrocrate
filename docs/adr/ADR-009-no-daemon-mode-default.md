# ADR-009: No Daemon Mode Default

## Status

**Accepted**

## Context

Traditional container runtimes run a persistent daemon:
- Docker: dockerd (120-180MB idle)
- containerd: containerd (30-50MB idle)
- Podman: No daemon by default

**Daemon Model Problems:**
1. **Resource waste**: Memory consumed even with zero containers
2. **State complexity**: Daemon holds container state; crash can orphan containers
3. **Attack surface**: Long-running privileged process is an attack target
4. **Debugging difficulty**: Daemon state differs from actual kernel state

**Daemonless Model (Podman approach):**
- CLI directly manipulates kernel resources
- State stored in filesystem (sqlite/json)
- No persistent privileged process
- Container processes survive CLI exit

**FerroCrate Requirements:**
- PERF-03: 0 MB idle memory
- PERF-05: <2 MB per-container overhead
- REL-01: Runtime crash does not kill containers

## Decision

**FerroCrate operates daemonless by default. Optional daemon mode for advanced use cases.**

Default Behavior:
1. CLI commands directly create/manage containers
2. State persisted to disk after each operation
3. No background process required
4. Container processes are direct children of PID 1 (via fork)

Optional Daemon Mode:
- `ferrocrate daemon` starts a management daemon
- Enables API server (Docker socket compatibility)
- Provides event streaming and real-time monitoring
- Uses <8 MB when idle (PERF-04)

## Consequences

### Positive

- **Zero idle memory**: Meets PERF-03 requirement exactly
- **No attack surface when idle**: No process running to attack
- **Crash resilience**: Container processes are independent
- **State transparency**: All state in files, easy to inspect
- **Resource efficiency**: Edge devices don't waste memory on daemons

### Negative

- **No event streaming**: Daemonless mode cannot push events
- **No socket API**: Docker-compatible socket requires daemon
- **Coordination complexity**: Multiple CLI calls need file locking
- **Startup latency**: Each CLI invocation has startup overhead (~5-10ms)

### Neutral

- **User expectation shift**: Users expect `systemctl start docker` equivalent

## Alternatives Considered

### Always Daemon (Docker Model)

**Pros:**
- Persistent API endpoint
- Real-time event streaming
- Lower per-command latency

**Cons:**
- Violates PERF-03 (0 MB idle)
- Persistent attack surface
- Crash can orphan containers
- Wastes resources on edge devices

**Decision**: Rejected. Zero idle memory is a core differentiator.

### Daemonless Only (No Daemon Option)

**Pros:**
- Simpler implementation
- No dual code paths
- Enforces resource efficiency

**Cons:**
- No Docker socket compatibility
- No real-time events
- Cannot support some orchestration tools

**Decision**: Rejected. Daemon mode needed for API compatibility and advanced features.

### Hybrid (Daemon On-Demand)

**Pros:**
- Starts daemon when needed
- Automatic shutdown when idle

**Cons:**
- Complex lifecycle management
- Race conditions on startup
- Unpredictable behavior

**Decision**: Rejected. Explicit daemon start is clearer and more reliable.

## Implementation Notes

**State Storage (Daemonless):**
```
/var/lib/ferrocrate/
├── containers/
│   └── <container-id>/
│       ├── config.json
│       ├── state.json
│       └── logs/
├── images/
│   └── <image-digest>/
└── networks/
    └── <network-name>/
```

**File Locking:**
```rust
use fs2::FileExt;

fn with_lock<T>(path: &Path, f: impl FnOnce() -> T) -> T {
    let lock_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path.join(".lock"))?;
    lock_file.lock_exclusive()?;
    let result = f();
    lock_file.unlock()?;
    result
}
```

**Daemon Mode API:**
```bash
# Start daemon (optional)
ferrocrate daemon --socket /var/run/ferrocrate.sock

# Docker socket compatibility
ferrocrate daemon --docker-compat --socket /var/run/docker.sock
```

## References

- [Podman Architecture](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)
- [Daemonless Container Management](https://developers.redhat.com/blog/2019/02/21/podman-and-buildah-for-docker-users)
- PRD Requirements: PERF-03, PERF-04, PERF-05, REL-01, CLI-02
