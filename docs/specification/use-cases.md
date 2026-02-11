# FerroCrate Use Cases

## Overview

This document details the primary use cases for FerroCrate, focusing on the most common workflows. Each use case includes preconditions, main flow, alternative flows, and system-level technical considerations.

---

## Use Case 1: Container Run

### UC-1: Run a Container Image

**Primary Actor:** Developer (Startup Steve, DevOps Dana)

**Goal:** Execute a container from an image with specified configuration.

**Trigger:** User invokes `ferrocrate run` command.

#### Preconditions
1. FerroCrate binary is installed and in PATH
2. User has appropriate permissions (rootless or rootful as needed)
3. Linux kernel 5.10+ is running
4. Required kernel features available: cgroups v2, namespaces, OverlayFS

#### Main Flow

```
1. User executes: ferrocrate run [OPTIONS] IMAGE [COMMAND] [ARG...]

2. CLI parses arguments and validates:
   - Image reference format (registry/image:tag)
   - Options syntax (--rm, -d, -p, -v, -e, etc.)
   - Command and arguments

3. Runtime performs pre-flight checks:
   3.1 Verify kernel version >= 5.10
   3.2 Verify cgroups v2 mounted at /sys/fs/cgroup
   3.3 Verify user namespace support
   3.4 Check available resources

4. Image resolution and acquisition:
   4.1 Check local store for image (/var/lib/ferrocrate/store/)
   4.2 If not present, resolve registry from image reference
   4.3 Fetch manifest from registry (OCI Distribution Spec)
   4.4 Download required layers (or lazy-pull manifest only)
   4.5 Verify content hashes (Blake3)
   4.6 Store layers in content-addressable store

5. Container creation:
   5.1 Generate container ID (or use --name)
   5.2 Create container state directory
   5.3 Prepare OCI runtime configuration:
       - User namespace with ID mapping (rootless)
       - Network namespace (bridge/host/none)
       - Mount namespace with OverlayFS
       - PID namespace
       - IPC namespace
       - UTS namespace
       - cgroup namespace
   5.4 Configure cgroups v2:
       - Create cgroup at /sys/fs/cgroup/ferrocrate/<id>/
       - Set memory.max (if --memory specified)
       - Set cpu.max (if --cpus specified)
       - Set pids.max (if --pids-limit specified)
   5.5 Prepare filesystem:
       - Mount OverlayFS with image layers as lower
       - Create writable upper layer
       - Apply volume mounts
       - Apply bind mounts
       - Apply tmpfs mounts
   5.6 Configure network:
       - Create veth pair (bridge mode)
       - Attach one end to ferro0 bridge
       - Move other end to container network namespace
       - Configure container IP and routes
       - Setup DNS resolution

6. Security configuration:
   6.1 Apply seccomp profile (default or custom)
   6.2 Drop all capabilities, add specified ones
   6.3 Set no-new-privileges flag
   6.4 Apply AppArmor/SELinux profile if available
   6.5 Configure read-only rootfs if specified

7. Container execution:
   7.1 Clone process with CLONE_NEW* flags
   7.2 In child process:
       - Set up namespaces
       - Configure UID/GID mapping
       - Pivot root to new rootfs
       - Drop privileges
       - Execute container command
   7.3 In parent process:
       - Record container PID
       - Start health check timer if configured
       - Stream logs if --follow or -d

8. Post-start:
   8.1 If --rm, mark for removal on exit
   8.2 If -d (detached), print container ID and return
   8.3 If attached, stream stdout/stderr to terminal
   8.4 Wait for container exit

9. Container exit:
   9.1 Capture exit code
   9.2 If --rm, remove container state and mounts
   9.3 Return exit code to user
```

#### Alternative Flows

**A1: Image Not Found in Registry**
```
4.3a. Registry returns 404
4.3b. Display error: "image not found: IMAGE"
4.3c. Exit with code 1
```

**A2: Insufficient Resources**
```
3.4a. Memory/CPU resources unavailable
3.4b. Display error with resource requirements
3.4c. Suggest alternatives (lower limits, wait for resources)
3.4d. Exit with code 1
```

**A3: Rootless Operation Failed**
```
7.1a. User namespace creation fails
7.1b. Check if kernel allows unprivileged user namespaces
7.1c. Suggest --rootful flag or sysctl adjustment
7.1d. Exit with code 1
```

**A4: Port Already in Use**
```
5.6a. Requested host port is bound
5.6b. Display error with conflicting process
5.6c. Suggest alternative port or stop conflicting container
5.6d. Exit with code 1
```

#### Postconditions
- Container process running in isolated namespaces
- Container state persisted in /var/lib/ferrocrate/containers/<id>/
- Logs streaming to configured destination
- Network connectivity established (if not --net=none)

#### Performance Targets
- Cold start (with image pull): < 5 seconds for 1GB image on 1Gbps link
- Warm start (cached image): < 100ms
- CLI response time: < 50ms to first output

---

## Use Case 2: Image Build

### UC-2: Build Container Image from Dockerfile

**Primary Actor:** Developer (Startup Steve, ML Marcus)

**Goal:** Create a container image from a Dockerfile.

**Trigger:** User invokes `ferrocrate build` command.

#### Preconditions
1. Dockerfile exists in specified context directory
2. Build context directory is accessible
3. Base images are accessible from registries
4. Sufficient disk space for build cache and output

#### Main Flow

```
1. User executes: ferrocrate build [OPTIONS] PATH | URL

2. CLI parses arguments:
   - Context path (local directory or git URL)
   - Dockerfile path (default: PATH/Dockerfile)
   - Tag(s) for output image (-t)
   - Build args (--build-arg)
   - Target stage (--target)

3. Build context preparation:
   3.1 If URL, clone git repository to temp directory
   3.2 Read .dockerignore and filter context files
   3.3 Compute context hash for cache lookup
   3.4 Create temp directory for build workspace

4. Dockerfile parsing:
   4.1 Read Dockerfile content
   4.2 Parse into instruction list:
       - FROM (with platform, AS stage name)
       - RUN (shell or exec form)
       - CMD, ENTRYPOINT
       - ENV, ARG
       - COPY, ADD
       - WORKDIR, USER
       - EXPOSE, VOLUME, LABEL
       - HEALTHCHECK
       - Multi-stage references (COPY --from)
   4.3 Validate instruction syntax
   4.4 Resolve ARG defaults and build-arg overrides

5. Build execution (per stage):
   5.1 FOR each stage in dependency order:

       5.1.1 Resolve base image:
           - Pull if not in local store
           - Verify platform compatibility
           - Extract to build workspace

       5.1.2 FOR each instruction in stage:

           A. FROM:
               - Already handled in 5.1.1

           B. RUN:
               - Compute instruction hash (command + layer state)
               - Check cache for matching layer
               - If cache hit: restore layer, skip execution
               - If cache miss:
                   - Create container from current state
                   - Execute command in container
                   - Commit filesystem changes as new layer
                   - Store layer in cache

           C. COPY/ADD:
               - Compute hash of source files + dest path
               - Check cache
               - If cache miss: copy files to layer
               - Handle ADD URL sources
               - Handle ADD tar extraction

           D. ENV/ARG:
               - Update build environment map
               - No layer created

           E. WORKDIR:
               - Create directory if not exists
               - Update working directory for subsequent instructions

           F. USER:
               - Update user for subsequent RUN instructions

           G. EXPOSE/VOLUME/LABEL:
               - Add to image metadata
               - No layer created

           H. HEALTHCHECK:
               - Parse health check command
               - Add to image config

           I. CMD/ENTRYPOINT:
               - Set in image config

       5.1.3 Stage complete:
           - Store stage image for COPY --from references
           - If target stage, mark as final output

6. Image finalization:
   6.1 Create image manifest (OCI v1.1 format)
   6.2 Create image config JSON:
       - Architecture, OS, Variant
       - Config (Env, Cmd, Entrypoint, etc.)
       - RootFS (layer diff IDs)
       - History (build metadata)
   6.3 Compute layer diff IDs (SHA256)
   6.4 Compress layers with zstd
   6.5 Store in local image store
   6.6 Apply specified tags

7. Output:
   7.1 Print image ID and tags
   7.2 Print build duration and cache statistics
   7.3 Clean up temp directories

8. Optional: Push to registry
   8.1 If --push flag, push to registry
   8.2 Handle authentication
   8.3 Upload layers and manifest
```

#### Alternative Flows

**A1: Dockerfile Syntax Error**
```
4.3a. Parser encounters invalid syntax
4.3b. Display error with line number and context
4.3c. Suggest fix if recoverable
4.3d. Exit with code 1
```

**A2: Base Image Pull Failure**
```
5.1.1a. Registry unreachable or image not found
5.1.1b. Display error with registry details
5.1.1c. Check alternative registries if configured
5.1.1d. Exit with code 1
```

**A3: RUN Command Failure**
```
B.RUNa. Command exits with non-zero code
B.RUNb. Display error output
B.RUNc. Option: --no-cache to retry
B.RUNd. Option: --keep-failed to inspect failed container
B.RUNe. Exit with code 1
```

**A4: Disk Space Exhausted**
```
5.1.2a. Layer creation fails due to disk space
5.1.2b. Clean up partial build artifacts
5.1.2c. Run `ferrocrate system prune` suggestion
5.1.2d. Exit with code 1
```

#### Postconditions
- Image stored in local store with specified tags
- Build cache updated for future builds
- Intermediate containers removed (unless --no-cache)

#### Performance Targets
- Build time within 15% of Docker BuildKit for equivalent Dockerfile
- Cache hit rate >90% for incremental builds
- Memory usage <2x final image size during build

---

## Use Case 3: Compose Up

### UC-3: Start Multi-Service Application

**Primary Actor:** Developer (Startup Steve), Platform Engineer (DevOps Dana)

**Goal:** Start a complete multi-service application defined in docker-compose.yml.

**Trigger:** User invokes `ferrocrate compose up` command.

#### Preconditions
1. docker-compose.yml or compose.yaml exists
2. All referenced images are accessible
3. Defined networks and volumes can be created
4. Port conflicts do not exist with running containers

#### Main Flow

```
1. User executes: ferrocrate compose up [OPTIONS] [SERVICE...]

2. Project initialization:
   2.1 Find compose file (docker-compose.yml, compose.yaml, or -f flag)
   2.2 Parse compose file (YAML)
   2.3 Load .env file for variable substitution
   2.4 Apply variable substitution: ${VAR:-default}
   2.5 Validate compose file schema
   2.6 Determine project name (directory name or -p flag)

3. Service resolution:
   3.1 Parse all service definitions
   3.2 Build service dependency graph (depends_on)
   3.3 Topological sort for start order
   3.4 Filter to specified services (if any)
   3.5 Apply profile filtering (--profile)

4. Resource creation:
   4.1 Create networks:
       - Default network: <project>_default
       - Custom networks from top-level networks:
         - Bridge driver
         - Custom subnet configuration
         - IPv6 enablement
   4.2 Create volumes:
       - Named volumes from top-level volumes
       - Local driver default
       - External volumes checked for existence

5. Service startup (in dependency order):
   5.1 FOR each service in order:

       5.1.1 Check depends_on conditions:
           - service_started: dependency running
           - service_healthy: dependency health check passing
           - service_completed_successfully: dependency exited 0

       5.1.2 Wait for dependencies:
           - Poll dependency status
           - Timeout after configured wait period
           - Fail if dependency unhealthy

       5.1.3 Pull/build image:
           - If image: pull from registry
           - If build: build from Dockerfile/context
           - Handle platform specification

       5.1.4 Create containers:
           - Apply replicas scaling (--scale)
           - Generate container names: <project>_<service>_<index>
           - Configure resource limits
           - Configure environment variables
           - Configure volume mounts
           - Configure network attachments
           - Configure port mappings
           - Configure health check

       5.1.5 Start containers:
           - Execute container run logic (UC-1)
           - Track container PIDs

6. Post-start:
   6.1 If -d (detached):
       - Print started services
       - Return to shell
   6.2 If attached:
       - Aggregate logs from all services
       - Stream to stdout with service prefixes
       - Handle Ctrl+C for graceful shutdown
       - Wait for all containers to exit

7. Health monitoring (background):
   7.1 Poll health check endpoints
   7.2 Update container health status
   7.3 Execute restart policy if unhealthy
   7.4 Emit events for orchestration
```

#### Alternative Flows

**A1: Dependency Not Met**
```
5.1.1a. Dependency service fails health check
5.1.1b. Wait for timeout period
5.1.1c. Log dependency failure
5.1.1d. Skip dependent service startup
5.1.1e. Continue with non-dependent services
```

**A2: Image Pull/Build Failure**
```
5.1.3a. Image not found or build fails
5.1.3b. Log failure with details
5.1.3c. Skip service and dependents
5.1.3d. Continue with unaffected services
```

**A3: Port Conflict**
```
5.1.4a. Requested port already bound
5.1.4b. Identify conflicting container
5.1.4c. Suggest port reassignment or conflict resolution
5.1.4d. Skip service or exit (configurable)
```

**A4: Graceful Shutdown (Ctrl+C)**
```
6.2a. User sends SIGINT
6.2b. Send SIGTERM to all containers
6.2c. Wait for graceful shutdown (stop_grace_period)
6.2d. Send SIGKILL to remaining containers
6.2e. Remove containers if --rm flag set
6.2f. Report shutdown summary
```

#### Postconditions
- All services running in containers
- Services discoverable by name via embedded DNS
- Networks and volumes created and attached
- Logs aggregating to configured output

#### Performance Targets
- Dependency resolution: <100ms
- Parallel service startup: start independent services concurrently
- Total startup: <30 seconds for typical 5-service app

---

## Use Case 4: AI Diagnostics

### UC-4: Analyze and Diagnose Container Issue

**Primary Actor:** Developer (all personas)

**Goal:** Get intelligent analysis of a container failure or anomaly.

**Trigger:** User invokes `ferrocrate ask` command or automated anomaly detection triggers.

#### Preconditions
1. AI features enabled (--no-ai not set)
2. Container exists (running or stopped)
3. Metrics and logs available for analysis
4. Network connectivity for Claude API (if complex case)

#### Main Flow

```
1. User executes: ferrorocrate ask "QUESTION" [--container ID]

2. Context gathering:
   2.1 Identify relevant containers:
       - Specified container
       - Or search by name/pattern from question
   2.2 Collect container state:
       - Exit code (if stopped)
       - OOM events from cgroups
       - Current resource usage
       - Configuration (limits, env, mounts)
   2.3 Collect container logs:
       - Last N lines of stdout/stderr
       - Error patterns (ERROR, FATAL, Exception, etc.)
   2.4 Collect metrics history:
       - CPU usage over time
       - Memory usage over time
       - Network I/O
       - Disk I/O
   2.5 Collect system context:
       - Host resource availability
       - Other container activity
       - Kernel events (dmesg)

3. AI complexity assessment:
   3.1 WASM model evaluates question complexity:
       - Simple: OOM, exit code, basic resource
       - Medium: multi-container, network, timing
       - Complex: multi-factor, architectural, security
   3.2 Route to appropriate AI backend:
       - Simple: WASM inference (<1ms)
       - Medium: Local LLM if available (~100ms)
       - Complex: Claude API via claude-flow (~2s)

4. Analysis execution:

   4.1 Simple (WASM):
       - Pattern match on known failure modes
       - Rule-based diagnosis
       - Generate explanation and recommendation

   4.2 Medium (Local LLM):
       - Build prompt with context
       - Execute local inference
       - Parse and validate response

   4.3 Complex (Claude API):
       - Build comprehensive context prompt
       - Route to claude-flow MCP
       - Spawn diagnostic agent if needed
       - Multi-turn analysis if required

5. Response generation:
   5.1 Structure analysis output:
       - Root cause (primary finding)
       - Contributing factors
       - Evidence (log excerpts, metrics)
       - Recommendations (ranked by impact)
       - Confidence level
   5.2 Generate decision ID for explainability
   5.3 Store analysis in decision log

6. Output:
   6.1 Display formatted analysis
   6.2 Provide follow-up commands:
       - `ferrocrate explain <decision-id>` for details
       - `ferrocrate apply <recommendation-id>` for auto-fix
   6.3 Optional: Store as learning pattern
```

#### Alternative Flows

**A1: No Container Found**
```
2.1a. Container ID/name not resolved
2.1b. Suggest similar container names
2.1c. Offer to analyze recent container events
2.1d. Prompt for clarification
```

**A2: Insufficient Data**
```
2.3a. Logs not available (rotated, disabled)
2.3b. Explain data limitations
2.3c. Provide best-effort analysis
2.3d. Suggest enabling verbose logging
```

**A3: AI Backend Unavailable**
```
4.2a. Local LLM not installed
4.3a. Claude API unreachable
4.*b. Fall back to WASM rule-based analysis
4.*c. Note degraded accuracy
4.*d. Suggest connectivity fix
```

**A4: User Opts Out**
```
1a. --no-ai flag detected
1b. Provide raw data dump instead
1c. Suggest manual analysis steps
1d. Skip AI processing entirely
```

#### Postconditions
- Analysis stored in decision log
- User has actionable recommendations
- Pattern learned for future similar issues

#### Performance Targets
- Simple analysis: <10ms (WASM only)
- Medium analysis: <500ms (local LLM)
- Complex analysis: <5s (Claude API)
- Accuracy target: >80% correct diagnosis

---

## Use Case Summary

| Use Case | Primary Actor | Complexity | Frequency |
|----------|--------------|------------|-----------|
| UC-1: Container Run | Developer | Medium | Very High |
| UC-2: Image Build | Developer | High | High |
| UC-3: Compose Up | Developer, DevOps | High | High |
| UC-4: AI Diagnostics | All Personas | High | Medium |

---

## Systems-Level Considerations

### Namespace Isolation Matrix

| Namespace | Purpose | Isolation Level |
|-----------|---------|-----------------|
| PID | Process IDs | Container sees PID 1 |
| NET | Network stack | Separate interfaces, routing |
| MNT | Mount points | Private mount tree |
| UTS | Hostname, domain | Container hostname |
| IPC | System V IPC, POSIX queues | Isolated IPC namespace |
| USER | User/Group IDs | UID/GID mapping for rootless |
| CGROUP | Cgroup root | Container cgroup hierarchy |

### Cgroups v2 Controllers

| Controller | Path | Purpose |
|------------|------|---------|
| memory | memory.max, memory.current | Memory limits |
| cpu | cpu.max, cpu.stat | CPU throttling |
| io | io.max, io.stat | Block I/O limits |
| pids | pids.max | Process count limit |
| freezer | cgroup.freeze | Pause/unpause |

### OCI Compliance Checkpoints

1. **Image Spec v1.1**: Manifest, config, layer formats
2. **Runtime Spec v1.2**: config.json, bundle structure, lifecycle hooks
3. **Distribution Spec v1.1**: Push/pull protocols, content discovery
