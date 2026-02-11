# FerroCrate Pseudocode

**SPARC Phase:** Pseudocode
**Version:** 1.0
**Date:** February 11, 2026
**Status:** Draft

---

## 1. Container Creation Flow

### 1.1 High-Level Algorithm

```
FUNCTION create_container(image_ref, config) -> ContainerID
    INPUT:
        image_ref: Image reference (e.g., "alpine:latest")
        config: Container configuration (env, mounts, network, etc.)
    OUTPUT:
        ContainerID on success, Error on failure

    // Step 1: Validate and resolve image
    image_manifest = RESOLVE_IMAGE(image_ref)
    IF image_manifest IS Error:
        RETURN Error("Image not found: " + image_ref)

    // Step 2: Generate unique container ID
    container_id = GENERATE_UUID()
    container_dir = CONTAINER_BASE + "/" + container_id

    // Step 3: Prepare container rootfs
    rootfs_path = PREPARE_ROOTFS(container_id, image_manifest)
    IF rootfs_path IS Error:
        RETURN Error("Failed to prepare rootfs")

    // Step 4: Create container configuration
    container_config = MERGE_CONFIGS(image_manifest.config, config)
    container_config.id = container_id
    container_config.created = CURRENT_TIMESTAMP()
    container_config.status = "created"

    // Step 5: Setup namespaces (without entering them)
    namespaces = PREPARE_NAMESPACES(container_config)
    IF namespaces IS Error:
        CLEANUP(container_dir)
        RETURN Error("Namespace setup failed")

    // Step 6: Setup cgroups
    cgroup_path = SETUP_CGROUPS(container_id, container_config.resources)
    IF cgroup_path IS Error:
        CLEANUP(container_dir)
        RETURN Error("Cgroup setup failed")

    // Step 7: Setup networking
    IF container_config.network != "none":
        network_config = SETUP_NETWORK(container_id, container_config.network)
        IF network_config IS Error:
            CLEANUP(container_dir, cgroup_path)
            RETURN Error("Network setup failed")

    // Step 8: Setup mounts
    mounts = PREPARE_MOUNTS(rootfs_path, container_config.mounts)
    IF mounts IS Error:
        CLEANUP(container_dir, cgroup_path, network_config)
        RETURN Error("Mount setup failed")

    // Step 9: Apply security profiles
    security_config = APPLY_SECURITY(container_config.security)
    // Note: Security applied at runtime, not creation

    // Step 10: Persist container state
    WRITE_FILE(container_dir + "/config.json", container_config)
    WRITE_FILE(container_dir + "/state.json", {status: "created"})

    // Step 11: Register with runtime state
    RUNTIME_STATE.containers[container_id] = {
        config: container_config,
        state: "created",
        pid: null
    }

    RETURN container_id
END FUNCTION
```

### 1.2 Rootfs Preparation

```
FUNCTION prepare_rootfs(container_id, image_manifest) -> Path
    INPUT:
        container_id: Unique container identifier
        image_manifest: OCI image manifest with layer references
    OUTPUT:
        Path to prepared rootfs

    rootfs_path = CONTAINER_BASE + "/" + container_id + "/rootfs"
    CREATE_DIRECTORY(rootfs_path)

    // OverlayFS structure: lower dirs (image layers) + upper dir (writes) + work dir
    overlay_dirs = []

    // Step 1: Assemble lower directories from image layers
    FOR EACH layer_digest IN REVERSE(image_manifest.layers):
        layer_path = LAYER_STORE + "/" + layer_digest

        IF NOT EXISTS(layer_path):
            // Lazy pull: fetch layer on demand
            result = FETCH_LAYER(layer_digest)
            IF result IS Error:
                RETURN Error("Layer fetch failed: " + layer_digest)

        // Reconstruct layer from CAS
        layer_dir = RECONSTRUCT_LAYER(layer_digest)
        APPEND(overlay_dirs, layer_dir)

    // Step 2: Create upper (writable) and work directories
    upper_dir = CONTAINER_BASE + "/" + container_id + "/upper"
    work_dir = CONTAINER_BASE + "/" + container_id + "/work"
    CREATE_DIRECTORY(upper_dir)
    CREATE_DIRECTORY(work_dir)

    // Step 3: Create init layer for container-specific files
    init_dir = CREATE_INIT_LAYER(container_id)
    PREPEND(overlay_dirs, init_dir)

    // Step 4: Mount OverlayFS
    mount_options = "lowerdir=" + JOIN(overlay_dirs, ":") +
                    ",upperdir=" + upper_dir +
                    ",workdir=" + work_dir

    result = MOUNT("overlay", rootfs_path, "overlay", mount_options)
    IF result IS Error:
        RETURN Error("OverlayFS mount failed")

    RETURN rootfs_path
END FUNCTION

FUNCTION reconstruct_layer(layer_digest) -> Path
    INPUT:
        layer_digest: SHA256 digest of the layer
    OUTPUT:
        Path to reconstructed layer directory

    layer_dir = LAYER_CACHE + "/" + layer_digest

    IF EXISTS(layer_dir):
        RETURN layer_dir  // Already reconstructed

    CREATE_DIRECTORY(layer_dir)

    // Load layer manifest (file -> Blake3 hash mapping)
    manifest = READ_FILE(LAYER_STORE + "/" + layer_digest + "/manifest.json")

    FOR EACH file_entry IN manifest.files:
        file_path = layer_dir + file_entry.path
        content_hash = file_entry.blake3

        // Retrieve from CAS
        source_path = CAS_STORE + "/" + PREFIX(content_hash, 2) + "/" + content_hash

        CREATE_DIRECTORY(PARENT_DIR(file_path))

        IF file_entry.type == "symlink":
            CREATE_SYMLINK(file_entry.target, file_path)
        ELSE IF file_entry.type == "directory":
            CREATE_DIRECTORY(file_path)
        ELSE:
            // Hard link to CAS (zero-copy)
            LINK(source_path, file_path)
            CHMOD(file_path, file_entry.mode)

    // Handle whiteouts (deletions from lower layers)
    FOR EACH whiteout IN manifest.whiteouts:
        whiteout_path = layer_dir + whiteout
        CREATE_WHITEOUT_MARKER(whiteout_path)

    RETURN layer_dir
END FUNCTION
```

### 1.3 Container Start

```
FUNCTION start_container(container_id) -> PID
    INPUT:
        container_id: Container to start
    OUTPUT:
        Process ID of container init process

    // Step 1: Load container state
    container = RUNTIME_STATE.containers[container_id]
    IF container IS None:
        RETURN Error("Container not found")

    IF container.state != "created":
        RETURN Error("Container not in created state")

    config = container.config

    // Step 2: Fork to create container process
    pid = FORK()

    IF pid == 0:  // Child process
        // Enter namespaces
        JOIN_NAMESPACES(container.namespaces)

        // Setup mount namespace (pivot_root)
        PIVOT_ROOT(config.rootfs, config.rootfs + "/.pivot")

        // Setup cgroup (move self to container cgroup)
        WRITE_FILE("/sys/fs/cgroup/" + container_id + "/cgroup.procs", getpid())

        // Apply security
        APPLY_SECCOMP(config.security.seccomp_profile)
        APPLY_APPARMOR(config.security.apparmor_profile)
        DROP_CAPABILITIES(config.security.capabilities)

        // Set no_new_privs
        PRCTL(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

        // Setup environment
        FOR EACH env_var IN config.env:
            SETENV(env_var.name, env_var.value)

        // Setup working directory
        CHDIR(config.working_dir)

        // Execute container process
        EXECVE(config.entrypoint, config.cmd, config.env)

    // Parent process: monitor child
    CONTINUE

    // Step 3: Update container state
    container.state = "running"
    container.pid = pid
    container.started_at = CURRENT_TIMESTAMP()

    WRITE_FILE(CONTAINER_BASE + "/" + container_id + "/state.json", container)

    // Step 4: Start health check if configured
    IF config.healthcheck != None:
        START_HEALTH_CHECK_THREAD(container_id, config.healthcheck)

    // Step 5: Start AI monitoring if enabled
    IF config.ai_enabled:
        START_AI_MONITOR(container_id)

    RETURN pid
END FUNCTION
```

---

## 2. Image Layer Deduplication

### 2.1 Storage Algorithm

```
FUNCTION store_layer(tarball_stream) -> LayerDigest
    INPUT:
        tarball_stream: Stream of compressed tarball data
    OUTPUT:
        SHA256 digest of the layer manifest

    temp_dir = CREATE_TEMP_DIRECTORY()
    manifest = {
        version: "1.0",
        files: [],
        whiteouts: []
    }

    // Step 1: Decompress and extract tarball
    decompressor = CREATE_DECOMPRESSOR(tarball_stream)
    tar_reader = CREATE_TAR_READER(decompressor)

    FOR EACH entry IN tar_reader:
        IF entry.name STARTS_WITH ".wh.":
            // Whiteout marker (deletion from lower layer)
            whiteout_path = STRIP_PREFIX(entry.name, ".wh.")
            APPEND(manifest.whiteouts, whiteout_path)
            CONTINUE

        file_path = temp_dir + "/" + entry.name

        IF entry.type == DIR:
            CREATE_DIRECTORY(file_path)
            APPEND(manifest.files, {
                path: entry.name,
                type: "directory",
                mode: entry.mode
            })

        ELSE IF entry.type == SYMLINK:
            CREATE_SYMLINK(entry.link_name, file_path)
            APPEND(manifest.files, {
                path: entry.name,
                type: "symlink",
                target: entry.link_name
            })

        ELSE IF entry.type == REGULAR:
            // Write to temp file for hashing
            WRITE_FILE(file_path, entry.content)

            // Step 2: Compute Blake3 hash
            content_hash = BLAKE3_HASH(entry.content)

            // Step 3: Store in CAS (deduplication point)
            cas_path = CAS_STORE + "/" + PREFIX(content_hash, 2) + "/" + content_hash

            IF NOT EXISTS(cas_path):
                // New content - store it
                RENAME(file_path, cas_path)
            ELSE:
                // Duplicate content - just delete temp
                DELETE(file_path)

            // Record metadata only
            APPEND(manifest.files, {
                path: entry.name,
                type: "regular",
                blake3: content_hash,
                mode: entry.mode,
                size: entry.size
            })

    // Step 4: Compute layer digest
    manifest_json = SERIALIZE_JSON(manifest)
    layer_digest = "sha256:" + SHA256_HASH(manifest_json)

    // Step 5: Store layer manifest
    layer_dir = LAYER_STORE + "/" + layer_digest
    CREATE_DIRECTORY(layer_dir)
    WRITE_FILE(layer_dir + "/manifest.json", manifest_json)

    // Step 6: Cleanup temp
    DELETE_DIRECTORY(temp_dir)

    // Step 7: Update statistics
    INCREMENT(stats.layers_stored)
    INCREMENT(stats.bytes_deduplicated, CALCULATE_SAVINGS(manifest))

    RETURN layer_digest
END FUNCTION
```

### 2.2 Deduplication Statistics

```
FUNCTION calculate_dedup_savings() -> DedupStats
    OUTPUT:
        Statistics about deduplication efficiency

    stats = {
        total_layers: 0,
        total_files: 0,
        unique_files: 0,
        logical_bytes: 0,
        physical_bytes: 0,
        savings_ratio: 0.0
    }

    // Count files in CAS
    FOR EACH file IN CAS_STORE:
        stats.unique_files += 1
        stats.physical_bytes += FILE_SIZE(file)

    // Count logical files across layers
    FOR EACH layer IN LAYER_STORE:
        stats.total_layers += 1
        manifest = READ_FILE(layer + "/manifest.json")
        FOR EACH file_entry IN manifest.files:
            IF file_entry.type == "regular":
                stats.total_files += 1
                stats.logical_bytes += file_entry.size

    // Calculate ratio
    IF stats.logical_bytes > 0:
        stats.savings_ratio = 1.0 - (stats.physical_bytes / stats.logical_bytes)

    RETURN stats
END FUNCTION
```

---

## 3. Resource Prediction Algorithm

### 3.1 WASM Neural Inference

```
FUNCTION predict_resources(container_spec, history) -> ResourcePrediction
    INPUT:
        container_spec: Container specification (image, env, mounts, etc.)
        history: Historical data from similar containers
    OUTPUT:
        Predicted resource requirements

    // Step 1: Extract features from container spec
    features = EXTRACT_FEATURES(container_spec)
    // features = [
    //     image_size_mb,
    //     entrypoint_complexity,  // 0=simple, 1=complex
    //     mount_count,
    //     env_var_count,
    //     exposed_port_count,
    //     has_healthcheck,
    //     network_mode,  // 0=none, 1=bridge, 2=host
    //     base_image_type  // 0=distroless, 1=alpine, 2=debian, 3=ubuntu
    // ]

    // Step 2: Normalize features
    normalized_features = NORMALIZE(features, {
        image_size_mb: {min: 0, max: 5000},
        entrypoint_complexity: {min: 0, max: 1},
        mount_count: {min: 0, max: 50},
        env_var_count: {min: 0, max: 200},
        exposed_port_count: {min: 0, max: 100},
        has_healthcheck: {min: 0, max: 1},
        network_mode: {min: 0, max: 2},
        base_image_type: {min: 0, max: 3}
    })

    // Step 3: Run WASM neural inference
    // Uses ruv-FANN compiled to WASM for portability
    wasm_module = LOAD_WASM("resource_predictor.wasm")
    inference_result = wasm_module.inference(normalized_features)

    // inference_result = [predicted_memory_mb, predicted_cpu_percent, predicted_startup_ms]

    // Step 4: Apply historical adjustment
    IF history.length > 0:
        // Weighted average with historical data
        historical_avg = CALCULATE_WEIGHTED_AVERAGE(history, weights=TIME_DECAY)
        prediction = BLEND_PREDICTIONS(
            model_prediction=inference_result,
            historical_prediction=historical_avg,
            alpha=0.7  // Favor model for new patterns, history for stable ones
        )
    ELSE:
        prediction = inference_result

    // Step 5: Add safety margin
    safety_margin = 1.2  // 20% buffer
    prediction.memory_mb = prediction.memory_mb * safety_margin
    prediction.cpu_percent = MIN(prediction.cpu_percent * safety_margin, 100)

    // Step 6: Round to reasonable values
    prediction.memory_mb = ROUND_TO_NEAREST(prediction.memory_mb, 64)  // 64MB granularity
    prediction.cpu_percent = ROUND_TO_NEAREST(prediction.cpu_percent, 5)  // 5% granularity

    RETURN {
        memory_mb: prediction.memory_mb,
        cpu_percent: prediction.cpu_percent,
        startup_ms: prediction.startup_ms,
        confidence: CALCULATE_CONFIDENCE(features, history)
    }
END FUNCTION
```

### 3.2 Feature Extraction

```
FUNCTION extract_features(container_spec) -> FeatureVector
    INPUT:
        container_spec: Container specification
    OUTPUT:
        Normalized feature vector for neural network

    features = []

    // Feature 1: Image size
    image = RESOLVE_IMAGE(container_spec.image)
    APPEND(features, image.size_bytes / (1024 * 1024))  // Convert to MB

    // Feature 2: Entrypoint complexity
    // Simple: single binary or script
    // Complex: shell with pipes, multiple commands, shell expansion
    IF image.config.entrypoint IS None:
        APPEND(features, 0.0)  // Default entrypoint
    ELSE IF LENGTH(image.config.entrypoint) == 1 AND NOT CONTAINS_SHELL(image.config.entrypoint[0]):
        APPEND(features, 0.0)  // Simple
    ELSE:
        APPEND(features, 1.0)  // Complex

    // Feature 3: Mount count
    APPEND(features, LENGTH(container_spec.mounts))

    // Feature 4: Environment variable count
    APPEND(features, LENGTH(container_spec.env))

    // Feature 5: Exposed port count
    APPEND(features, LENGTH(image.config.exposed_ports))

    // Feature 6: Has healthcheck
    APPEND(features, image.config.healthcheck IS NOT None ? 1.0 : 0.0)

    // Feature 7: Network mode
    network_map = {"none": 0.0, "bridge": 1.0, "host": 2.0}
    APPEND(features, network_map[container_spec.network_mode] OR 1.0)

    // Feature 8: Base image type
    // Classify by image layers and file structure
    IF CONTAINS(image.layers, "distroless"):
        APPEND(features, 0.0)
    ELSE IF CONTAINS(image.manifest.labels, "alpine"):
        APPEND(features, 1.0)
    ELSE IF CONTAINS(image.manifest.labels, "debian"):
        APPEND(features, 2.0)
    ELSE:
        APPEND(features, 3.0)  // Ubuntu or other

    RETURN features
END FUNCTION
```

---

## 4. Intelligent Restart Logic

### 4.1 Restart Decision Algorithm

```
FUNCTION intelligent_restart(container_id, exit_info) -> RestartDecision
    INPUT:
        container_id: Container that exited
        exit_info: {exit_code, signal, oom_killed, duration, resource_usage}
    OUTPUT:
        Decision on whether and how to restart

    container = RUNTIME_STATE.containers[container_id]
    restart_policy = container.config.restart_policy

    // Step 1: Check restart policy
    IF restart_policy == "no":
        RETURN {action: "no_restart", reason: "Restart policy is 'no'"}

    // Step 2: Analyze exit reason
    analysis = ANALYZE_EXIT(exit_info)

    // analysis = {
    //     cause: "oom" | "crash" | "signal" | "normal",
    //     severity: "critical" | "warning" | "info",
    //     pattern_match: string or null,
    //     recommended_action: string
    // }

    // Step 3: Check restart policy conditions
    IF restart_policy == "on-failure" AND exit_info.exit_code == 0:
        RETURN {action: "no_restart", reason: "Clean exit with 'on-failure' policy"}

    IF restart_policy == "unless-stopped" AND WAS_MANUALLY_STOPPED(container_id):
        RETURN {action: "no_restart", reason: "Manually stopped"}

    // Step 4: Check restart backoff
    restart_count = container.restart_count
    max_restarts = container.config.max_restarts OR 5

    IF restart_count >= max_restarts:
        RETURN {
            action: "no_restart",
            reason: "Max restart attempts reached",
            escalation: "manual_intervention_required"
        }

    // Step 5: AI-driven diagnostic
    IF container.config.ai_enabled:
        diagnosis = AI_DIAGNOSE(container_id, exit_info, analysis)

        IF diagnosis.action == "adjust_and_restart":
            RETURN {
                action: "restart_with_adjustments",
                adjustments: diagnosis.adjustments,
                // e.g., {"memory_limit_mb": 512, "cpu_shares": 1024}
                reason: diagnosis.reason,
                confidence: diagnosis.confidence
            }

        IF diagnosis.action == "alert_and_wait":
            RETURN {
                action: "wait",
                wait_duration: diagnosis.wait_duration,
                reason: diagnosis.reason,
                alert: diagnosis.alert_message
            }

    // Step 6: Default restart with exponential backoff
    backoff_duration = CALCULATE_BACKOFF(restart_count)
    // backoff_duration = min(2^restart_count * 100ms, 5 minutes)

    RETURN {
        action: "restart",
        delay: backoff_duration,
        restart_count: restart_count + 1,
        reason: "Standard restart with backoff"
    }
END FUNCTION
```

### 4.2 AI Diagnostic Analysis

```
FUNCTION ai_diagnose(container_id, exit_info, analysis) -> Diagnosis
    INPUT:
        container_id: Container that exited
        exit_info: Exit details
        analysis: Initial analysis
    OUTPUT:
        AI-generated diagnosis and recommendation

    // Gather context for AI analysis
    context = {
        container: container_id,
        exit_info: exit_info,
        analysis: analysis,
        history: GET_CONTAINER_HISTORY(container_id, limit=10),
        resource_usage: GET_RESOURCE_USAGE(container_id, duration="1h"),
        logs: GET_LOGS(container_id, tail=100),
        similar_incidents: SEARCH_SIMILAR_INCIDENTS(analysis.pattern_match)
    }

    // Route to appropriate AI tier based on complexity
    complexity = ASSESS_COMPLEXITY(context)

    IF complexity == "simple" AND analysis.cause == "oom":
        // Tier 1: WASM inference (free, fast)
        RETURN WASM_DIAGNOSE_OOM(context)

    ELSE IF complexity == "moderate":
        // Tier 2: Local LLM (cheap, reasonable quality)
        RETURN LOCAL_LLM_DIAGNOSE(context)

    ELSE:
        // Tier 3: Claude API (complex cases)
        RETURN CLAUDE_API_DIAGNOSE(context)

END FUNCTION

FUNCTION wasm_diagnose_oom(context) -> Diagnosis
    // Fast WASM-based OOM pattern matching
    features = [
        context.resource_usage.memory_peak_mb,
        context.exit_info.duration_seconds,
        context.container.config.memory_limit_mb,
        context.history.filter(h => h.cause == "oom").count
    ]

    // Load pre-trained OOM classifier
    wasm_module = LOAD_WASM("oom_classifier.wasm")
    prediction = wasm_module.classify(features)

    // prediction = {pattern: string, recommended_memory_mb: number, confidence: number}

    IF prediction.pattern == "steady_growth":
        // Memory leak or undersized
        recommended_memory = context.resource_usage.memory_peak_mb * 1.5
        RETURN {
            action: "adjust_and_restart",
            adjustments: {memory_limit_mb: recommended_memory},
            reason: "Detected steady memory growth, increasing limit by 50%",
            confidence: prediction.confidence
        }

    IF prediction.pattern == "spike":
        // Transient spike - restart with same config
        RETURN {
            action: "restart",
            reason: "Transient memory spike, no adjustment needed",
            confidence: prediction.confidence
        }

    IF prediction.pattern == "immediate":
        // OOM on startup - likely config error
        RETURN {
            action: "alert_and_wait",
            alert: "Container OOMs immediately on startup - check configuration",
            reason: "Configuration issue suspected",
            confidence: prediction.confidence
        }

    RETURN {
        action: "restart",
        reason: "Unknown OOM pattern, attempting restart",
        confidence: 0.5
    }
END FUNCTION
```

---

## 5. eBPF Packet Routing

### 5.1 BPF Program Structure

```
// eBPF program for container port forwarding (TC classifier)
// Attached to: ferrob0 bridge (ingress)

SEC("tc")
FUNCTION ferro_port_forward(ctx) -> TC_ACT
    INPUT:
        ctx: skb context (packet buffer)
    OUTPUT:
        TC_ACT_OK (pass) or TC_ACT_SHOT (drop) or TC_ACT_REDIRECT

    // Parse packet headers
    eth = PARSE_ETHERNET(ctx)
    IF eth IS NULL:
        RETURN TC_ACT_OK  // Pass non-IP traffic

    IF eth.type == ETH_P_IP:
        ip = PARSE_IPV4(ctx, eth)
    ELSE IF eth.type == ETH_P_IPV6:
        ip = PARSE_IPV6(ctx, eth)
    ELSE:
        RETURN TC_ACT_OK  // Pass non-IP traffic

    // Only handle TCP/UDP
    IF ip.proto != IPPROTO_TCP AND ip.proto != IPPROTO_UDP:
        RETURN TC_ACT_OK

    IF ip.proto == IPPROTO_TCP:
        tcp = PARSE_TCP(ctx, ip)
        port = tcp.dest
    ELSE:
        udp = PARSE_UDP(ctx, ip)
        port = udp.dest

    // Lookup port mapping in BPF map
    mapping = BPF_MAP_LOOKUP_ELEMENT(&port_map, &port)

    IF mapping IS NULL:
        // No mapping - pass to host network stack
        RETURN TC_ACT_OK

    // mapping = {container_ip: u32, container_port: u16, container_ifindex: u32}

    // Rewrite destination (DNAT)
    ip.dest_ip = mapping.container_ip

    IF ip.proto == IPPROTO_TCP:
        tcp.dest = mapping.container_port
        tcp.check = RECALCULATE_CHECKSUM(tcp.check, old_port, mapping.container_port)
    ELSE:
        udp.dest = mapping.container_port
        udp.check = RECALCULATE_CHECKSUM(udp.check, old_port, mapping.container_port)

    ip.check = RECALCULATE_CHECKSUM(ip.check, old_ip, mapping.container_ip)

    // Update Ethernet destination MAC (bridge to container)
    eth.dest_mac = LOOKUP_MAC(mapping.container_ip)

    // Redirect to container veth interface
    RETURN BPF_REDIRECT(mapping.container_ifindex, 0)

END FUNCTION
```

### 5.2 Port Map Management

```
FUNCTION setup_port_mapping(host_port, container_id, container_port) -> Result
    INPUT:
        host_port: Port to expose on host
        container_id: Target container
        container_port: Port inside container
    OUTPUT:
        Success or Error

    // Step 1: Get container network info
    container = RUNTIME_STATE.containers[container_id]
    container_ip = container.network.ip_address
    container_ifindex = container.network.veth_ifindex

    // Step 2: Check for port conflicts
    existing = BPF_MAP_LOOKUP_ELEMENT(&port_map, &host_port)
    IF existing IS NOT NULL:
        RETURN Error("Port " + host_port + " already in use")

    // Step 3: Add to BPF map
    mapping = {
        container_ip: container_ip,
        container_port: container_port,
        container_ifindex: container_ifindex
    }

    result = BPF_MAP_UPDATE_ELEMENT(&port_map, &host_port, &mapping, BPF_ANY)
    IF result IS Error:
        RETURN Error("Failed to update BPF map")

    // Step 4: Persist mapping for restart
    port_mappings_file = CONTAINER_BASE + "/" + container_id + "/port_mappings.json"
    mappings = READ_FILE(port_mappings_file) OR []
    APPEND(mappings, {
        host_port: host_port,
        container_port: container_port
    })
    WRITE_FILE(port_mappings_file, mappings)

    RETURN Success
END FUNCTION

FUNCTION cleanup_port_mappings(container_id) -> Result
    INPUT:
        container_id: Container being removed
    OUTPUT:
        Success or Error

    port_mappings_file = CONTAINER_BASE + "/" + container_id + "/port_mappings.json"

    IF NOT EXISTS(port_mappings_file):
        RETURN Success  // No mappings to clean

    mappings = READ_FILE(port_mappings_file)

    FOR EACH mapping IN mappings:
        BPF_MAP_DELETE_ELEMENT(&port_map, &mapping.host_port)

    DELETE_FILE(port_mappings_file)

    RETURN Success
END FUNCTION
```

### 5.3 Network Setup

```
FUNCTION setup_container_network(container_id, network_config) -> NetworkInfo
    INPUT:
        container_id: Container identifier
        network_config: {mode: "bridge"|"host"|"none", network_name: string}
    OUTPUT:
        NetworkInfo with IP, interfaces, etc.

    // Handle network modes
    IF network_config.mode == "none":
        RETURN {mode: "none", ip_address: null}

    IF network_config.mode == "host":
        RETURN {mode: "host", ip_address: HOST_IP}

    // Bridge mode (default)
    bridge_name = "ferrob0"

    // Step 1: Create veth pair
    host_veth = "veth" + container_id[:8] + "h"
    container_veth = "eth0"

    result = CREATE_VETH_PAIR(host_veth, container_veth)
    IF result IS Error:
        RETURN Error("Failed to create veth pair")

    // Step 2: Attach host end to bridge
    result = ATTACH_TO_BRIDGE(bridge_name, host_veth)
    IF result IS Error:
        DELETE_VETH(host_veth)
        RETURN Error("Failed to attach to bridge")

    // Step 3: Allocate IP address
    subnet = GET_NETWORK_SUBNET(network_config.network_name)
    ip_address = ALLOCATE_IP(subnet, container_id)

    // Step 4: Move container end to container namespace
    container_pid = RUNTIME_STATE.containers[container_id].pid
    result = MOVE_TO_NAMESPACE(container_veth, container_pid, "net")
    IF result IS Error:
        DELETE_VETH(host_veth)
        RETURN Error("Failed to move veth to container namespace")

    // Step 5: Configure container interface (inside namespace)
    EXEC_IN_NAMESPACE(container_pid, "net", FUNCTION():
        BRING_UP_INTERFACE(container_veth)
        ASSIGN_IP(container_veth, ip_address, subnet.mask)
        ADD_DEFAULT_ROUTE(subnet.gateway)
        SETUP_LOOPBACK()
    )

    // Step 6: Setup port mappings
    FOR EACH port_mapping IN network_config.port_mappings:
        result = SETUP_PORT_MAPPING(
            port_mapping.host_port,
            container_id,
            port_mapping.container_port
        )
        IF result IS Error:
            LOG("Port mapping failed: " + result.error)

    // Step 7: Register with embedded DNS
    container_name = RUNTIME_STATE.containers[container_id].config.name
    DNS_REGISTER(container_name, network_config.network_name, ip_address)

    RETURN {
        mode: "bridge",
        ip_address: ip_address,
        gateway: subnet.gateway,
        bridge: bridge_name,
        veth_host: host_veth,
        veth_container: container_veth,
        ifindex: GET_IFINDEX(host_veth)
    }
END FUNCTION
```

---

## 6. Complexity Analysis

| Algorithm | Time Complexity | Space Complexity | Notes |
|-----------|-----------------|------------------|-------|
| `create_container` | O(n) | O(n) | n = number of layers |
| `prepare_rootfs` | O(n * m) | O(n) | n = layers, m = files per layer |
| `store_layer` | O(n) | O(1) | n = files in layer, CAS storage is constant-time lookup |
| `predict_resources` | O(1) | O(1) | Fixed neural network size |
| `intelligent_restart` | O(1) | O(1) | Map lookups and AI inference |
| `ferro_port_forward` | O(1) | O(1) | BPF map lookup is constant time |
| `setup_container_network` | O(p) | O(1) | p = number of port mappings |

---

## 7. Entry/Exit Criteria

### Phase 2: Pseudocode (Current)

**Entry Criteria:**
- [x] Specification approved
- [x] State machines validated
- [x] Workflow diagrams complete

**Exit Criteria:**
- [x] Core algorithms documented
- [x] Complexity analysis complete
- [x] Edge cases identified
- [ ] Pseudocode review completed
- [ ] Ready for architecture design

---

## Appendix A: Edge Cases

### A.1 Container Creation Edge Cases

| Edge Case | Handling |
|-----------|----------|
| Image doesn't exist | Lazy pull with timeout, fallback to error |
| Layer download fails | Retry with exponential backoff, fallback to partial pull |
| Rootfs mount fails | Cleanup and retry with fresh overlay dirs |
| Namespace creation fails | Check kernel support, fallback with degraded isolation |
| Cgroup creation fails | Check cgroup v2 mounted, fallback to unlimited |

### A.2 Restart Edge Cases

| Edge Case | Handling |
|-----------|----------|
| Restart loop detected | Escalate after max_restarts, alert user |
| OOM on first startup | Likely config error, don't restart, alert |
| AI diagnosis times out | Fallback to standard restart with backoff |
| Container modified while restarting | Use atomic state updates with locks |

### A.3 Network Edge Cases

| Edge Case | Handling |
|-----------|----------|
| Port already in use | Check before allocation, return clear error |
| Bridge doesn't exist | Create bridge on first container |
| IP exhaustion | Return error, suggest network expansion |
| eBPF not supported | Fallback to iptables |
| Container removed during setup | Cleanup partial state with transaction rollback |
