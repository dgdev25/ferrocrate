# M2: API Layer Milestone

**⚠️ LEGACY NOTICE:** This milestone structure has been superseded by the 6-phase implementation plan (Phase 1-6). Maintained for historical reference only. See `INDEX.md` for the current Phase 1-6 timeline.

**Duration:** Weeks 9-12 | **Story Points:** 31 | **Tasks:** 4

---

## 1. Objective

Deliver production-ready networking with eBPF-based packet handling, complete CLI command implementation, and Docker API compatibility layer. Enable seamless migration from Docker with socket compatibility for existing tooling.

## 2. Scope

### In Scope
- ferro-net crate implementation
- eBPF bridge networking (no iptables)
- Port forwarding (host:container)
- DNS resolution for container names
- Network modes: bridge, host, none
- Docker API v1.45+ compatibility
- Docker socket emulation
- Complete CLI command coverage

### Out of Scope
- AI features (M3)
- Compose orchestration (M3)
- WireGuard overlay (post-v1.0)
- IPv6 (post-v1.0)

## 3. Architecture

### Component Structure

```
ferro-net/
+-- Cargo.toml
+-- src/
|   +-- lib.rs
|   +-- ebpf/
|   |   +-- mod.rs           # eBPF loader
|   |   +-- bridge.bpf.c     # Bridge program
|   |   +-- redirect.bpf.c   # Port redirect
|   |   +-- nat.bpf.c        # NAT/conntrack
|   +-- network/
|   |   +-- mod.rs           # Network management
|   |   +-- bridge.rs        # Bridge network
|   |   +-- host.rs          # Host networking
|   |   +-- none.rs          # Isolated networking
|   +-- dns/
|   |   +-- mod.rs           # DNS resolver
|   |   +-- server.rs        # Embedded DNS server
|   |   +-- records.rs       # DNS record management
|   +-- port/
|   |   +-- mod.rs           # Port management
|   |   +-- mapping.rs       # Port mapping
|   |   +-- forwarder.rs     # Traffic forwarder
|   +-- error.rs

ferro-mgr/
+-- Cargo.toml
+-- src/
|   +-- lib.rs
|   +-- server/
|   |   +-- mod.rs           # API server
|   |   +-- router.rs        # Route definitions
|   |   +-- socket.rs        # Unix socket
|   +-- handlers/
|   |   +-- containers.rs    # /containers/*
|   |   +-- images.rs        # /images/*
|   |   +-- networks.rs      # /networks/*
|   |   +-- volumes.rs       # /volumes/*
|   |   +-- system.rs        # /_ping, /version, /info
|   |   +-- exec.rs          # /exec/*
|   +-- types/
|   |   +-- mod.rs           # Docker API types
|   |   +-- container.rs
|   |   +-- image.rs
|   |   +-- network.rs
|   +-- error.rs
```

### Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| aya | 0.11 | eBPF program loading |
| aya-log | 0.11 | eBPF logging |
| axum | 0.7 | HTTP server |
| tower | 0.4 | Service middleware |
| hyper | 1.0 | HTTP implementation |
| tokio | 1.35 | Async runtime |
| trust-dns | 0.23 | DNS server |
| smoltcp | 0.10 | Network stack |

## 4. Tasks

### TASK-012: Implement ferro-net crate skeleton

**Effort:** 3 days | **Points:** 5 | **Priority:** P0 | **Depends On:** TASK-002

**Description:**
Create the networking crate with eBPF program loading, network namespace management, and DNS resolution interfaces.

**Acceptance Criteria:**
- [ ] Cargo.toml with aya, smol deps
- [ ] eBPF program skeleton
- [ ] Network namespace utilities
- [ ] cargo test passes

**Implementation Notes:**
```rust
// src/lib.rs
pub mod ebpf;
pub mod network;
pub mod dns;
pub mod port;
pub mod error;

pub use network::{Network, NetworkDriver};
pub use error::Error;
```

**eBPF Program Skeleton:**
```c
// src/ebpf/bridge.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1024);
} container_ips SEC(".maps");

SEC("tc")
int bridge_forward(struct __sk_buff *skb) {
    // Packet forwarding logic
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
```

---

### TASK-013: Implement eBPF bridge networking

**Effort:** 6 days | **Points:** 10 | **Priority:** P0 | **Depends On:** TASK-012

**Description:**
Replace iptables with eBPF programs for container networking. Implement bridge mode with container-to-container communication.

**Acceptance Criteria:**
- [ ] No iptables rules created
- [ ] Container-to-container connectivity
- [ ] O(1) packet forwarding
- [ ] No conflicts with host firewall

**Implementation Notes:**
```rust
// ebpf/mod.rs
pub struct EbpfLoader {
    program: Program,
    maps: HashMap<String, Map>,
}

impl EbpfLoader {
    pub fn load_bridge(&mut self) -> Result<()> {
        // Load compiled eBPF bytecode
        let bytecode = include_bytes_aligned!("bridge.bpf.o");
        self.program = Program::from_bytes(bytecode)?;

        // Attach to network interface
        self.program.attach_tc("ferro0")?;
        Ok(())
    }

    pub fn add_container(&mut self, container_id: &str, ip: Ipv4Addr) -> Result<()> {
        // Add to eBPF map for O(1) lookup
        let key = container_id.hash() as u32;
        let value = u32::from(ip);
        self.maps["container_ips"].update(&key, &value)?;
        Ok(())
    }
}
```

**Network Driver:**
```rust
// network/bridge.rs
pub struct BridgeNetwork {
    name: String,
    subnet: Ipv4Cidr,
    gateway: Ipv4Addr,
    ebpf: EbpfLoader,
    containers: HashMap<String, ContainerNetwork>,
}

pub struct ContainerNetwork {
    veth_host: String,
    veth_container: String,
    ip: Ipv4Addr,
    mac: MacAddr,
}

impl BridgeNetwork {
    pub fn create(name: &str, subnet: Ipv4Cidr) -> Result<Self> {
        // Create bridge device
        netlink::add_bridge(name)?;

        // Load eBPF program
        let mut ebpf = EbpfLoader::new();
        ebpf.load_bridge()?;

        Ok(Self { ... })
    }

    pub fn connect_container(&mut self, container_id: &str) -> Result<ContainerNetwork> {
        // Create veth pair
        let veth_host = format!("veth-{}", &container_id[..8]);
        let veth_container = format!("eth0");

        netlink::add_veth_pair(&veth_host, &veth_container, &self.name)?;

        // Allocate IP
        let ip = self.allocate_ip();

        // Add to eBPF map
        self.ebpf.add_container(container_id, ip)?;

        Ok(ContainerNetwork { veth_host, veth_container, ip, mac })
    }
}
```

---

### TASK-014: Implement port forwarding and DNS

**Effort:** 4 days | **Points:** 6 | **Priority:** P0 | **Depends On:** TASK-013

**Description:**
Implement eBPF-based port forwarding (host:container) and embedded DNS server for container name resolution.

**Acceptance Criteria:**
- [ ] Port mapping works for TCP and UDP
- [ ] Container DNS resolves container names
- [ ] Host networking mode supported
- [ ] None networking mode supported

**Implementation Notes:**
```rust
// port/forwarder.rs
pub struct PortForwarder {
    ebpf: EbpfLoader,
    mappings: HashMap<u16, PortMapping>,
}

pub struct PortMapping {
    host_port: u16,
    container_ip: Ipv4Addr,
    container_port: u16,
    protocol: Protocol,
}

impl PortForwarder {
    pub fn add_mapping(&mut self, mapping: PortMapping) -> Result<()> {
        // eBPF sk_lookup for port redirect
        self.ebpf.add_port_redirect(
            mapping.host_port,
            mapping.container_ip,
            mapping.container_port,
        )?;

        self.mappings.insert(mapping.host_port, mapping);
        Ok(())
    }
}
```

**DNS Server:**
```rust
// dns/server.rs
pub struct ContainerDns {
    records: HashMap<String, Ipv4Addr>,
    server: DnsServer,
}

impl ContainerDns {
    pub fn new(listen_addr: Ipv4Addr) -> Result<Self> {
        let server = DnsServer::bind(listen_addr, 53)?;
        Ok(Self { records: HashMap::new(), server })
    }

    pub fn register(&mut self, name: &str, ip: Ipv4Addr) {
        self.records.insert(name.to_string(), ip);
    }

    pub async fn run(&self) {
        self.server.run(|query| {
            self.records.get(&query.name).cloned()
        }).await
    }
}
```

---

### TASK-015: Implement Docker API compatibility layer

**Effort:** 6 days | **Points:** 10 | **Priority:** P0 | **Depends On:** TASK-006, TASK-011, TASK-014

**Description:**
Implement HTTP API server with Docker v1.45+ endpoint compatibility. Cover containers, images, networks, volumes, and system endpoints.

**Acceptance Criteria:**
- [ ] 95% endpoint coverage
- [ ] VS Code Dev Containers works
- [ ] Testcontainers works
- [ ] Document unsupported endpoints

**Implementation Notes:**
```rust
// server/router.rs
pub fn docker_api_router() -> Router {
    Router::new()
        // Containers
        .route("/containers/json", get(list_containers))
        .route("/containers/create", post(create_container))
        .route("/containers/:id/start", post(start_container))
        .route("/containers/:id/stop", post(stop_container))
        .route("/containers/:id/kill", post(kill_container))
        .route("/containers/:id/restart", post(restart_container))
        .route("/containers/:id/logs", get(container_logs))
        .route("/containers/:id/inspect", get(inspect_container))
        .route("/containers/:id/exec", post(create_exec))
        .route("/containers/:id/stats", get(container_stats))
        .route("/containers/:id", delete(remove_container))

        // Images
        .route("/images/json", get(list_images))
        .route("/images/create", post(pull_image))
        .route("/build", post(build_image))
        .route("/images/:id", get(inspect_image))
        .route("/images/:id", delete(remove_image))
        .route("/images/:id/push", post(push_image))
        .route("/images/:id/tag", post(tag_image))

        // Networks
        .route("/networks", get(list_networks))
        .route("/networks/create", post(create_network))
        .route("/networks/:id", get(inspect_network))
        .route("/networks/:id", delete(remove_network))

        // Volumes
        .route("/volumes", get(list_volumes))
        .route("/volumes/create", post(create_volume))
        .route("/volumes/:id", get(inspect_volume))
        .route("/volumes/:id", delete(remove_volume))

        // System
        .route("/_ping", get(ping))
        .route("/version", get(version))
        .route("/info", get(system_info))
        .route("/events", get(events_stream))
        .route("/system/df", get(disk_usage))
}
```

**Container Handler:**
```rust
// handlers/containers.rs
pub async fn create_container(
    State(state): State<AppState>,
    Json(config): CreateContainerRequest,
) -> Result<Json<CreateContainerResponse>, ApiError> {
    // Convert Docker config to FerroCrate config
    let ferro_config = translate_config(&config)?;

    // Create container
    let container = state.runtime.create_container(ferro_config).await?;

    Ok(Json(CreateContainerResponse {
        id: container.id,
        warnings: vec![],
    }))
}

pub async fn start_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.runtime.start_container(&id).await?;
    Ok(StatusCode::NoContent)
}
```

**API Types:**
```rust
// types/container.rs
#[derive(Serialize)]
pub struct ContainerSummary {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Names")]
    pub names: Vec<String>,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Ports")]
    pub ports: Vec<PortBinding>,
    #[serde(rename = "Created")]
    pub created: i64,
}

#[derive(Deserialize)]
pub struct CreateContainerRequest {
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "Cmd")]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "Env")]
    pub env: Option<Vec<String>>,
    #[serde(rename = "HostConfig")]
    pub host_config: Option<HostConfig>,
}
```

**Version Response:**
```rust
// handlers/system.rs
pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        api_version: "1.45",
        min_api_version: "1.24",
        git_commit: env!("VERGEN_GIT_SHA"),
        go_version: "n/a",  // Rust, not Go
        os: "linux",
        arch: std::env::consts::ARCH,
        kernel_version: get_kernel_version(),
        version: env!("CARGO_PKG_VERSION"),
    })
}
```

---

## 5. Quality Gate

### Step 1: Code Complete
- [ ] All 4 tasks marked complete
- [ ] No TODO comments
- [ ] Clippy clean
- [ ] rustfmt applied

### Step 2: Unit Tests
- [ ] >80% coverage
- [ ] API handler tests
- [ ] eBPF program tests
- [ ] DNS resolution tests

### Step 3: Integration Tests
- [ ] Docker CLI compatibility
- [ ] VS Code Dev Containers
- [ ] Testcontainers
- [ ] docker-compose via API

```bash
# Test with Docker CLI
export DOCKER_HOST=unix:///var/run/ferrocrate.sock
docker run alpine echo "Hello"
docker ps
docker build -t test .
```

### Step 4: Performance Tests
- [ ] API response <50ms
- [ ] Network throughput >10Gbps
- [ ] DNS resolution <1ms
- [ ] No iptables conflicts

### Step 5: Security Audit
- [ ] Socket permission correct
- [ ] API authentication (if configured)
- [ ] No credential leakage
- [ ] Rate limiting

### Step 6: Documentation
- [ ] API endpoint documentation
- [ ] Compatibility matrix
- [ ] Troubleshooting guide

### Step 7: Review Sign-off
- [ ] Code review
- [ ] Security review
- [ ] Compatibility testing

---

## 6. Dependencies

### Internal Dependencies
- ferro-exec (container operations)
- ferro-store (image operations)
- ferro-net (networking)

### External Dependencies
- Linux kernel 5.10+ with eBPF support
- CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_BPF_JIT

---

## 7. Risks and Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| eBPF load failure | Medium | High | iptables fallback option |
| Docker API edge cases | High | Medium | Document gaps clearly |
| Socket permission | Low | High | Clear setup documentation |
| Tool incompatibility | Medium | Medium | Test matrix with popular tools |

---

## 8. Exit Criteria

Before proceeding to M3, demonstrate:

```bash
# Start daemon with Docker compatibility
ferrocrate daemon --docker-compat &

# Docker CLI works
export DOCKER_HOST=unix:///var/run/docker.sock
docker pull alpine
docker run -d --name web -p 8080:80 nginx
curl localhost:8080

# Multi-container networking
docker network create mynet
docker run -d --name app1 --network mynet alpine sleep infinity
docker run -d --name app2 --network mynet alpine sleep infinity
docker exec app1 ping -c 1 app2  # Container DNS resolution

# VS Code Dev Containers
# (Open project with devcontainer.json, verify it works)

# Testcontainers (Java/Node/etc)
# (Run test suite using Testcontainers, verify passes)
```

---

*Milestone Owner: TBD | Last Updated: 2026-02-11*
