# EPIC-05: Orchestration

**Phase:** Phase 3, Phase 4 (Weeks 15-24) | **Tasks:** 4 | **Story Points:** 26

---

## 1. Overview

This epic delivers multi-container orchestration capabilities including docker-compose support, eBPF-based networking, and service coordination.

### User Stories Covered
- US-1.5: `ferrocrate compose` parses docker-compose.yml
- US-5.1: Claude-Flow agents monitor container health
- US-5.2: Containers negotiate resource allocation
- US-5.3: Agentic security scanning

### PRD Requirements Covered
- CMP-01 through CMP-07 (Compose/Multi-Container)
- NET-01 through NET-10 (Networking)

---

## 2. Components

### ferro-compose Crate

```
ferro-compose/
+-- src/
|   +-- parser/
|   |   +-- v3.rs            # docker-compose.yml v3.x parser
|   |   +-- interpolate.rs   # Variable interpolation
|   +-- planner/
|   |   +-- dependency.rs    # Service dependency graph
|   |   +-- graph.rs         # Topological sort
|   +-- executor/
|   |   +-- parallel.rs      # Parallel service start
|   |   +-- health.rs        # Health check waiting
|   +-- commands/
|   |   +-- up.rs            # compose up
|   |   +-- down.rs          # compose down
|   |   +-- scale.rs         # compose scale
```

### ferro-net Crate

```
ferro-net/
+-- src/
|   +-- ebpf/
|   |   +-- bridge.bpf.c     # Bridge forwarding
|   |   +-- nat.bpf.c        # NAT/connection tracking
|   |   +-- redirect.bpf.c   # Port redirection
|   +-- network/
|   |   +-- bridge.rs        # Bridge network
|   |   +-- host.rs          # Host networking
|   +-- dns/
|   |   +-- server.rs        # Embedded DNS
```

---

## 3. Tasks

| ID | Title | Points | Milestone | Status |
|----|-------|--------|-----------|--------|
| TASK-012 | Implement ferro-net crate skeleton | 5 | M2 | Not Started |
| TASK-013 | Implement eBPF bridge networking | 10 | M2 | Not Started |
| TASK-014 | Implement port forwarding and DNS | 6 | M2 | Not Started |
| TASK-021 | Implement ferro-compose crate | 10 | M3 | Not Started |

**Total Story Points:** 31

---

## 4. Docker Compose Support

### Supported Compose Features

| Feature | Support | Notes |
|---------|---------|-------|
| version | 3.x | Required |
| services | Full | |
| networks | Full | |
| volumes | Full | |
| configs | Full | |
| secrets | Full | |
| build | Full | |
| image | Full | |
| command | Full | |
| entrypoint | Full | |
| environment | Full | |
| env_file | Full | |
| ports | Full | |
| expose | Full | |
| volumes | Full | |
| networks | Full | |
| depends_on | Full | With conditions |
| restart | Full | |
| healthcheck | Full | |
| deploy | Partial | Replicas only |
| labels | Full | |
| profiles | Full | |
| scale | Full | |

### Compose File Example

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8080:80"
    networks:
      - frontend
      - backend
    depends_on:
      db:
        condition: service_healthy
      cache:
        condition: service_started
    environment:
      DATABASE_URL: postgres://user:pass@db:5432/app
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      replicas: 3

  db:
    image: postgres:15
    volumes:
      - db-data:/var/lib/postgresql/data
    networks:
      - backend
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user"]
      interval: 5s
      timeout: 5s
      retries: 5

  cache:
    image: redis:7
    networks:
      - backend

networks:
  frontend:
  backend:

volumes:
  db-data:
```

---

## 5. eBPF Networking

### Architecture

```
+------------------------------------------------------------------+
|                    eBPF Network Stack                            |
|                                                                   |
|  +-------------+  +-------------+  +-------------+  +-----------+ |
|  | sk_lookup   |  |  tc/cls    |  |  XDP        |  | cgroup_skb| |
|  | Port redirect|  | Bridge fwd |  | Fast packet|  | Per-ctnr  | |
|  +-------------+  +-------------+  +-------------+  +-----------+ |
|                                                                   |
|  +------------------------------------------------------------+  |
|  |                    eBPF Maps                               |  |
|  |  +------------+  +------------+  +------------+            |  |
|  |  | container_ip|  | port_map   |  | conntrack  |            |  |
|  |  | key: c_id   |  | key: port  |  | key: 5-tuple|            |  |
|  |  | val: ip     |  | val: c_ip  |  | val: state  |            |  |
|  |  +------------+  +------------+  +------------+            |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### Key Features

1. **No iptables**: Zero conflict with host firewall
2. **O(1) lookups**: Hash-based packet routing
3. **Per-container policies**: Isolated network rules
4. **Connection tracking**: Stateful NAT

### Bridge Network Flow

```c
// bridge.bpf.c - eBPF bridge program
SEC("tc")
int bridge_forward(struct __sk_buff *skb) {
    struct iphdr *ip = get_ip_header(skb);

    // Lookup destination container
    u32 *dest_ip = bpf_map_lookup_elem(&container_ips, &ip->daddr);
    if (!dest_ip) {
        return TC_ACT_OK;  // Pass to host stack
    }

    // Lookup destination veth
    u32 ifindex = bpf_map_lookup_elem(&veth_map, dest_ip);

    // Redirect to container veth
    return bpf_redirect(ifindex, 0);
}
```

---

## 6. Service Orchestration

### Dependency Graph

```rust
// planner/graph.rs
pub struct ServiceGraph {
    graph: petgraph::DiGraph<String, ()>,
}

impl ServiceGraph {
    /// Compute start order with parallelism
    pub fn start_order(&self) -> Vec<Vec<String>> {
        // Kahn's algorithm with level grouping
        let mut levels = Vec::new();
        let mut in_degree: HashMap<_, _> = self.graph
            .node_indices()
            .map(|n| (n, self.graph.neighbors_directed(n, Incoming).count()))
            .collect();

        while !in_degree.is_empty() {
            // Find nodes with no dependencies
            let ready: Vec<_> = in_degree
                .iter()
                .filter(|(_, &deg)| deg == 0)
                .map(|(&n, _)| self.graph[n].clone())
                .collect();

            if ready.is_empty() && !in_degree.is_empty() {
                panic!("Cyclic dependency detected");
            }

            levels.push(ready.clone());

            // Remove ready nodes and update in-degrees
            for node in ready {
                let idx = self.find_node(&node);
                in_degree.remove(&idx);

                for neighbor in self.graph.neighbors_directed(idx, Outgoing) {
                    *in_degree.get_mut(&neighbor).unwrap() -= 1;
                }
            }
        }

        levels
    }
}
```

### Parallel Service Start

```rust
// executor/parallel.rs
pub async fn start_services_parallel(
    services: &[ServiceConfig],
    graph: &ServiceGraph,
) -> Result<()> {
    let levels = graph.start_order();

    for level in levels {
        // Start all services in this level concurrently
        let tasks: Vec<_> = level
            .iter()
            .map(|name| start_service(name, services))
            .collect();

        let results = futures::future::join_all(tasks).await;

        // Check for failures
        for result in results {
            result?;
        }
    }

    Ok(())
}
```

### Health Check Waiting

```rust
// executor/health.rs
pub async fn wait_for_healthy(
    container: &Container,
    config: &HealthCheckConfig,
) -> Result<()> {
    let start = Instant::now();
    let timeout = Duration::from_secs(config.start_period.unwrap_or(60));

    loop {
        if start.elapsed() > timeout {
            return Err(Error::HealthCheckTimeout);
        }

        match container.health_status().await? {
            HealthStatus::Healthy => return Ok(()),
            HealthStatus::Unhealthy => {
                return Err(Error::HealthCheckFailed);
            }
            HealthStatus::Starting => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
```

---

## 7. DNS Resolution

### Embedded DNS Server

```rust
// dns/server.rs
pub struct ContainerDns {
    records: RwLock<HashMap<String, Ipv4Addr>>,
    server: DnsServer,
}

impl ContainerDns {
    /// Register container with DNS
    pub fn register(&self, name: &str, ip: Ipv4Addr) {
        self.records.write().unwrap().insert(name.to_string(), ip);
    }

    /// Handle DNS query
    fn handle_query(&self, query: &DnsQuery) -> DnsResponse {
        let records = self.records.read().unwrap();

        if let Some(&ip) = records.get(&query.name) {
            DnsResponse::A(ip)
        } else {
            DnsResponse::NXDomain
        }
    }

    /// Run DNS server
    pub async fn run(&self) {
        self.server.serve(|query| self.handle_query(query)).await;
    }
}
```

### Container DNS Configuration

```rust
// Configure container to use embedded DNS
fn configure_dns(container: &mut Container, dns_ip: Ipv4Addr) {
    // /etc/resolv.conf in container
    let resolv_conf = format!(
        "nameserver {}\nsearch ferrocrate.local\n",
        dns_ip
    );

    container.write_file("/etc/resolv.conf", &resolv_conf);
}
```

---

## 8. Port Forwarding

### eBPF Port Redirection

```c
// redirect.bpf.c - Port forwarding via sk_lookup
SEC("sk_lookup")
int port_redirect(struct bpf_md *ctx) {
    struct bpf_sock *sk = ctx->sk;
    u16 port = sk->src_port;

    // Lookup port mapping
    struct port_mapping *map = bpf_map_lookup_elem(&port_map, &port);
    if (!map) {
        return SK_PASS;  // No mapping, pass through
    }

    // Lookup container socket
    struct bpf_sock *target = bpf_map_lookup_elem(&container_sockets, &map->container_ip);
    if (!target) {
        return SK_DROP;
    }

    // Redirect to container
    return bpf_sk_assign(ctx, target, 0);
}
```

### Port Mapping Management

```rust
// port/mapping.rs
pub struct PortManager {
    ebpf: EbpfLoader,
    mappings: HashMap<u16, PortMapping>,
}

pub struct PortMapping {
    pub host_port: u16,
    pub host_ip: Ipv4Addr,
    pub container_ip: Ipv4Addr,
    pub container_port: u16,
    pub protocol: Protocol,
}

impl PortManager {
    pub fn add_mapping(&mut self, mapping: PortMapping) -> Result<()> {
        // Update eBPF map
        self.ebpf.update_map("port_map", &mapping.host_port, &PortMapEntry {
            container_ip: mapping.container_ip,
            container_port: mapping.container_port,
        })?;

        self.mappings.insert(mapping.host_port, mapping);
        Ok(())
    }

    pub fn remove_mapping(&mut self, host_port: u16) -> Result<()> {
        self.ebpf.delete_map("port_map", &host_port)?;
        self.mappings.remove(&host_port);
        Ok(())
    }
}
```

---

## 9. CLI Commands

### compose up

```bash
# Start all services
ferrocrate compose up

# Start in background
ferrocrate compose up -d

# Build images before starting
ferrocrate compose up --build

# Scale services
ferrocrate compose up --scale web=3

# Use specific profiles
ferrocrate compose up --profile production
```

### compose down

```bash
# Stop and remove containers
ferrocrate compose down

# Remove volumes
ferrocrate compose down -v

# Remove images
ferrocrate compose down --rmi all
```

### compose ps

```bash
# List services
ferrocrate compose ps

NAME                COMMAND             SERVICE             STATUS              PORTS
web-1               "nginx -g daemon"   web                 running             0.0.0.0:8080->80/tcp
web-2               "nginx -g daemon"   web                 running
web-3               "nginx -g daemon"   web                 running
db-1                "postgres"          db                  running (healthy)
cache-1             "redis-server"      cache               running
```

### compose logs

```bash
# View all logs
ferrocrate compose logs

# Follow logs
ferrocrate compose logs -f

# Specific service
ferrocrate compose logs web

# Last N lines
ferrocrate compose logs --tail 100
```

---

## 10. Acceptance Criteria

This epic is complete when:

1. **Docker Compose Support**
   - [ ] Parse docker-compose.yml v3.x
   - [ ] Service dependencies work
   - [ ] Health check conditions work
   - [ ] Environment files work
   - [ ] Profiles work

2. **Networking**
   - [ ] Bridge network works
   - [ ] Container DNS resolution works
   - [ ] Port forwarding works
   - [ ] No iptables rules created

3. **Performance**
   - [ ] Parallel service start
   - [ ] O(1) packet forwarding
   - [ ] DNS resolution <1ms

4. **CLI**
   - [ ] compose up/down/ps/logs work
   - [ ] Scale command works
   - [ ] Profile selection works

---

*Epic Owner: TBD | Last Updated: 2026-02-11*
