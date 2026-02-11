# Networking Test Cases

**Component:** ferro-net | **Priority:** P0 | **Last Updated:** 2026-02-11

---

## Overview

Networking tests verify all functionality related to container network isolation, connectivity, and performance. Tests cover bridge networking, host networking, custom networks, DNS resolution, and eBPF-based packet forwarding.

---

## Test Categories

### 1. Bridge Networking (NET-01)

#### TC-NET-001: Default bridge network creation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-001 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Runtime initialized

**Steps:**
1. Execute `ferrocrate run --name bridge-test alpine ip addr`
2. Verify bridge interface created
3. Verify container has veth pair

**Expected Result:**
- Container connected to bridge
- IP assigned from bridge subnet
- veth pair created

---

#### TC-NET-002: Container connectivity via bridge

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-002 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Two containers on bridge network

**Steps:**
1. Start container A: `ferrocrate run -d --name container-a alpine nc -l -p 8080`
2. Start container B: `ferrocrate run --name container-b alpine`
3. From B, ping A's IP

**Expected Result:**
- Ping successful
- Containers can communicate

---

#### TC-NET-003: Port mapping (TCP)

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-003 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run -d -p 8080:80 --name nginx-test nginx:alpine`
2. Curl localhost:8080 from host

**Expected Result:**
- HTTP response received
- Port mapped correctly

---

#### TC-NET-004: Port mapping (UDP)

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-004 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Start DNS server container with UDP port mapped
2. Query DNS from host

**Expected Result:**
- UDP traffic forwarded
- DNS response received

---

#### TC-NET-005: Multiple port mappings

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-005 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run -d -p 8080:80 -p 8443:443 --name multi-port nginx:alpine`
2. Test both ports

**Expected Result:**
- Both ports accessible
- Traffic routed correctly

---

#### TC-NET-006: Port mapping with specific IP

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-006 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run -d -p 127.0.0.1:8080:80 --name ip-bind nginx:alpine`
2. Curl 127.0.0.1:8080
3. Try external IP

**Expected Result:**
- Localhost works
- External IP fails (bound to localhost only)

---

#### TC-NET-007: Port conflict detection

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-007 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Preconditions:**
- Port 8080 already in use

**Steps:**
1. Execute `ferrocrate run -d -p 8080:80 nginx:alpine`

**Expected Result:**
- Error: "port 8080 already in use"
- Container not started

---

### 2. Host Networking (NET-02)

#### TC-NET-010: Host network mode

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-010 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --network host --name host-test alpine ip addr`
2. Verify output matches host network

**Expected Result:**
- Container shares host network namespace
- Same interfaces as host

---

#### TC-NET-011: Host network port binding

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-011 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --network host -d --name host-nginx nginx:alpine`
2. Curl localhost:80 directly (no port mapping needed)

**Expected Result:**
- Service accessible on host port 80

---

#### TC-NET-012: Host network isolation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-012 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Two containers in host network mode

**Steps:**
1. Start two host-network containers
2. Verify they share network namespace

**Expected Result:**
- Both containers see same network stack
- Can communicate via localhost

---

### 3. None Networking (NET-03)

#### TC-NET-020: None network mode

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-020 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --network none --name none-test alpine ip addr`
2. Verify only loopback interface

**Expected Result:**
- Only lo interface present
- No external connectivity

---

#### TC-NET-021: None network isolation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-021 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container in none network mode

**Steps:**
1. Attempt to ping external host
2. Attempt to connect to bridge network container

**Expected Result:**
- All external connections fail
- Complete network isolation

---

### 4. DNS Resolution (NET-04)

#### TC-NET-030: Container DNS resolution

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-030 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container running

**Steps:**
1. Execute `ferrocrate exec dns-test nslookup google.com`

**Expected Result:**
- DNS resolution successful
- IP addresses returned

---

#### TC-NET-031: Custom DNS server

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-031 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --dns 8.8.8.8 --name custom-dns alpine nslookup example.com`

**Expected Result:**
- DNS query goes to 8.8.8.8

---

#### TC-NET-032: Container name resolution

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-032 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Two containers on same custom network

**Steps:**
1. Create network: `ferrocrate network create test-net`
2. Run container A: `ferrocrate run --network test-net --name web nginx:alpine`
3. Run container B: `ferrocrate run --network test-net --name client alpine`
4. From B: ping web

**Expected Result:**
- Container name "web" resolves
- Ping successful

---

#### TC-NET-033: DNS search domains

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-033 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --dns-search example.com alpine cat /etc/resolv.conf`

**Expected Result:**
- search example.com in resolv.conf

---

### 5. Custom Networks (NET-05)

#### TC-NET-040: Create bridge network

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-040 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate network create my-network`
2. Verify in `ferrocrate network ls`

**Expected Result:**
- Network created
- Listed with driver "bridge"

---

#### TC-NET-041: Create network with subnet

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-041 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate network create --subnet 172.20.0.0/16 custom-subnet`
2. Run container and verify IP

**Expected Result:**
- Container gets IP from specified subnet

---

#### TC-NET-042: Create network with gateway

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-042 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate network create --subnet 172.21.0.0/16 --gateway 172.21.0.1 custom-gw`

**Expected Result:**
- Gateway configured as specified

---

#### TC-NET-043: Network isolation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-043 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Two custom networks
- Container in each network

**Steps:**
1. Try to ping container in different network

**Expected Result:**
- Connection fails (network isolation)

---

#### TC-NET-044: Remove network

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-044 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- No containers using network

**Steps:**
1. Execute `ferrocrate network rm my-network`

**Expected Result:**
- Network removed
- Not in list

---

#### TC-NET-045: Remove network with containers

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-045 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Preconditions:**
- Container connected to network

**Steps:**
1. Execute `ferrocrate network rm used-network`

**Expected Result:**
- Error: "network has active endpoints"

---

#### TC-NET-046: Connect container to network

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-046 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Running container
- Existing network

**Steps:**
1. Execute `ferrocrate network connect my-network my-container`
2. Verify container has additional interface

**Expected Result:**
- Container connected to additional network

---

#### TC-NET-047: Disconnect container from network

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-047 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate network disconnect my-network my-container`

**Expected Result:**
- Interface removed
- Network connectivity lost

---

### 6. eBPF Packet Forwarding (NET-06)

#### TC-NET-050: eBPF program loading

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-050 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Kernel supports eBPF
- eBPF enabled in config

**Steps:**
1. Start container with port mapping
2. Verify eBPF program loaded

**Expected Result:**
- eBPF program attached to interface
- No iptables rules created

---

#### TC-NET-051: eBPF fallback to iptables

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-051 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- eBPF unavailable

**Steps:**
1. Start container
2. Verify iptables fallback used

**Expected Result:**
- iptables rules created
- Connectivity maintained

---

#### TC-NET-052: eBPF performance

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-052 |
| **Priority** | P1 |
| **Type** | Performance |
| **Automated** | Yes |

**Steps:**
1. Run iperf3 between containers
2. Measure throughput

**Expected Result:**
- Throughput within 10% of native
- Low latency

---

### 7. WireGuard Overlay (NET-07)

#### TC-NET-060: WireGuard tunnel creation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-060 |
| **Priority** | P2 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- WireGuard kernel module available
- Two hosts with ferrocrate

**Steps:**
1. Create overlay network with WireGuard
2. Verify encrypted tunnel

**Expected Result:**
- WireGuard interface created
- Traffic encrypted

---

#### TC-NET-061: Cross-host connectivity

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-061 |
| **Priority** | P2 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- WireGuard overlay established

**Steps:**
1. Run containers on different hosts
2. Ping between containers

**Expected Result:**
- Connectivity across hosts
- Traffic encrypted in transit

---

### 8. IPv6 Support (NET-09)

#### TC-NET-070: IPv6 address assignment

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-070 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- IPv6 enabled in config

**Steps:**
1. Execute `ferrocrate run --network bridge alpine ip -6 addr`

**Expected Result:**
- IPv6 address assigned
- From configured IPv6 subnet

---

#### TC-NET-071: IPv6 connectivity

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-071 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- IPv6 connectivity available

**Steps:**
1. Execute `ferrocrate run alpine ping6 -c 3 google.com`

**Expected Result:**
- IPv6 ping successful

---

#### TC-NET-072: Dual-stack networking

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-072 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Create network with IPv4 and IPv6 subnets
2. Verify both addresses assigned

**Expected Result:**
- Both IPv4 and IPv6 addresses
- Both protocols functional

---

### 9. Bandwidth Limiting (NET-10)

#### TC-NET-080: Egress rate limiting

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-080 |
| **Priority** | P2 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- eBPF rate limiting enabled

**Steps:**
1. Execute `ferrocrate run --network bridge --egress-rate 1mbs alpine`
2. Run iperf3 test

**Expected Result:**
- Egress bandwidth capped at 1 Mbps

---

#### TC-NET-081: Ingress rate limiting

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-081 |
| **Priority** | P2 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --network bridge --ingress-rate 1mbs alpine`
2. Test download speed

**Expected Result:**
- Ingress bandwidth capped

---

### 10. Network Troubleshooting

#### TC-NET-090: Network inspect

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-090 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate network inspect bridge`

**Expected Result:**
- JSON output with network details
- Subnet, gateway, connected containers

---

#### TC-NET-091: Container network stats

| Attribute | Value |
|-----------|-------|
| **ID** | TC-NET-091 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container with network traffic

**Steps:**
1. Execute `ferrocrate stats container-name`
2. Check network RX/TX

**Expected Result:**
- Bytes received/transmitted
- Packet counts

---

## Test Execution Matrix

| Test ID | Priority | Smoke | Regression | CI |
|---------|----------|-------|------------|-----|
| TC-NET-001 | P0 | X | X | X |
| TC-NET-003 | P0 | X | X | X |
| TC-NET-010 | P0 | X | X | X |
| TC-NET-020 | P0 | X | X | X |
| TC-NET-030 | P0 | - | X | X |
| TC-NET-032 | P0 | - | X | X |
| TC-NET-040 | P0 | - | X | X |
| TC-NET-050 | P1 | - | X | X |
| TC-NET-070 | P1 | - | X | X |
