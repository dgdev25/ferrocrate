# Docker Socket Compatibility

This document describes FerroCrate's Docker API compatibility layer, enabling tools expecting the Docker socket to work without modification.

## Overview

FerroCrate provides 95%+ Docker API v1.45+ compatibility through a socket emulation layer at `/var/run/ferrocrate.sock` (or user-configured path).

## Supported Endpoints

### Containers API

| Endpoint | Method | Compatibility | Notes |
|----------|--------|---------------|-------|
| `/containers/json` | GET | ✅ Full | All filters supported |
| `/containers/create` | POST | ✅ Full | All HostConfig options |
| `/containers/{id}/start` | POST | ✅ Full | |
| `/containers/{id}/stop` | POST | ✅ Full | Grace period supported |
| `/containers/{id}/restart` | POST | ✅ Full | |
| `/containers/{id}/kill` | POST | ✅ Full | All signals |
| `/containers/{id}/pause` | POST | ✅ Full | cgroup freezer |
| `/containers/{id}/unpause` | POST | ✅ Full | |
| `/containers/{id}` | GET | ✅ Full | Full inspect output |
| `/containers/{id}` | DELETE | ✅ Full | Force and volume removal |
| `/containers/{id}/logs` | GET | ✅ Full | Streaming and historical |
| `/containers/{id}/exec` | POST | ✅ Full | Create exec instance |
| `/exec/{id}/start` | POST | ✅ Full | Start exec |
| `/containers/{id}/stats` | GET | ✅ Full | Resource usage stats |
| `/containers/{id}/top` | GET | ✅ Full | Process list |
| `/containers/{id}/wait` | POST | ✅ Full | Wait for exit |
| `/containers/{id}/rename` | POST | ✅ Full | |
| `/containers/{id}/update` | POST | ⚠️ Partial | Resource limits only |
| `/containers/{id}/attach` | POST | ✅ Full | WebSocket compatible |
| `/containers/{id}/resize` | POST | ✅ Full | TTY resize |

### Images API

| Endpoint | Method | Compatibility | Notes |
|----------|--------|---------------|-------|
| `/images/json` | GET | ✅ Full | |
| `/images/create` | POST | ✅ Full | Pull from registry |
| `/images/{name}/json` | GET | ✅ Full | Image inspect |
| `/images/{name}/history` | GET | ✅ Full | Layer history |
| `/images/{name}/tag` | POST | ✅ Full | |
| `/images/{name}` | DELETE | ✅ Full | |
| `/images/search` | GET | ⚠️ Partial | Docker Hub only |
| `/images/prune` | POST | ✅ Full | |
| `/build` | POST | ✅ Full | Dockerfile build |
| `/commit` | POST | ✅ Full | Create image from container |

### Networks API

| Endpoint | Method | Compatibility | Notes |
|----------|--------|---------------|-------|
| `/networks` | GET | ✅ Full | |
| `/networks/{id}` | GET | ✅ Full | |
| `/networks/create` | POST | ✅ Full | |
| `/networks/{id}/connect` | POST | ✅ Full | |
| `/networks/{id}/disconnect` | POST | ✅ Full | |
| `/networks/{id}` | DELETE | ✅ Full | |

### Volumes API

| Endpoint | Method | Compatibility | Notes |
|----------|--------|---------------|-------|
| `/volumes` | GET | ✅ Full | |
| `/volumes/create` | POST | ✅ Full | |
| `/volumes/{name}` | GET | ✅ Full | |
| `/volumes/{name}` | DELETE | ✅ Full | |
| `/volumes/prune` | POST | ✅ Full | |

### System API

| Endpoint | Method | Compatibility | Notes |
|----------|--------|---------------|-------|
| `/info` | GET | ✅ Full | Extended with FerroCrate fields |
| `/version` | GET | ✅ Full | |
| `/events` | GET | ✅ Full | |
| `/ping` | GET | ✅ Full | |
| `/df` | GET | ✅ Full | Disk usage |

## Known Gaps

The following endpoints have known limitations:

### Not Supported (by design)

| Endpoint | Reason |
|----------|--------|
| `/swarm/*` | Swarm is deprecated; use compose instead |
| `/nodes/*` | Swarm-related |
| `/services/*` | Swarm-related |
| `/tasks/*` | Swarm-related |
| `/secrets/*` | Swarm-related |
| `/configs/*` | Swarm-related |
| `/plugins/*` | Different plugin architecture |

### Partial Support

| Endpoint | Gap | Workaround |
|----------|-----|------------|
| `/build` | BuildKit frontend | Use standard Dockerfile syntax |
| `/containers/{id}/update` | No live restart policy update | Stop/start with new config |
| `/images/search` | Limited to Docker Hub | Use `ferrocrate search` |

## Compatibility Mode

Enable Docker socket emulation:

```bash
# Create symlink for tools expecting Docker socket
sudo ln -sf /var/run/ferrocrate.sock /var/run/docker.sock

# Or use environment variable
export DOCKER_HOST=unix:///var/run/ferrocrate.sock
```

## Tool Compatibility Matrix

| Tool | Compatibility | Notes |
|------|---------------|-------|
| docker-compose | ✅ Full | v3.x files |
| docker CLI | ✅ Full | 95% command coverage |
| VS Code Dev Containers | ✅ Full | |
| Testcontainers | ✅ Full | |
| Kubernetes (cri-dockerd) | ⚠️ Partial | Use CRI directly |
| Portainer | ✅ Full | |
| Traefik | ✅ Full | |
| nginx-proxy | ✅ Full | |

## Version Mapping

| FerroCrate Version | Docker API Version |
|-------------------|---------------------|
| 1.0.x | 1.45 |

## Response Differences

FerroCrate includes additional fields in some responses:

```json
// GET /info
{
  "Containers": 5,
  "Images": 12,
  // Docker-compatible fields...
  "FerroCrateVersion": "1.0.0",
  "AiFeaturesEnabled": true,
  "WasmRuntime": "wasmtime",
  "DefaultSecurityProfile": "rootless",
  "StorageDriver": "overlayfs",
  "CgroupsVersion": "v2"
}
```
