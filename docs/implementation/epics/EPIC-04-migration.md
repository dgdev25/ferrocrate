# EPIC-04: Migration

**Phase:** Phase 3, Phase 6 (Weeks 15-20, 33-36) | **Tasks:** 2 | **Story Points:** 16

---

## 1. Overview

This epic ensures seamless migration from Docker to FerroCrate through API compatibility, CLI parity, and automated migration tooling.

### User Stories Covered
- US-4.1: `ferrocrate migrate` scans Docker and generates config
- US-4.2: Docker socket emulation for existing tools
- US-4.3: Drop-in replacement in GitHub Actions

### PRD Requirements Covered
- COMPAT-01 through COMPAT-09 (Compatibility)
- CLI-01, CLI-02, CLI-06 (CLI)
- CMP-01 (Compose compatibility)

---

## 2. Migration Strategy

### Three-Layer Compatibility

```
+------------------------------------------------------------------+
|                    Migration Layers                               |
|                                                                   |
|  Layer 1: CLI Compatibility                                       |
|  +------------------------------------------------------------+  |
|  | ferrocrate run  ->  ferro-exec create + start              |  |
|  | ferrocrate pull ->  ferro-store pull                       |  |
|  | ferrocrate build -> ferro-build build                      |  |
|  | ferrocrate ps    ->  query container state                 |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  Layer 2: API Compatibility                                       |
|  +------------------------------------------------------------+  |
|  | Docker Socket: /var/run/docker.sock                        |  |
|  | API Version: v1.45+                                        |  |
|  | Coverage: 95% endpoints                                    |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  Layer 3: Format Compatibility                                    |
|  +------------------------------------------------------------+  |
|  | Dockerfile: 95%+ directive support                         |  |
|  | docker-compose.yml: v3.x support                           |  |
|  | OCI Images: Full compliance                                |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

---

## 3. API Compatibility Matrix

### Supported Endpoints

| Category | Endpoint | Status | Notes |
|----------|----------|--------|-------|
| **Containers** | | | |
| | POST /containers/create | Full | |
| | POST /containers/{id}/start | Full | |
| | POST /containers/{id}/stop | Full | |
| | POST /containers/{id}/kill | Full | |
| | POST /containers/{id}/restart | Full | |
| | GET /containers/{id}/logs | Full | |
| | GET /containers/{id}/inspect | Full | |
| | GET /containers/{id}/stats | Full | |
| | DELETE /containers/{id} | Full | |
| | POST /containers/{id}/exec | Full | |
| | POST /exec/{id}/start | Full | |
| **Images** | | | |
| | GET /images/json | Full | |
| | POST /images/create | Full | Pull |
| | POST /build | Full | |
| | GET /images/{id}/json | Full | |
| | DELETE /images/{id} | Full | |
| | POST /images/{id}/push | Full | |
| | POST /images/{id}/tag | Full | |
| **Networks** | | | |
| | GET /networks | Full | |
| | POST /networks/create | Full | |
| | GET /networks/{id} | Full | |
| | DELETE /networks/{id} | Full | |
| **Volumes** | | | |
| | GET /volumes | Full | |
| | POST /volumes/create | Full | |
| | DELETE /volumes/{id} | Full | |
| **System** | | | |
| | GET /_ping | Full | |
| | GET /version | Full | |
| | GET /info | Full | |
| | GET /events | Full | |
| | GET /system/df | Full | |
| **Swarm** | | | |
| | /swarm/* | None | Out of scope |
| | /services/* | None | Out of scope |
| | /nodes/* | None | Out of scope |

### Coverage Summary
- Containers: 100%
- Images: 100%
- Networks: 95%
- Volumes: 100%
- System: 90%
- Swarm: 0% (explicitly out of scope)

---

## 4. Tasks

| ID | Title | Points | Milestone | Status |
|----|-------|--------|-----------|--------|
| TASK-015 | Implement Docker API compatibility layer | 10 | M2 | Not Started |
| TASK-022 | Implement Docker migration tool | 6 | M3 | Not Started |

**Total Story Points:** 16

---

## 5. CLI Compatibility

### Command Mapping

| Docker Command | FerroCrate Equivalent | Notes |
|----------------|----------------------|-------|
| `docker run` | `ferrocrate run` | Identical flags |
| `docker build` | `ferrocrate build` | Identical flags |
| `docker pull` | `ferrocrate pull` | Identical |
| `docker push` | `ferrocrate push` | Identical |
| `docker ps` | `ferrocrate ps` | Identical output |
| `docker images` | `ferrocrate images` | Identical output |
| `docker logs` | `ferrocrate logs` | Identical |
| `docker exec` | `ferrocrate exec` | Identical |
| `docker stop` | `ferrocrate stop` | Identical |
| `docker rm` | `ferrocrate rm` | Identical |
| `docker rmi` | `ferrocrate rmi` | Identical |
| `docker compose up` | `ferrocrate compose up` | Identical |
| `docker network create` | `ferrocrate network create` | Identical |
| `docker volume create` | `ferrocrate volume create` | Identical |

### Flag Compatibility

```bash
# docker run flags supported
ferrocrate run \
  -d, --detach                    # Background
  -e, --env                       # Environment variables
  --env-file                      # Environment file
  -p, --publish                   # Port mapping
  -P, --publish-all               # Publish all ports
  -v, --volume                    # Volume mount
  --mount                         # Mount specification
  --network                       # Network
  --restart                       # Restart policy
  --name                          # Container name
  -h, --hostname                  # Hostname
  --add-host                      # /etc/hosts entry
  --dns                           # DNS server
  --memory, -m                    # Memory limit
  --cpus                          # CPU limit
  --privileged                    # Privileged mode
  --cap-add                       # Add capabilities
  --cap-drop                      # Drop capabilities
  --security-opt                  # Security options
  --user, -u                      # User
  -w, --workdir                   # Working directory
  --entrypoint                    # Override entrypoint
  --health-cmd                    # Health check command
  --health-interval               # Health check interval
  --health-retries                # Health check retries
  --label                         # Labels
  -t, --tty                       # TTY
  -i, --interactive               # Interactive
  --rm                            # Remove on exit
```

---

## 6. Migration Tool

### Features

```bash
# Scan and analyze Docker installation
ferrocrate migrate --analyze

# Generate migration report
ferrocrate migrate --report

# Generate FerroCrate configuration
ferrocrate migrate --generate --output ./ferrocrate-config/

# Execute migration (copy images, recreate containers)
ferrocrate migrate --execute --dry-run
ferrocrate migrate --execute

# Export Docker state
ferrocrate migrate --export --output docker-state.json
```

### Migration Report

```
FerroCrate Migration Report
===========================

Summary:
  Containers: 15 (12 compatible, 3 warnings)
  Images: 28 (100% compatible)
  Networks: 4 (100% compatible)
  Volumes: 8 (100% compatible)

Compatibility Issues:
  [WARNING] container 'legacy-app' uses privileged mode
  [WARNING] container 'db-backup' mounts /var/run/docker.sock
  [INFO] container 'swarm-service' uses Swarm (unsupported, skipped)

Migration Steps:
  1. Pull images from Docker to FerroCrate store
  2. Create networks with matching configuration
  3. Create volumes with matching configuration
  4. Create containers with translated config
  5. Stop Docker containers
  6. Start FerroCrate containers

Estimated Time: 5 minutes
Disk Space Required: 2.3 GB

Run 'ferrocrate migrate --execute' to proceed.
```

### Generated Configuration

```yaml
# ferrocrate-config/containers.yaml
containers:
  - name: web-server
    image: nginx:1.25
    ports:
      - "8080:80"
    networks:
      - frontend
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s

  - name: database
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - db-data:/var/lib/postgresql/data
    networks:
      - backend

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge

volumes:
  db-data:
```

---

## 7. GitHub Actions Compatibility

### Drop-In Replacement

```yaml
# Before (Docker)
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/user/app:latest
```

```yaml
# After (FerroCrate) - Just change the socket!
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      DOCKER_HOST: unix:///var/run/ferrocrate.sock
    steps:
      - name: Setup FerroCrate
        run: |
          curl -fsSL https://get.ferrocrate.dev | sh
          ferrocrate daemon --docker-compat &
      # Same Docker actions work!
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/user/app:latest
```

---

## 8. VS Code Dev Containers

### Compatibility Verification

```bash
# Test VS Code Dev Containers
code --install-extension ms-vscode-remote.remote-containers

# Open project with devcontainer.json
# VS Code uses Docker socket automatically
# FerroCrate's Docker socket compatibility handles it
```

### devcontainer.json Example

```json
{
  "name": "My Dev Container",
  "image": "mcr.microsoft.com/devcontainers/base:ubuntu-22.04",
  "features": {
    "ghcr.io/devcontainers/features/rust:1": {}
  },
  "forwardPorts": [3000],
  "customizations": {
    "vscode": {
      "extensions": ["rust-lang.rust-analyzer"]
    }
  }
}
```

---

## 9. Testcontainers Compatibility

### Java Testcontainers

```java
// Works with FerroCrate without modification
@Testcontainers
class MyTest {
    @Container
    PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15");

    @Test
    void testDatabase() {
        // postgres.getJdbcUrl() works
    }
}
```

### Node.js Testcontainers

```typescript
// Works with FerroCrate without modification
import { GenericContainer } from "testcontainers";

test("should work with FerroCrate", async () => {
  const container = await new GenericContainer("redis:7")
    .withExposedPorts(6379)
    .start();

  // container works normally
});
```

---

## 10. Acceptance Criteria

This epic is complete when:

1. **API Compatibility**
   - [ ] 95% Docker API endpoint coverage
   - [ ] VS Code Dev Containers works
   - [ ] Testcontainers works
   - [ ] GitHub Actions works

2. **CLI Compatibility**
   - [ ] All common Docker CLI commands work
   - [ ] Identical flag support
   - [ ] Identical output format

3. **Migration Tool**
   - [ ] Analyze Docker installation
   - [ ] Generate migration report
   - [ ] Execute migration
   - [ ] Handle edge cases with warnings

4. **Documentation**
   - [ ] Migration guide
   - [ ] API compatibility matrix
   - [ ] Unsupported features documented

---

*Epic Owner: TBD | Last Updated: 2026-02-11*
