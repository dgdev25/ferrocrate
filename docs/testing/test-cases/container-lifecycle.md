# Container Lifecycle Test Cases

**Component:** ferro-exec | **Priority:** P0 | **Last Updated:** 2026-02-11

---

## Overview

Container lifecycle tests verify all operations related to container creation, execution, and termination. These tests ensure compliance with OCI Runtime Specification and Docker-compatible behavior.

---

## Test Categories

### 1. Container Creation (CLM-01, CLM-02)

#### TC-CL-001: Create container from valid image

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-001 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Image `alpine:latest` available in local store
- Runtime initialized

**Steps:**
1. Execute `ferrocrate create --name test-container alpine:latest`
2. Verify container exists in `ferrocrate ps -a`
3. Verify container state is `created`

**Expected Result:**
- Container created successfully
- Exit code 0
- Container listed with state "created"

**Cleanup:**
- `ferrocrate rm test-container`

---

#### TC-CL-002: Create container with custom name

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-002 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate create --name my-custom-name alpine:latest`
2. Verify container name matches in `ferrocrate ps -a`

**Expected Result:**
- Container created with specified name

---

#### TC-CL-003: Create container with duplicate name

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-003 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Preconditions:**
- Container named "duplicate-test" already exists

**Steps:**
1. Execute `ferrocrate create --name duplicate-test alpine:latest`

**Expected Result:**
- Error: "Container with name 'duplicate-test' already exists"
- Exit code non-zero

---

#### TC-CL-004: Create container from non-existent image

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-004 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate create --name test non-existent-image:latest`

**Expected Result:**
- Error: "Image not found: non-existent-image:latest"
- Exit code non-zero

---

#### TC-CL-005: Create container with resource limits

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-005 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate create --name limited --memory 256m --cpus 0.5 alpine:latest`
2. Verify limits in `ferrocrate inspect limited`

**Expected Result:**
- Memory limit: 268435456 bytes (256MB)
- CPU limit: 0.5

---

### 2. Container Start (CLM-02)

#### TC-CL-010: Start created container

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-010 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container "start-test" in created state

**Steps:**
1. Execute `ferrocrate start start-test`
2. Verify state changes to `running`

**Expected Result:**
- Container running
- Exit code 0

---

#### TC-CL-011: Start already running container

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-011 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Preconditions:**
- Container already in running state

**Steps:**
1. Execute `ferrocrate start running-container`

**Expected Result:**
- Warning: "Container already running"
- No error (idempotent operation)

---

#### TC-CL-012: Run container (create + start)

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-012 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --name run-test alpine:latest echo "hello"`
2. Verify output contains "hello"
3. Verify container in exited state

**Expected Result:**
- Command output: "hello"
- Container state: exited

---

#### TC-CL-013: Start container with entrypoint override

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-013 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --name entrypoint-test --entrypoint /bin/sh alpine:latest -c "echo custom"`

**Expected Result:**
- Output: "custom"
- Entrypoint overridden

---

### 3. Container Stop (CLM-02)

#### TC-CL-020: Stop running container gracefully

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-020 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container running with PID 1 handling SIGTERM

**Steps:**
1. Execute `ferrocrate stop stop-test`
2. Wait up to 10 seconds
3. Verify state is `exited`

**Expected Result:**
- SIGTERM sent to container
- Container exits gracefully
- Exit code 0

---

#### TC-CL-021: Stop container with timeout

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-021 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container running with unresponsive PID 1

**Steps:**
1. Execute `ferrocrate stop --timeout 5 unresponsive-container`
2. Wait for SIGKILL after 5 seconds

**Expected Result:**
- SIGTERM sent immediately
- SIGKILL sent after 5 seconds
- Container terminated

---

#### TC-CL-022: Stop stopped container

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-022 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Preconditions:**
- Container in stopped/exited state

**Steps:**
1. Execute `ferrocrate stop stopped-container`

**Expected Result:**
- Warning: "Container already stopped"
- No error (idempotent)

---

### 4. Container Kill (CLM-02)

#### TC-CL-030: Kill container with SIGKILL

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-030 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container running

**Steps:**
1. Execute `ferrocrate kill kill-test`
2. Verify immediate termination

**Expected Result:**
- SIGKILL sent
- Container terminated immediately
- Exit code 137

---

#### TC-CL-031: Kill container with custom signal

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-031 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate kill --signal SIGINT signal-test`
2. Verify signal delivered

**Expected Result:**
- SIGINT sent to PID 1
- Container handles signal appropriately

---

### 5. Container Restart (CLM-02, CLM-08)

#### TC-CL-040: Restart running container

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-040 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container running

**Steps:**
1. Record container start time
2. Execute `ferrocrate restart restart-test`
3. Verify new start time

**Expected Result:**
- Container stopped and started
- New start time recorded
- Same container ID

---

#### TC-CL-041: Automatic restart on failure

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-041 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container created with `--restart on-failure`

**Steps:**
1. Start container that exits with code 1
2. Verify automatic restart triggered
3. Verify restart count incremented

**Expected Result:**
- Container restarted automatically
- RestartCount > 0 in inspect output

---

#### TC-CL-042: Restart policy always

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-042 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Create container with `--restart always`
2. Stop container manually
3. Verify no automatic restart (manual stop)
4. Kill container
5. Verify automatic restart triggered

**Expected Result:**
- Manual stop: no restart
- Kill: restart triggered

---

### 6. Container Remove (CLM-02)

#### TC-CL-050: Remove stopped container

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-050 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container in stopped state

**Steps:**
1. Execute `ferrocrate rm remove-test`
2. Verify container not in `ferrocrate ps -a`

**Expected Result:**
- Container removed
- All resources freed

---

#### TC-CL-051: Remove running container with force

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-051 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container running

**Steps:**
1. Execute `ferrocrate rm --force running-test`

**Expected Result:**
- Container killed and removed
- SIGKILL sent before removal

---

#### TC-CL-052: Remove running container without force

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-052 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Preconditions:**
- Container running

**Steps:**
1. Execute `ferrocrate rm running-test`

**Expected Result:**
- Error: "Container is running. Use --force to remove."
- Container not removed

---

#### TC-CL-053: Remove container with volumes

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-053 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container with anonymous volumes

**Steps:**
1. Execute `ferrocrate rm --volumes volume-test`

**Expected Result:**
- Container removed
- Anonymous volumes removed
- Named volumes preserved

---

### 7. Container Pause/Unpause (CLM-03)

#### TC-CL-060: Pause running container

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-060 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container running

**Steps:**
1. Execute `ferrocrate pause pause-test`
2. Verify state is `paused`
3. Verify processes frozen via cgroup freezer

**Expected Result:**
- Container paused
- Processes suspended (not terminated)

---

#### TC-CL-061: Unpause paused container

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-061 |
| **Priority** | P1 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container paused

**Steps:**
1. Execute `ferrocrate unpause pause-test`
2. Verify state is `running`
3. Verify processes resume

**Expected Result:**
- Container running
- Processes resume from frozen state

---

### 8. Container Exec (CLM-04)

#### TC-CL-070: Exec command in running container

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-070 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container running

**Steps:**
1. Execute `ferrocrate exec exec-test ls /`

**Expected Result:**
- Command output matches container filesystem
- Exit code 0

---

#### TC-CL-071: Exec interactive command

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-071 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container running

**Steps:**
1. Execute `ferrocrate exec -it exec-test /bin/sh`
2. Send input "echo test"
3. Verify output "test"

**Expected Result:**
- Interactive shell attached
- Input/output working

---

#### TC-CL-072: Exec in stopped container

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-072 |
| **Priority** | P0 |
| **Type** | Negative |
| **Automated** | Yes |

**Preconditions:**
- Container stopped

**Steps:**
1. Execute `ferrocrate exec stopped-test ls`

**Expected Result:**
- Error: "Container is not running"
- Exit code non-zero

---

### 9. Container Logs (CLM-05)

#### TC-CL-080: Fetch container logs

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-080 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container with stdout output

**Steps:**
1. Execute `ferrocrate logs log-test`

**Expected Result:**
- Stdout/stderr output displayed
- Timestamps included (if configured)

---

#### TC-CL-081: Follow container logs

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-081 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate logs -f log-test`
2. Generate new output in container
3. Verify new output appears

**Expected Result:**
- Logs streamed in real-time
- New output appears as generated

---

#### TC-CL-082: Logs with tail limit

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-082 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate logs --tail 10 log-test`

**Expected Result:**
- Only last 10 lines displayed

---

### 10. Container Inspect (CLM-06)

#### TC-CL-090: Inspect container metadata

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-090 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container exists

**Steps:**
1. Execute `ferrocrate inspect inspect-test`
2. Parse JSON output

**Expected Result:**
- Valid JSON output
- Contains: Id, Name, State, Image, Config, NetworkSettings

---

#### TC-CL-091: Inspect with format string

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-091 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate inspect --format '{{.State.Status}}' inspect-test`

**Expected Result:**
- Only status value output (e.g., "running")

---

### 11. Health Checks (CLM-07)

#### TC-CL-100: Health check passing

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-100 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container with HEALTHCHECK CMD

**Steps:**
1. Start container with health check
2. Wait for health check interval
3. Check `ferrocrate inspect` for health status

**Expected Result:**
- Health status: "healthy"

---

#### TC-CL-101: Health check failing

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-101 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Preconditions:**
- Container with failing health check

**Steps:**
1. Start container with failing health check
2. Wait for retries exceeded
3. Check health status

**Expected Result:**
- Health status: "unhealthy"
- FailingStreak > 0

---

### 12. Environment and Labels (CLM-10)

#### TC-CL-110: Environment variables

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-110 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run -e TEST_VAR=value -e DB_HOST=localhost alpine printenv`
2. Verify output contains both variables

**Expected Result:**
- TEST_VAR=value
- DB_HOST=localhost

---

#### TC-CL-111: Labels

| Attribute | Value |
|-----------|-------|
| **ID** | TC-CL-111 |
| **Priority** | P0 |
| **Type** | Positive |
| **Automated** | Yes |

**Steps:**
1. Execute `ferrocrate run --label env=test --label version=1.0 alpine true`
2. Verify labels in inspect output

**Expected Result:**
- Labels present in Config.Labels

---

## Test Execution Matrix

| Test ID | Priority | Smoke | Regression | CI |
|---------|----------|-------|------------|-----|
| TC-CL-001 | P0 | X | X | X |
| TC-CL-002 | P0 | X | X | X |
| TC-CL-003 | P0 | - | X | X |
| TC-CL-004 | P0 | - | X | X |
| TC-CL-005 | P0 | - | X | X |
| TC-CL-010 | P0 | X | X | X |
| TC-CL-011 | P0 | - | X | X |
| TC-CL-012 | P0 | X | X | X |
| TC-CL-020 | P0 | X | X | X |
| TC-CL-030 | P0 | - | X | X |
| TC-CL-040 | P0 | - | X | X |
| TC-CL-050 | P0 | X | X | X |
| TC-CL-060 | P1 | - | X | X |
| TC-CL-070 | P0 | X | X | X |
| TC-CL-080 | P0 | - | X | X |
| TC-CL-090 | P0 | - | X | X |
| TC-CL-100 | P0 | - | X | X |
| TC-CL-110 | P0 | - | X | X |
