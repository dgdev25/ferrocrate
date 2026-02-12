# FerroCrate Technical Remediation Plan

**Generated:** 2026-02-12
**Updated:** 2026-02-12
**Initial Score:** 4.5/10 → **Current Score:** ~6.0/10 (Wave 1 completed)
**Target Score:** 7.5/10
**Project:** AI-native container runtime in Rust (7 crates, ~15,500 LOC)

---

## How To Use This Document

This is a self-contained remediation plan. Each task includes the exact files to modify, the specific problems to fix, and the acceptance criteria. Execute tasks in wave order — each wave's tasks can run in parallel, but later waves depend on earlier ones completing.

---

## Current State Summary

| Metric | Initial Value | Current Value |
|--------|---------------|---------------|
| Compiles | **NO** — 2 errors in ferro-core | **YES** ✅ |
| Tests Pass | Unknown | **YES** (89/89) ✅ |
| Total Rust files | 83 | 83 |
| Total LOC | ~15,500 | ~15,500 |
| Crates | ferro-core, ferro-net, ferro-mind, ferro-compose, ferro-cli, ferro-cri, ferro-desktop | Same |
| Clippy warnings | 50+ | ~15 (mostly architectural) |
| Panics in src/ | 26 | 26 (unchanged) |
| Unwraps in src/ | 17 | 17 (unchanged) |
| Silent `let _ =` discards | 60 (across 12 files) | 60 (unchanged) |
| Largest file | ferro-cli/src/main.rs — 3,225 lines | Same |
| ferro-net real code | ~5% (rest is command-builder stubs) | Same |
| ferro-mind real code | ~50% (rest is stubs/placeholders) | Same | |
| Workspace lints | `unsafe_code = "forbid"` (good) |
| Edition | 2024 |

### Compilation Errors

```
error[E0425]: cannot find function `setup_wireguard` in this scope
  --> ferro-core/src/runtime.rs:1059:32

error[E0063]: missing field `ipv6_address` in initializer of `ContainerRecord`
  --> ferro-core/src/container_store.rs:226:22
```

### Architecture Overview

```
ferro-cli         (3,225 LOC)  — CLI frontend, clap-based, monolithic main.rs
├── ferro-core    (6,800 LOC)  — Container runtime, images, storage, builds
│   └── ferro-net   (760 LOC)  — Networking (mostly stubs)
├── ferro-compose   (630 LOC)  — Docker Compose parser (best quality crate)
├── ferro-mind      (550 LOC)  — AI/ML decision layer (50% stubs)
├── ferro-cri       (200 LOC)  — Kubernetes CRI shim (minimal)
└── ferro-desktop   (235 LOC)  — Windows WSL proxy
```

---

## Wave 1 — Unblock Build (BLOCKER)

### ~~Task 1.1: Fix Compile Errors~~ ✅ COMPLETED

**Priority:** BLOCKER — nothing else can proceed until this is done.

#### ~~Problem A: `setup_wireguard` not found~~ ✅ FIXED

**File:** `ferro-core/src/runtime.rs`

Added stub `setup_wireguard` function that returns an error indicating WireGuard is not yet implemented.

#### ~~Problem B: Missing `ipv6_address` field~~ ✅ FIXED

**File:** `ferro-core/src/container_store.rs`

Added `ipv6_address: None,` to the test struct.

#### ~~Problem C: Unused import warning~~ ✅ FIXED

**File:** `ferro-core/src/runtime.rs`

Removed the unused `PermissionsExt` import.

#### ~~Additional Fixes: ferro-cri compilation~~ ✅ FIXED

- Added `ferro-core` dependency to `ferro-cri/Cargo.toml`
- Added `ImageStoreError` variant to `CriError`
- Implemented custom `Debug` for `CriRuntime` (since `LocalImageStore` doesn't impl Debug)
- Fixed `thiserror` version to 2.0

#### Acceptance Criteria
- ✅ `cargo check` passes with zero errors
- ✅ `cargo test --no-run` compiles all test binaries
- ✅ No new warnings introduced

---

### ~~Task 1.2: Fix Clippy Warnings~~ ✅ COMPLETED (mostly)

**Priority:** HIGH — do immediately after compile fix.

**Fixed warnings:**
- ✅ `ferro-compose/src/lib.rs` — collapsible if statements (4 fixes)
- ✅ `ferro-net/tests/kernel_compat.rs` — `get(0)` → `first()`
- ✅ `ferro-core/src/container_store.rs` — `Default` derive for `RestartPolicy`
- ✅ `ferro-core/src/docker_auth.rs` — collapsible if
- ✅ `ferro-core/src/dockerfile_build.rs` — 8 fixes (io_other_error, redundant_closure, etc.)
- ✅ `ferro-core/src/observability.rs` — io_other_error
- ✅ `ferro-core/src/process_lifecycle.rs` — collapsible if (2 fixes)
- ✅ `ferro-core/src/registry.rs` — collapsible if (2 fixes)
- ✅ `ferro-core/src/runtime.rs` — multiple fixes (collapsible_if, io_other_error, vec_init_then_push, ptr_arg, etc.)
- ✅ `ferro-core/src/volume_store.rs` — default_constructed_unit_structs
- ✅ `ferro-core/src/image_fetch.rs` — collapsible if
- ✅ `ferro-cli/src/main.rs` — multiple fixes (collapsible_if, unnecessary_to_owned, map_identity)

**Remaining warnings (architectural, not critical):**
- `too_many_arguments` warnings for functions with many parameters (would require refactoring)
- `type_complexity` warning for complex return types
- `large_enum_variant` warning for CLI Commands enum

**Acceptance Criteria:**
- ✅ Most clippy warnings fixed
- ⚠️ Some architectural warnings remain (would require significant refactoring)

---

### Task 1.3: Update Roadmap Honesty

**Priority:** MEDIUM — important for project integrity but doesn't block code.

**File:** `docs/ROADMAP.md`

The roadmap claims ~95% of requirements are "Done" but many are stubs. Reclassify each item using these definitions:

| Status | Meaning |
|--------|---------|
| Done | Fully implemented, tested, working |
| API Designed | Data structures and command builders exist, no execution |
| Partial | Some implementation but significant gaps |
| Rework Needed | Already tagged, keep as-is |
| Not Started | No code exists |

**Specific reclassifications needed:**

Networking (ferro-net is 95% command-builder stubs):
- NET-01 (Bridge networking): Change to "Partial" — runtime.rs calls the builders but ferro-net has no execution layer
- NET-02 through NET-10: Review each. The runtime.rs `setup_network` function does call commands via `run_cmd`, so the runtime itself works for the happy path. But ferro-net as a library is stubs. Classify based on whether the runtime actually exercises the feature end-to-end.

AI (ferro-mind is ~50% stubs):
- AI-01 (WASM inference): Change to "Partial" — noop engine only, no real WASM runtime
- AI-02 (Predictive resource): Change to "Partial" — simple averaging, not ML
- AI-06 (Anomaly detection): Change to "Partial" — static z-score only
- AI-07 (ruvector build cache): Keep "Done" — dedup helper works
- AI-08 (NL management): Change to "Partial" — O(n) brute force search
- AI-12 (GPU scheduling): Change to "Partial" — no device discovery

Security:
- SEC-02 (Seccomp profiles): Change to "Partial" — parsed but NOT enforced
- SEC-03 (AppArmor/SELinux): Already "Rework Needed" — keep

Compatibility:
- COMPAT-09 (CRI): Change to "Partial" — minimal shim, missing most operations

Performance (PERF-01 through PERF-08): All are shell scripts that measure latency — classify as "Partial" (scripts exist, no optimization work done).

**Acceptance Criteria:**
- Every "Done" item in the roadmap has a real, tested implementation behind it
- Stubs/scaffolds are classified as "API Designed" or "Partial"
- The file provides an honest picture of project maturity

---

## Wave 2 — Critical Security & Code Quality (Parallel)

These tasks all depend on Wave 1 completing (project must compile).

### Task 2.1: Implement Seccomp Enforcement

**Priority:** CRITICAL SECURITY

**Current state:** `ferro-core/src/seccomp.rs` (65 lines) parses JSON seccomp profiles into a `SeccompProfile` struct but never calls `seccomp()` or `prctl()` to apply them. Containers run with no syscall filtering.

**Files to modify:**
- `ferro-core/src/seccomp.rs` — add enforcement function
- `ferro-core/src/runtime.rs` — call enforcement before exec
- `ferro-core/Cargo.toml` — add seccomp dependency

**Implementation:**

1. Add dependency to `ferro-core/Cargo.toml`:
   ```toml
   libseccomp = "0.3"  # or seccompiler = "0.4"
   ```

2. In `seccomp.rs`, add an `apply_profile` function:
   ```rust
   pub fn apply_seccomp_profile(profile: &SeccompProfile) -> Result<(), SeccompError> {
       // Build a seccomp filter from the parsed profile
       // Set default action from profile.default_action
       // Add rules for each syscall in profile.syscalls
       // Load the filter
   }
   ```

3. In `runtime.rs`, in the container spawn path (look for where `drop_all_capabilities` is called — this is in the child process setup), add seccomp enforcement AFTER capability drops:
   ```rust
   // After capabilities are dropped, apply seccomp
   if let Some(profile) = &seccomp_profile {
       seccomp::apply_seccomp_profile(profile)?;
   }
   ```

4. Provide a default seccomp profile (similar to Docker's default) that blocks dangerous syscalls: `kexec_load`, `reboot`, `mount` (in some contexts), `ptrace`, etc.

**Key constraints:**
- Seccomp must be applied in the child process AFTER fork but BEFORE exec
- Must be applied AFTER capability drops (seccomp is the last sandboxing step)
- Must handle `SCMP_ACT_ERRNO`, `SCMP_ACT_ALLOW`, `SCMP_ACT_KILL_PROCESS`

**Tests to add:**
- Parse and apply a profile that blocks `getpid` — verify the call fails
- Apply default profile — verify container still works for basic operations
- Missing profile → no seccomp applied (backward compatible)

**Acceptance Criteria:**
- Default seccomp profile applied to all containers unless `--security-opt seccomp=unconfined`
- Custom profiles from `--security-opt seccomp=/path/to/profile.json` work
- `cargo test` includes seccomp enforcement tests (can be `#[ignore]` if needs root)

---

### Task 2.2: Add Input Validation to ferro-net

**Priority:** CRITICAL SECURITY

**Current state:** All 12 files in `ferro-net/src/` accept raw strings with zero validation. Values are placed directly into shell command vectors.

**Files to modify:** All files in `ferro-net/src/`:
- `bridge.rs` — validate bridge name, CIDR
- `dns.rs` — validate IP addresses, domain names
- `ebpf.rs` — validate file paths, section names
- `ebpf_maps.rs` — validate map types, key/value sizes
- `iptables.rs` — validate table/chain names, rule args
- `netns.rs` — validate namespace names
- `nftables.rs` — validate family, table, chain names
- `packet_rules.rs` — validate protocol, CIDR, action
- `portmap.rs` — validate IPs, ports, protocol
- `rootless.rs` — validate tap name, CIDR
- `veth.rs` — validate interface names, MTU

**Create:** `ferro-net/src/validate.rs` — shared validation module

**Validation rules:**

```rust
// ferro-net/src/validate.rs

/// Interface/bridge names: alphanumeric, dash, underscore. Max 15 chars (IFNAMSIZ - 1).
pub fn validate_interface_name(name: &str) -> Result<(), ValidationError>;

/// CIDR: must be valid IP/prefix (e.g., "10.0.0.0/24" or "fd00::/64")
pub fn validate_cidr(cidr: &str) -> Result<(), ValidationError>;

/// IP address: must parse as std::net::IpAddr
pub fn validate_ip(addr: &str) -> Result<(), ValidationError>;

/// Port: 1-65535
pub fn validate_port(port: u16) -> Result<(), ValidationError>;

/// Protocol: tcp, udp, icmp, icmpv6
pub fn validate_protocol(proto: &str) -> Result<(), ValidationError>;

/// nftables family: ip, ip6, inet, bridge, arp
pub fn validate_nft_family(family: &str) -> Result<(), ValidationError>;

/// File path: no null bytes, no path traversal (../)
pub fn validate_path(path: &str) -> Result<(), ValidationError>;

/// Generic shell-safe string: no semicolons, pipes, backticks, $(), etc.
pub fn validate_shell_safe(value: &str) -> Result<(), ValidationError>;
```

**Migration pattern:** Change each `build_*` function from returning `Vec<String>` to returning `Result<Vec<String>, ValidationError>`. Example:

```rust
// BEFORE (bridge.rs):
pub fn build_ip_link_add_bridge_cmd(bridge: &str) -> Vec<String> {
    vec!["ip".into(), "link".into(), "add".into(), bridge.into(), ...]
}

// AFTER:
pub fn build_ip_link_add_bridge_cmd(bridge: &str) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(bridge)?;
    Ok(vec!["ip".into(), "link".into(), "add".into(), bridge.into(), ...])
}
```

**Callers update:** After changing return types, update all callers in `ferro-core/src/runtime.rs` — the `run_cmd` calls will need `?` propagation from the builder calls too.

**Tests to add (in each module's existing test block):**
- Valid input produces expected command vector
- Invalid interface name (too long, special chars) → error
- Invalid CIDR → error
- Shell injection attempt ("10.0.0.1; rm -rf /") → error

**Acceptance Criteria:**
- Every command builder validates its inputs before producing commands
- All existing tests still pass (valid inputs)
- New negative tests cover injection attempts
- `ferro-net/src/validate.rs` is comprehensive and reusable

---

### Task 2.3: Validate Auth File Permissions

**Priority:** SECURITY

**File:** `ferro-core/src/docker_auth.rs`

**Current state:** Credentials stored in `~/.ferrocrate/registry-auth.json` with no permission checks. File may be world-readable.

**Changes:**

1. When creating the auth file, set permissions to 0o600:
   ```rust
   use std::os::unix::fs::PermissionsExt;
   // After writing file:
   std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
   ```

2. When reading the auth file, check permissions and warn:
   ```rust
   let metadata = std::fs::metadata(&path)?;
   let mode = metadata.permissions().mode();
   if mode & 0o077 != 0 {
       eprintln!("WARNING: {} is accessible by other users (mode {:o}). Run: chmod 600 {}",
           path.display(), mode, path.display());
   }
   ```

3. Apply same treatment to Docker config.json reading (warn only, don't fail — it's not our file).

**Tests:**
- Create auth file → verify permissions are 0o600
- Create file with 0o644 → verify warning is emitted on read

**Acceptance Criteria:**
- New auth files created with 0o600
- Reading a world-readable auth file produces a stderr warning
- No functional regressions

---

### Task 2.4: Split ferro-cli/src/main.rs

**Priority:** CODE QUALITY

**Current state:** Single 3,225-line file containing all CLI definitions and handlers. Project rule says max 500 lines per file.

**File:** `ferro-cli/src/main.rs`

**Target structure:**
```
ferro-cli/src/
├── main.rs              (< 100 lines — arg parsing + dispatch)
├── commands/
│   ├── mod.rs           (re-exports)
│   ├── run.rs           (run, exec, attach)
│   ├── lifecycle.rs     (start, stop, kill, restart, pause, unpause, rm)
│   ├── images.rs        (images, pull, push, tag, rmi, prune, scan)
│   ├── build.rs         (build, ferrofile build)
│   ├── containers.rs    (ps, inspect, logs, stats, top, wait)
│   ├── compose.rs       (compose up/down/watch)
│   ├── volumes.rs       (volume create/ls/rm/backup/restore)
│   ├── network.rs       (network commands if any)
│   ├── system.rs        (info, version, daemon, tui, migrate, completion)
│   └── ai.rs            (ai-audit, ai-explain)
└── output.rs            (shared formatting: JSON mode, colored output)
```

**Steps:**
1. Read the full main.rs and identify the clap command definitions and their handler functions
2. Group related commands into modules
3. Move each group into its own file
4. Keep the clap `#[derive(Parser)]` struct in main.rs or a dedicated `cli.rs`
5. Each command module exports a `pub fn handle_<command>(args) -> Result<()>` function
6. main.rs becomes: parse args → match subcommand → call handler

**Constraints:**
- No behavioral changes — all commands must work identically
- All existing tests in `ferro-cli/tests/cli_integration.rs` must pass
- Each new file must be under 500 lines
- Preserve all imports and dependencies

**Acceptance Criteria:**
- `ferro-cli/src/main.rs` is under 150 lines
- No file in `ferro-cli/src/commands/` exceeds 500 lines
- `cargo test -p ferro-cli` passes
- `cargo run -p ferro-cli -- --help` shows all commands

---

### Task 2.5: Fix Error Handling — Remove Panics and Unsafe Unwraps

**Priority:** CODE QUALITY

**Scope:** All `*.rs` files under `ferro-*/src/` (not test files).

**Step 1: Audit and fix all `panic!()` calls (26 found)**

Run: `grep -rn "panic!" ferro-*/src/ --include="*.rs"`

For each panic:
- If it's in a code path that can be reached at runtime → replace with `return Err(...)`
- If it's genuinely unreachable → replace with `unreachable!()` with a comment explaining why
- If it's a precondition check → replace with a proper validation that returns Result

**Step 2: Audit and fix all `.unwrap()` calls (17 found)**

Run: `grep -rn "\.unwrap()" ferro-*/src/ --include="*.rs"` (exclude test files)

For each unwrap:
- If the value can genuinely be None/Err → replace with `?`, `.unwrap_or()`, `.unwrap_or_default()`, or `.map_err()?`
- If it's provably safe → add a comment: `// SAFETY: <reason>` and use `expect("reason")`

**Critical specific fix:**

`ferro-mind/src/ai/learning/vector_memory.rs` around line 28:
```rust
// BEFORE — panics on NaN:
scored.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());

// AFTER:
scored.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
```

**Step 3: Replace `Result<T, String>` with proper error types**

Search: `grep -rn "Result<.*String>" ferro-*/src/ --include="*.rs"`

For each instance, create or use an existing error enum with `#[derive(Debug, thiserror::Error)]`.

**Step 4: Remove silent error suppression**

Search: `grep -rn "Err(_) => continue\|Err(_) =>" ferro-*/src/ --include="*.rs"`

Replace with either:
- Logging the error before continuing
- Propagating the error with `?`
- Collecting errors to return at the end

**Step 5: Audit all `let _ =` silent discards (60 instances across 12 files)**

Search: `grep -rn "let _ =" ferro-*/src/ --include="*.rs"`

There are **60 instances** across these files:
- `ferro-core/src/runtime.rs` — 31 instances (most critical)
- `ferro-cli/src/main.rs` — 7 instances
- `ferro-core/src/image_fetch.rs` — 6 instances
- `ferro-core/src/dockerfile_build.rs` — 4 instances
- `ferro-core/src/observability.rs` — 3 instances
- `ferro-core/src/container_exec.rs` — 2 instances
- `ferro-desktop/src/main.rs` — 2 instances
- `ferro-core/src/capabilities.rs` — 1 instance
- `ferro-core/src/rootfs.rs` — 1 instance
- `ferro-core/src/mount_cleanup.rs` — 1 instance
- `ferro-core/src/cgroups.rs` — 1 instance
- `ferro-cri/src/server.rs` — 1 instance

For each `let _ =` instance:
- If it discards a `Result` from a fallible operation → replace with proper error handling:
  - `let _ = update_health(...)` → `if let Err(e) = update_health(...) { eprintln!("health update failed: {e}"); }`
  - `let _ = fs::remove_file(...)` → `if let Err(e) = fs::remove_file(...) { eprintln!("cleanup warning: {e}"); }`
- If it's in cleanup/teardown code where failure is expected → add a comment explaining why: `let _ = fs::remove_dir(...); // best-effort cleanup, dir may not exist`
- If the Result genuinely doesn't matter → use explicit `drop()` with a comment

**Example from health check (runtime.rs:1941):**
```rust
// BEFORE — silently discards health update failure:
let _ = update_health(&store, &id, "healthy", failures, now);

// AFTER:
if let Err(e) = update_health(&store, &id, "healthy", failures, now) {
    eprintln!("[health] failed to update health for {id}: {e}");
}
```

**Acceptance Criteria:**
- Zero `panic!()` calls in src/ files (except `unreachable!()` with safety comments)
- Zero bare `.unwrap()` calls in src/ files (`.expect("reason")` is acceptable for provably-safe cases)
- Zero `Result<T, String>` types in public APIs
- No silent error suppression (`Err(_) => continue`)
- All `let _ =` on Result types either log the error or have an explicit comment justifying the discard

---

### Task 2.6: Fix Container ID Generation — Use Cryptographic Randomness

**Priority:** SECURITY

**File:** `ferro-core/src/runtime.rs`, line 649-651

**Current state:**
```rust
fn generate_container_id() -> String {
    format!("c{}-{}", now_unix(), std::process::id())
}
```

This produces predictable, guessable IDs like `c1739356800-12345`. An attacker who knows the approximate time and can enumerate PIDs can predict container IDs. Container IDs are used as keys in the store and as part of resource names (netns, cgroup paths).

**Fix:**
```rust
use rand::Rng;

fn generate_container_id() -> String {
    let mut rng = rand::rng();
    let random_bytes: [u8; 16] = rng.random();
    hex::encode(random_bytes)  // 32-char hex string, e.g. "a1b2c3d4e5f6..."
}
```

Or without the `hex` dependency:
```rust
fn generate_container_id() -> String {
    let mut rng = rand::rng();
    let random_bytes: [u8; 16] = rng.random();
    random_bytes.iter().map(|b| format!("{b:02x}")).collect()
}
```

**Dependencies to add to `ferro-core/Cargo.toml`:**
```toml
rand = "0.9"
```

**Note:** If `rand` is already a transitive dependency, check the version. Use `rand::rng()` for the thread-local CSPRNG (uses `getrandom` under the hood on Linux).

**Tests:**
- Generate 1000 IDs → all unique
- ID format is 32 hex chars
- No timestamp or PID leakage in the ID

**Acceptance Criteria:**
- Container IDs are 32-character hex strings from a CSPRNG
- No predictable information (time, PID) in the ID
- Existing containers with old-format IDs still work (store lookup is by key, format doesn't matter)

---

### Task 2.7: Add eBPF Fallback Logging

**Priority:** OPERATIONAL

**File:** `ferro-core/src/runtime.rs`, lines 1077-1081

**Current state:**
```rust
let effective_backend = if network_backend == "ebpf" {
    "iptables"
} else {
    network_backend
};
```

When a user requests `--network-backend=ebpf`, it is **silently** changed to `iptables` with no log, warning, or error. The user believes they're running eBPF-based networking but they're actually on iptables.

**Fix:**
```rust
let effective_backend = if network_backend == "ebpf" {
    eprintln!("WARNING: eBPF network backend is not yet implemented, falling back to iptables");
    "iptables"
} else {
    network_backend
};
```

Or better — return an error if the user explicitly chose ebpf:
```rust
let effective_backend = if network_backend == "ebpf" {
    return Err(RuntimeError::Network(
        "eBPF network backend is not yet implemented. Use --network-backend=iptables or --network-backend=nftables".to_string()
    ));
} else {
    network_backend
};
```

**Decision for implementer:** Choose between warning+fallback or hard error. A hard error is more honest and prevents false security assumptions. If the eBPF backend was advertised as a feature in the CLI help, also update the CLI help text to mark it as `[experimental]` or `[not yet implemented]`.

**Tests:**
- Request ebpf backend → verify warning is emitted OR error is returned
- Request iptables backend → works normally, no warning

**Acceptance Criteria:**
- User is explicitly informed when eBPF is not available
- No silent behavior changes

---

### Task 2.8: Add Health Check Cancellation Token

**Priority:** RELIABILITY

**File:** `ferro-core/src/runtime.rs`, lines 1921-1959

**Current state:**
```rust
fn run_health_checks(store: sled::Db, id: String, pid: u32, config: HealthConfig) {
    if config.start_period_secs > 0 {
        thread::sleep(Duration::from_secs(config.start_period_secs));
    }
    let mut failures = 0_u32;
    loop {
        // ... check health ...
        thread::sleep(Duration::from_secs(config.interval_secs));
    }
}
```

This thread loops forever with `thread::sleep`. When a container is stopped or removed, the health check thread continues running — it wastes resources and may attempt to exec into a dead PID (or worse, a recycled PID belonging to a different process).

The only exit condition is at line 1952: `Ok(false) => break` from `update_health()` — which returns false when the container record is gone from the store. But this only triggers on a health check *failure* path, not the success path (line 1941 uses `let _ =`).

**Fix:** Add an `Arc<AtomicBool>` cancellation token:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn run_health_checks(
    store: sled::Db,
    id: String,
    pid: u32,
    config: HealthConfig,
    cancel: Arc<AtomicBool>,
) {
    if config.start_period_secs > 0 {
        // Sleep in small increments so we can check cancellation
        let deadline = std::time::Instant::now()
            + Duration::from_secs(config.start_period_secs);
        while std::time::Instant::now() < deadline {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    let mut failures = 0_u32;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        // ... existing health check logic ...

        // Replace the single sleep with cancellation-aware sleep
        let deadline = std::time::Instant::now()
            + Duration::from_secs(config.interval_secs);
        while std::time::Instant::now() < deadline {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
}
```

**Also update the caller** (wherever `run_health_checks` is spawned via `thread::spawn`):
1. Store the `Arc<AtomicBool>` in the `ContainerRecord` or a side map
2. When stopping/removing a container, set the flag: `cancel.store(true, Ordering::Relaxed)`
3. Optionally join the thread handle (with a timeout) to ensure cleanup

**Tests:**
- Spawn health check thread → set cancel flag → verify thread exits within 1 second
- Remove container from store → verify health check thread eventually exits
- Health check with 0 interval → thread doesn't spin-loop

**Acceptance Criteria:**
- Health check threads exit within 1 second of container stop/removal
- No zombie health check threads after container cleanup
- Start period sleep is also cancellable

---

### Task 2.9: Complete ferro-cri CRI Implementation

**Priority:** COMPLETENESS

**Current state:** `ferro-cri/src/server.rs` (114 lines) implements only:
- `Version` — returns version string
- `Status` — returns ready status
- `ListImages` — returns digests only (no full metadata)

**Files to modify:**
- `ferro-cri/src/server.rs` — add CRI operations
- `ferro-cri/src/lib.rs` — re-export types
- `ferro-cri/Cargo.toml` — add ferro-core dependency, fix thiserror version

**Cargo.toml fix:**
```toml
# Change from:
thiserror = "1"
# To:
thiserror = "2.0"

# Add:
ferro-core = { path = "../ferro-core" }
```

**CRI operations to implement:**

PodSandbox (maps to network namespace + cgroup):
- `RunPodSandbox` — create netns + cgroup, return sandbox ID
- `StopPodSandbox` — tear down networking
- `RemovePodSandbox` — clean up all resources
- `PodSandboxStatus` — return sandbox state
- `ListPodSandbox` — list all sandboxes

Container (maps to ferro-core runtime):
- `CreateContainer` — prepare container config, return container ID
- `StartContainer` — start via `ContainerRuntime::run`
- `StopContainer` — stop via `ContainerRuntime::stop`
- `RemoveContainer` — remove via `ContainerRuntime::remove`
- `ContainerStatus` — get from container store
- `ListContainers` — list from container store

Exec:
- `ExecSync` — run command via `ContainerRuntime::exec`

Image (enhance existing):
- `ListImages` — return full Image metadata (size, repo tags, repo digests)
- `PullImage` — pull via ferro-core image_fetch
- `RemoveImage` — remove via ferro-core image_store

**Acceptance Criteria:**
- All listed CRI RPCs have implementations (even if basic)
- thiserror version matches workspace
- Integration tests for at least: ListImages, CreateContainer, StartContainer, StopContainer
- `cargo test -p ferro-cri` passes

---

## Wave 3 — Infrastructure & Depth (After Wave 2)

### Task 3.1: Implement ferro-net Execution Layer

**Depends on:** Task 2.2 (input validation)

**Priority:** HIGH

**Current state:** ferro-net's 12 source files only build command vectors. Nothing executes.

**Create:** `ferro-net/src/executor.rs`

```rust
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("command failed: {cmd} — {stderr}")]
    CommandFailed { cmd: String, stderr: String },
    #[error("io error running {cmd}: {source}")]
    Io { cmd: String, #[source] source: std::io::Error },
}

/// Execute a command vector, returning Ok(()) on success or ExecError on failure.
pub fn exec_cmd(args: &[String]) -> Result<(), ExecError> { ... }

/// Execute a sequence of commands atomically — if any fails, roll back previous ones.
pub struct Transaction {
    executed: Vec<(Vec<String>, Vec<String>)>,  // (forward_cmd, rollback_cmd)
}

impl Transaction {
    pub fn new() -> Self { ... }
    pub fn add(&mut self, forward: Vec<String>, rollback: Vec<String>) -> Result<(), ExecError> { ... }
    pub fn rollback(&self) { ... }
}
```

**Then wire into each module.** Example for bridge.rs:

```rust
// Add execution functions alongside the existing command builders:
pub fn create_bridge(config: &BridgeConfig) -> Result<(), ExecError> {
    let mut txn = Transaction::new();
    txn.add(
        build_ip_link_add_bridge_cmd(&config.name)?,
        build_ip_link_del_cmd(&config.name)?,  // rollback
    )?;
    txn.add(
        build_ip_addr_add_bridge_cmd(&config.name, &config.cidr)?,
        vec![],  // no rollback needed
    )?;
    txn.add(
        build_ip_link_set_up_cmd(&config.name)?,
        build_ip_link_set_down_cmd(&config.name)?,
    )?;
    Ok(())
}
```

**Modules to wire:**
- `bridge.rs` — create_bridge, destroy_bridge
- `veth.rs` — create_veth_pair, destroy_veth_pair, assign_ip
- `netns.rs` — create_netns, destroy_netns (already has enter_netns)
- `iptables.rs` — add_rule, delete_rule
- `nftables.rs` — add_rule, delete_rule
- `portmap.rs` — add_port_mapping, remove_port_mapping
- `ebpf.rs` — load_program, unload_program

**Then update ferro-core/src/runtime.rs** to use the new execution functions instead of calling `run_cmd` with raw command vectors. This reduces the 47 shell-outs in runtime.rs.

**Acceptance Criteria:**
- Each ferro-net module has both builder functions AND execution functions
- Transaction rollback works (test: mock a failure at step N, verify steps 1..N-1 are rolled back)
- Integration tests (can be `#[ignore]` if needs root)
- runtime.rs updated to use ferro-net execution functions where possible

---

### Task 3.2: Add Tests for Untested Critical Paths

**Depends on:** Task 2.1 (seccomp — need enforcement before testing it)

**Priority:** HIGH

**New test files to create:**

1. **`ferro-cri/tests/service_tests.rs`**
   - Test Version, Status, ListImages responses
   - Test error handling for invalid requests

2. **`ferro-mind/tests/ai_tests.rs`**
   - Anomaly detection: known anomalous values detected
   - Restart policy: respects failure threshold
   - GPU selection: picks GPU with sufficient VRAM
   - Resource prediction: returns reasonable estimates
   - Vector memory: search returns nearest neighbors
   - Vector memory: NaN handling doesn't panic

3. **`ferro-core/tests/security_tests.rs`**
   - Seccomp profile parsing + enforcement (after Task 2.1)
   - Capability drop verification
   - Auth file permission warnings

4. **`ferro-net/tests/validation_tests.rs`** (after Task 2.2)
   - Valid inputs produce correct commands
   - Invalid inputs rejected with clear errors
   - Shell injection attempts blocked

5. **`ferro-compose/tests/edge_cases.rs`**
   - Malformed YAML → clear error
   - Empty services → rejected
   - Circular dependencies → detected
   - Missing env file → clear error

**Acceptance Criteria:**
- At least 3 tests per untested module
- All new tests pass
- `cargo test` runs cleanly

---

### Task 3.3: Replace ferro-mind Stub Implementations

**Depends on:** Task 2.5 (error handling fixes)

**Priority:** MEDIUM

**Files and fixes:**

1. **`ferro-mind/src/ai/anomaly.rs`** (16 lines → ~60 lines)
   - Add configurable threshold (not hardcoded)
   - Add temporal window (sliding window of recent values)
   - Return anomaly context (value, threshold, z-score, timestamp)
   - Add tests

2. **`ferro-mind/src/ai/gpu.rs`** (13 lines → ~50 lines)
   - Discover GPUs by reading `/proc/driver/nvidia/gpus/*/information` or parsing `nvidia-smi` output
   - Fallback to empty list if no GPU available
   - Validate VRAM requirement is reasonable
   - Add tests with mock GPU list

3. **`ferro-mind/src/ai/restart.rs`** (21 lines → ~40 lines)
   - Make failure threshold configurable
   - Add exponential backoff for restart delay
   - Return restart decision with reasoning
   - Add tests

4. **`ferro-mind/src/ai/config.rs`** (19 lines → ~40 lines)
   - Validate config values (e.g., threshold must be > 0)
   - Support config file in addition to env vars
   - Add tests

5. **`ferro-mind/src/ai/resource.rs`** (~40 lines → ~60 lines)
   - Replace simple averaging with exponential moving average (EWMA)
   - Add configurable smoothing factor
   - Add tests comparing prediction accuracy

6. **`ferro-mind/src/ai/learning/vector_memory.rs`**
   - Document that O(n) brute force is intentional for small N (< 10,000 entries)
   - Add a size limit with clear error when exceeded
   - Fix the NaN panic (already covered in Task 2.5)
   - Add persistence (save/load to JSON file)

7. **`ferro-mind/src/ruv/embeddings.rs`**
   - If HashEmbedding is intentional as a fallback, document it clearly with a comment
   - Add a trait `EmbeddingProvider` that both HashEmbedding and future real implementations can use
   - Remove the `todo!()` if any

8. **`ferro-mind/src/wasm.rs`**
   - If WASM inference is not yet needed, add a clear comment: "// Placeholder: real WASM runtime integration is planned for Phase 6"
   - Ensure the noop engine returns sensible defaults, not panics

**Acceptance Criteria:**
- No module is under 20 lines (stubs expanded to real implementations or clearly documented as intentional placeholders)
- Each module has at least 2 tests
- All error paths return Result, not panic

---

## Wave 4 — Hardening (After Wave 3)

### Task 4.1: Add Atomic Operations and Rollback to Runtime

**Depends on:** Task 3.1 (ferro-net execution layer)

**Priority:** MEDIUM

**File:** `ferro-core/src/runtime.rs`

**Current state:** Network setup involves sequential shell commands. If step N fails, steps 1..N-1 are not cleaned up.

**Implementation:** Use the Transaction pattern from Task 3.1 throughout the container lifecycle:

1. **Container creation transaction:**
   - Create cgroup → rollback: delete cgroup
   - Create network namespace → rollback: delete namespace
   - Create veth pair → rollback: delete veth pair
   - Assign IP → rollback: (implicit from veth deletion)
   - Add iptables rules → rollback: delete iptables rules
   - Mount overlayfs → rollback: unmount

2. **Container removal transaction:**
   - Stop process (SIGTERM → SIGKILL)
   - Unmount overlayfs
   - Remove iptables rules
   - Delete veth pair
   - Delete network namespace
   - Delete cgroup
   - Remove from store

**Acceptance Criteria:**
- Failed container creation leaves no orphan resources
- Failed container removal retries all cleanup steps
- Tests simulate failures at each step and verify cleanup

---

### Task 4.2: Reduce Shell-Out Surface in runtime.rs

**Depends on:** Task 3.1 (ferro-net execution layer)

**Priority:** MEDIUM

**File:** `ferro-core/src/runtime.rs` (47 Command::new / run_cmd calls)

**Replace with direct syscalls where possible:**

| Current shell-out | Replace with | Crate |
|-------------------|-------------|-------|
| `mount -t overlay ...` | `nix::mount::mount()` | nix |
| `umount /path` | `nix::mount::umount2()` | nix |
| `ip netns add X` | Already using `nix::sched::setns` for entry; add creation | nix |
| `kill -TERM pid` | Already using `nix::sys::signal::kill` | nix |
| `chown uid:gid path` | `nix::unistd::chown()` | nix |
| `ip link add/set/del` | Netlink socket operations | rtnetlink or netlink-packet-route |
| `ip addr add` | Netlink socket operations | rtnetlink |

**Note:** For network-specific operations (`ip link`, `ip addr`, `ip route`), consider the `rtnetlink` crate as an alternative to shelling out to `ip`. It speaks netlink directly, which is more reliable and performant than parsing CLI output. The `nix` crate handles mount/signal/chown well but doesn't cover netlink. Use both: `nix` for syscalls, `rtnetlink` for network configuration.

**Keep as shell-outs (no good Rust alternative):**
- `iptables` / `nft` — no stable Rust library
- `bpftool` — too complex to reimplement
- `wg` — WireGuard CLI
- `cosign` — image signing
- `aa-exec` / `runcon` — MAC enforcement
- `slirp4netns` — rootless networking
- `tc` — traffic control

**For remaining shell-outs, ensure:**
- Each goes through a single `exec_cmd()` wrapper with:
  - Timeout (default 30s)
  - Full command logged at debug level
  - stderr captured and included in error message
  - Command name included in error type

**Target:** Reduce shell-outs from 47 to ~25 (keep only those that genuinely need external tools).

**Acceptance Criteria:**
- All mount/umount operations use nix crate directly
- All remaining shell-outs go through a single executor with logging
- No raw `Command::new` calls outside the executor
- `cargo test` passes

---

## Appendix A: File Inventory

### Files with tests (have `#[test]`)
```
ferro-compose/src/lib.rs
ferro-compose/src/service_graph.rs
ferro-compose/src/compose.rs
ferro-core/src/mounts.rs
ferro-core/src/rootless.rs
ferro-core/src/container_exec.rs
ferro-core/src/cgroups.rs
ferro-core/src/dockerfile_build.rs
ferro-core/src/runtime_config.rs
ferro-core/src/image_config.rs
ferro-core/src/docker_auth.rs
ferro-core/src/registry.rs
ferro-core/src/overlayfs.rs
ferro-core/src/image_store.rs
ferro-core/src/image_tagging.rs
ferro-core/src/image_fetch.rs
ferro-core/src/layer_compression.rs
ferro-core/src/mount_cleanup.rs
ferro-core/src/seccomp.rs
ferro-core/src/rootfs.rs
ferro-core/src/volume_store.rs
ferro-core/src/mac_profiles.rs
ferro-core/src/rootfs_prep.rs
ferro-core/src/container_store.rs
ferro-core/src/process_lifecycle.rs
ferro-core/src/ferrofile_build.rs
ferro-core/src/linux_namespaces.rs
ferro-core/src/runtime.rs
ferro-core/src/capabilities.rs
ferro-core/src/layer_mount.rs
ferro-core/src/image_manifest.rs
ferro-core/tests/rootless_isolation.rs
ferro-core/tests/image_operations.rs
ferro-core/tests/container_lifecycle.rs
ferro-core/tests/storage_operations.rs
ferro-cli/src/main.rs
ferro-cli/tests/cli_integration.rs
ferro-desktop/src/main.rs
ferro-net/src/netns.rs (and all other ferro-net src files)
ferro-net/tests/*.rs (7 test files, most #[ignore])
ferro-mind/src/ruv/distance.rs
```

### Files WITHOUT tests (need coverage)
```
ferro-cri/src/server.rs
ferro-cri/src/main.rs
ferro-mind/src/ai/anomaly.rs
ferro-mind/src/ai/audit.rs
ferro-mind/src/ai/config.rs
ferro-mind/src/ai/explain.rs
ferro-mind/src/ai/gpu.rs
ferro-mind/src/ai/resource.rs
ferro-mind/src/ai/restart.rs
ferro-mind/src/ai/learning/vector_memory.rs
ferro-mind/src/ai/routing/cost.rs
ferro-mind/src/ruv/dedup.rs
ferro-mind/src/ruv/embeddings.rs
ferro-mind/src/wasm.rs
ferro-core/src/observability.rs
ferro-core/src/image_security.rs
```

## Appendix B: Dependency Graph

```
Wave 1: [Task 1.1] [Task 1.2] [Task 1.3]
            |          |
            v          v
Wave 2: [2.1 Seccomp] [2.2 Validation] [2.3 Auth perms] [2.4 Split CLI] [2.5 Error handling]
        [2.6 Container IDs] [2.7 eBPF logging] [2.8 Health cancel] [2.9 CRI impl]
            |          |                                       |
            v          v                                       v
Wave 3:    [Task 3.2] [Task 3.1]                          [Task 3.3]
                          |
                          v
Wave 4:              [Task 4.1] [Task 4.2]
```

## Appendix C: Verification Commands

After all waves complete, run these to verify:

```bash
# Must all pass:
cargo check                           # Zero errors
cargo clippy --all-targets            # Zero warnings
cargo test                            # All tests pass
cargo test --no-run 2>&1 | grep -c "Compiling"  # All crates compile

# Verify file sizes:
wc -l ferro-cli/src/main.rs           # Should be < 150
find . -name "*.rs" -not -path "*/target/*" -exec wc -l {} + | awk '$1 > 500 {print}'
# Should show only ferro-core/src/runtime.rs and ferro-core/src/registry.rs (both acceptable)

# Verify no panics in source:
grep -rn "panic!" ferro-*/src/ --include="*.rs" | grep -v "unreachable!" | wc -l  # Should be 0

# Verify no bare unwraps:
grep -rn "\.unwrap()" ferro-*/src/ --include="*.rs" | grep -v test | grep -v "expect(" | wc -l  # Should be 0
```
