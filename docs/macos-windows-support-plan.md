# FerroCrate macOS + Windows Support Plan

## Objective
Provide a native-feeling FerroCrate CLI on macOS and Windows by running the Linux runtime inside a lightweight VM layer, with transparent file sharing, networking, and credential integration.

## High-Level Approach
Build a **desktop VM layer** that hosts the Linux runtime, and a **host-side CLI proxy** that forwards CLI/API calls into the VM. This mirrors Docker Desktop’s architecture while keeping FerroCrate’s runtime Linux-only.

## Architecture Overview
1. **Host CLI Proxy**
   - `ferrocrate` on macOS/Windows becomes a thin client.
   - Talks to a local daemon (`ferro-desktop`) via Unix socket / Windows named pipe.
   - Forwards commands to the VM via gRPC/HTTP.

2. **VM Runtime**
   - Minimal Linux image containing FerroCrate runtime + helpers.
   - Runtime manages containers and storage inside VM.
   - Exported API is the same CLI + Docker compat socket.

3. **Communication Channel**
   - macOS: `vsock` or `ssh` tunnel for VM RPC.
   - Windows: `vsock` (Hyper-V), `AF_VSOCK` or `named pipe` bridging.

4. **File Sharing**
   - macOS: `virtiofs` (preferred), fallback `9p`.
   - Windows: `virtiofs` on WSL2 or `9p`/`smb` for Hyper-V.
   - Host paths mapped into VM, then bind-mounted into containers.

5. **Networking**
   - VM NAT with port forward from host to VM.
   - Host-to-container port mapping proxy (host listens, forwards into VM).
   - DNS forwarding from VM to host DNS.

6. **Credential + Config Sync**
   - Sync `~/.docker/config.json` and `~/.ferrocrate/*`.
   - macOS Keychain and Windows Credential Manager integration on host.
   - Registry creds forwarded to VM runtime.

7. **Updates + Telemetry**
   - Host app manages VM image updates.
   - Optional telemetry from host only, not required for runtime.

## Implementation Phases

### Phase 0 — WSL2 First-Class Support (Windows)
- Target: Run FerroCrate inside WSL2 as the first Windows experience.
- Deliver:
  - `ferrocrate` installer for WSL2.
  - CLI proxy on Windows that calls into WSL2.
  - Port forwarding from Windows host to WSL2.

### Phase 1 — macOS VM Layer
- Use Apple HVF or QEMU/HVF.
- Build minimal Linux VM image with FerroCrate.
- Implement:
  - VM lifecycle: start/stop, auto-start on CLI use.
  - virtiofs mount for host paths.
  - port forwarding from host -> VM.

### Phase 2 — Windows Hyper-V VM Layer
- Use Hyper-V (or fallback QEMU if Hyper-V unavailable).
- VM image identical to macOS.
- Implement:
  - vsock channel for CLI proxy.
  - host filesystem mounts.
  - port forwarding.

### Phase 3 — Desktop UX + Packaging
- Installers:
  - macOS `.dmg` + launch agent.
  - Windows MSI + service.
- Add `ferro-desktop` background daemon.
- Status UI optional (tray/menubar).

## Detailed Component Work

### 1. Host CLI Proxy
- Implement `ferro-desktop` (Rust or Go).
- Provide:
  - socket endpoints for CLI and docker-compat.
  - daemon lifecycle management.
  - config sync and credential pass-through.

### 2. VM Runtime Image
- Minimal Linux (Alpine/Ubuntu minimal).
- Preinstall:
  - FerroCrate runtime binaries.
  - `ip`, `nft`, `slirp4netns`, `fuse-overlayfs`.
- Image build pipeline:
  - reproducible VM image with checksum.

### 3. File Sharing
- macOS:
  - `virtiofsd` on host, mount inside VM.
- Windows:
  - WSL2: leverage `drvfs`.
  - Hyper-V: `9p` or `smb` share.

### 4. Networking
- VM NAT + host port forward table.
- `ferro-desktop` maintains port proxies so `-p` works on host.
- DNS:
  - host DNS forwarded into VM; container DNS uses runtime config.

### 5. Docker Compatibility (Optional)
- Expose `/var/run/docker.sock` equivalent from host.
- Tools like Compose/Testcontainers work with minimal config.

## Security Considerations
- VM isolation is the security boundary.
- Signed VM images and runtime binaries.
- Least-privilege host daemon.
- Secure credential forwarding (never store plaintext in VM).

## Testing Strategy
- CI in GitHub Actions:
  - macOS and Windows runners.
  - Integration tests:
    - Pull/run image
    - Volume mounts
    - Port forwarding
    - Registry auth
- Performance tests:
  - CLI startup latency
  - File I/O throughput
  - Port mapping latency

## Risks and Mitigations
- **File sharing performance**: prefer virtiofs, tune caching.
- **Networking complexity**: build stable port-forwarding layer first.
- **Credential handling**: keep secrets in host only; forward short-lived tokens.

## Suggested Milestones
1. WSL2 proxy + runtime parity on Windows.
2. macOS VM with bind mounts and port forwarding.
3. Windows Hyper-V VM parity.
4. Desktop installers + auto-update.
