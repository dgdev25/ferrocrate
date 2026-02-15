# Ferrocrate VM SSH / cloud-init Debug Report

## Status: RESOLVED (2026-02-15)

All issues identified and fixed. VM boots with working SSH, cloud-init runcmd, 9p host mount, and user/password setup.

## Root Causes Found

### 1. Static instance-id (PRIMARY ROOT CAUSE)

**Symptom**: `runcmd` never executes despite `cloud-final` completing. `cloud-final` finishes in ~0.1s (way too fast).

**Cause**: `meta-data` had a static `instance-id: ferrocrate-vm`. The qcow2 disk persists across VM reinits. Cloud-init stores the processed instance-id in `/var/lib/cloud/data/instance-id`. When the ID matches a previous run, cloud-init treats the boot as a **reboot** and skips all per-instance modules (`runcmd`, `users`, `set_passwords`). Only per-boot modules like `bootcmd` still execute.

**Fix**: Generate a unique instance-id on each `vm init` using an epoch timestamp:
```rust
let instance_ts = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0);
fs::write(&meta_data, format!("instance-id: ferrocrate-vm-{instance_ts}\nlocal-hostname: ferrocrate\n"))?;
```

**Confirmed by**: DeepSeek R1 and Gemini 2.5 Pro via PAL MCP consensus (OpenRouter provider).

### 2. Deprecated `chpasswd.list` format

**Symptom**: Password login fails for `ubuntu` user.

**Cause**: `chpasswd: list: | ubuntu:ferrocrate` was deprecated in cloud-init 23.x and silently ignored in 24.x+. Ubuntu 24.04 cloud images ship cloud-init 25.2.

**Fix**: Use the `users` block with `plain_text_passwd` and `lock_passwd: false`:
```yaml
users:
  - name: ubuntu
    lock_passwd: false
    plain_text_passwd: ferrocrate
    ssh_authorized_keys:
      - <key>
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
```

### 3. ttyS0 output redirect conflicts

**Symptom**: runcmd commands like `mkdir -p /mnt/host > /dev/ttyS0 2>&1` fail silently; 9p mount never happens.

**Cause**: `output: all` already tees cloud-init stdout/stderr to `/dev/ttyS0`. Adding explicit `> /dev/ttyS0 2>&1` redirects on individual runcmd entries causes conflicts — the tee pipe breaks with `tee: 'standard output': Input/output error`, and commands silently fail because their stdout is redirected to a broken pipe instead of cloud-init's capture.

**Fix**: Remove all `> /dev/ttyS0 2>&1` redirects from runcmd entries. Let `output: all` handle serial output. Only use explicit redirects for background processes that outlive cloud-init (like sshd log files).

### 4. Manual sshd launch fragile

**Symptom**: SSH connection reset during key exchange after runcmd runs.

**Cause**: `nohup /usr/sbin/sshd -D -e ... > /dev/ttyS0 2>&1 &` launched from cloud-init's runcmd context is fragile — the process can die when cloud-init's output pipes close.

**Fix**: Use systemd service management instead:
```yaml
runcmd:
  - systemctl disable --now ssh.socket || true
  - systemctl enable ssh.service
  - systemctl restart ssh.service
```

### 5. Debug service dependency cycle

**Symptom**: `systemd: cloud-final.service: Job ferro-cloud-debug.service/start deleted to break ordering cycle`

**Cause**: `ferro-cloud-debug.service` had `After=cloud-init.service cloud-final.service` + `Wants=cloud-final.service`, and runcmd (running inside cloud-final) tried to `enable --now` this service, creating a circular dependency.

**Fix**: Changed to `After=cloud-init.service` only (no cloud-final dependency). Changed runcmd to `systemctl enable` (without `--now`) to avoid the cycle.

### 6. Wrong QEMU backend defaults

**Symptom**: `qemu-system-aarch64: -accel hvf: invalid accelerator hvf` on x86_64 macOS.

**Cause**: CLI default `--backend qemu-hvf` maps to `qemu-system-aarch64`, wrong for x86_64 hosts. Also `--fs-backend virtiofs` requires `virtiofsd` which isn't always installed.

**Fix**: Auto-detect defaults based on host architecture and available tools:
```rust
fn default_vm_backend() -> String {
    if cfg!(target_arch = "aarch64") { "qemu-hvf" } else { "qemu-x86_64" }.to_string()
}
fn default_fs_backend() -> String {
    if Command::new("virtiofsd").arg("--version").output().is_ok() { "virtiofs" } else { "9p" }.to_string()
}
```

## Key cloud-init Lessons

| Module | Frequency | Behavior |
|--------|-----------|----------|
| `bootcmd` | per-boot | Runs every boot regardless of instance-id |
| `runcmd` | per-instance | Runs only on first boot for a given instance-id |
| `users` | per-instance | User/password setup only on first boot |
| `set_passwords` | per-instance | Password changes only on first boot |
| `write_files` | per-instance | File creation only on first boot |
| `package_update` | per-instance | apt update only on first boot |

**Critical rule**: If the qcow2 disk persists and the instance-id doesn't change, cloud-init skips ALL per-instance modules on subsequent boots. The `cloud-final` stage completes instantly (~0.1s) because there's nothing to do.

## Environment
- Host: macOS (x86_64)
- VM: QEMU with HVF acceleration
- Guest: Ubuntu 24.04.3 LTS, cloud-init v25.2
- Datasource: NoCloud via virtio cdrom
- Shared filesystem: 9p `ferrohost` tag
- Code: `ferro-desktop/src/main.rs` — `ensure_cloud_init_iso()` function
