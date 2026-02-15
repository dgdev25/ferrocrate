# Cloud-init / VM SSH Fixes Summary (2026-02-15)

All bugs preventing VM SSH access and cloud-init runcmd execution have been resolved.

## Fixes

| Bug | Root Cause | Fix | Verified |
|-----|-----------|-----|----------|
| **runcmd never executes** | Static `instance-id` — cloud-init skips per-instance modules on persistent disk | Timestamp-based unique instance-id: `ferrocrate-vm-{epoch}` | `cloud-init-runcmd-start` on serial |
| **Password login fails** | `chpasswd.list` deprecated in cloud-init 23.x+ | `users` block with `plain_text_passwd` + `lock_passwd: false` | `ubuntu P` in passwd status |
| **SSH connection reset** | Manual `nohup sshd -D` fragile in cloud-init context | `systemctl restart ssh.service` | SSH key auth works |
| **ttyS0 redirect conflicts** | `> /dev/ttyS0` on runcmd lines fights with `output: all` tee | Removed all explicit ttyS0 redirects from runcmd | mkdir/mount succeed |
| **Debug service cycle** | `After=cloud-final.service` + runcmd enable = circular dep | Changed to `After=cloud-init.service` only | No systemd cycle warnings |
| **Wrong QEMU binary** | Default `qemu-hvf` = aarch64 on x86_64 host | Auto-detect: `cfg!(target_arch)` for backend, PATH check for virtiofsd | `qemu-x86_64` + `9p` auto-selected |
| **9p mount fails** | Output redirect broke mkdir | Clean runcmd without redirects | `ferrohost on /mnt/host type 9p` |

## Changed Files

- `ferro-desktop/src/main.rs`

## See Also

- [cloud-init-ssh-debug.md](cloud-init-ssh-debug.md) — full debug report with root cause analysis
