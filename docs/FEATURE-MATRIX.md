# Ferrocrate feature matrix

This is the public source of truth for Ferrocrate's alpha support boundary.
Internal qualification records are retained outside the public repository.
A release must not promote a row without fresh candidate testing.

## Status terms

- **Supported** means the behavior is part of the advertised alpha contract.
- **Experimental** means the implementation exists but remains opt-in or narrowly qualified.
- **In progress** means the path exists but is not ready for a support claim.
- **Unsupported** means Ferrocrate rejects the request explicitly.

## Platforms

| Platform | Status |
| --- | --- |
| Ubuntu 24.04 and 26.04, x86_64, rootful | Supported |
| Debian 12 and 13, Fedora 42, Alpine 3.22, x86_64, rootful | Supported |
| Ubuntu 24.04 on Oracle A1, aarch64 | Supported |
| Rocky 9 and Ubuntu 20.04 HWE | Experimental; requires opt-in `legacy-peercred` |
| Rootless Linux | Experimental; host kernel, user namespaces, cgroup v2, AppArmor, and helper availability apply |
| Windows 11 through WSL2 | In progress |
| macOS through a Linux VM | In progress |
| Host-native Windows or macOS container execution | Unsupported |

## Product surface

| Area | Status and boundary |
| --- | --- |
| Image pull, list, inspect, tag, remove, save, load, export, and import | Supported |
| Registry authentication and TLS | Supported; external registries remain subject to registry compatibility |
| Dockerfile build and cache | Supported for the documented Dockerfile subset |
| BuildKit through the authenticated Docker driver | Supported for local `dockerfile.v0`; arbitrary LLB and `gateway.v0` are unsupported |
| Container lifecycle, logs, exec, attach, TTY, and resize | Supported |
| Named volumes, bind mounts, and read-only mounts | Supported |
| Bridge networking through iptables or nftables | Supported |
| Multi-network containers and per-network DNS aliases | Supported on the qualified rootful tier |
| Published IPv4 ports | Supported on qualified rootful and rootless hosts |
| IPv6 address lifecycle | Supported; globally routed and published IPv6 remain host-dependent |
| eBPF published ports | Experimental and opt-in |
| Compose up/down, volumes, configs, secrets, health, profiles, scale, and watch | Supported on qualified hosts |
| Docker Engine API | Supported subset; unsupported endpoints return explicit errors |
| CRI v1 image, sandbox, and container lifecycle | Experimental; fixture-qualified, not a broad kubelet compatibility claim |
| Seccomp and capability/device restrictions | Supported on qualified Linux hosts |
| AppArmor and SELinux enforcement | Supported where the matching host policy is installed |
| Crash and daemon-restart recovery | Supported |
| Host reboot and disk-full recovery | In progress |
| AI monitoring and automated actions | Experimental; autonomous actions require explicit opt-in |
| RVF/QEMU image launcher | Experimental; dry-run by default |
| Fleet control plane and browser UI | Experimental |
| Local dashboard | Supported on the qualified Linux tier |

## Explicitly unsupported

- `POST /plugins/pull`.
- Host-native Windows or macOS engine execution without WSL2 or a Linux VM.
- Foreign-architecture emulation, `--platform` builds, and multi-architecture manifests.
- Arbitrary BuildKit LLB and `gateway.v0` frontends.

## Maintenance rule

Update this matrix in the same change that changes an advertised capability.
Historical test results do not override the current release boundary.
