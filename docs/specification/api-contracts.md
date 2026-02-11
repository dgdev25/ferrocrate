# FerroCrate API Contracts

## Overview

This document defines the API contracts for FerroCrate, including Docker socket compatibility and native REST endpoints. FerroCrate implements Docker API v1.45+ compatibility for seamless tool integration while providing enhanced native APIs for FerroCrate-specific features.

---

## 1. API Architecture

### 1.1 Endpoints Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      FerroCrate API Layer                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────┐       ┌─────────────────────┐         │
│  │  Docker Socket API  │       │   Native REST API   │         │
│  │  (Compatibility)    │       │   (Extended)        │         │
│  │                     │       │                     │         │
│  │  /var/run/          │       │  http://localhost:  │         │
│  │  docker.sock        │       │  8989/api/v1/       │         │
│  └──────────┬──────────┘       └──────────┬──────────┘         │
│             │                              │                    │
│             └──────────────┬───────────────┘                    │
│                            │                                    │
│                   ┌────────▼────────┐                          │
│                   │   Core Runtime  │                          │
│                   │   (Rust)        │                          │
│                   └─────────────────┘                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 API Versioning

| API | Version | Path Prefix |
|-----|---------|-------------|
| Docker Compatible | v1.45+ | `/v1.45/` |
| Native REST | v1 | `/api/v1/` |

### 1.3 Content Types

| Request | Response |
|---------|----------|
| `application/json` | `application/json` |
| `application/x-tar` | `application/x-tar` (image export) |
| `text/plain` | `text/plain` (logs) |

---

## 2. Docker Socket Compatibility API

The Docker-compatible API enables tools expecting Docker to work with FerroCrate without modification.

### 2.1 Container Operations

#### List Containers

```
GET /containers/json
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `all` | bool | false | Show all containers (including stopped) |
| `limit` | int | - | Limit number of results |
| `size` | bool | false | Include container sizes |
| `filters` | string | - | JSON-encoded filter map |

**Filters:**
```json
{
  "status": ["running", "exited"],
  "label": ["com.example.key=value"],
  "name": ["container-name"],
  "network": ["bridge"],
  "ancestor": ["nginx:latest"]
}
```

**Response:**
```json
[
  {
    "Id": "abc123def456...",
    "Names": ["/my-container"],
    "Image": "nginx:latest",
    "ImageID": "sha256:abc123...",
    "Command": "/docker-entrypoint.sh nginx -g 'daemon off;'",
    "Created": 1707667200,
    "State": "running",
    "Status": "Up 2 hours",
    "Ports": [
      {
        "IP": "0.0.0.0",
        "PrivatePort": 80,
        "PublicPort": 8080,
        "Type": "tcp"
      }
    ],
    "Labels": {
      "com.example.key": "value"
    },
    "HostConfig": {
      "NetworkMode": "bridge"
    },
    "NetworkSettings": {
      "Networks": {
        "bridge": {
          "IPAMConfig": null,
          "Links": null,
          "Aliases": null,
          "NetworkID": "abc123...",
          "EndpointID": "def456...",
          "Gateway": "172.17.0.1",
          "IPAddress": "172.17.0.2",
          "IPPrefixLen": 16,
          "IPv6Gateway": "",
          "GlobalIPv6Address": "",
          "GlobalIPv6PrefixLen": 0,
          "MacAddress": "02:42:ac:11:00:02"
        }
      }
    },
    "Mounts": []
  }
]
```

#### Create Container

```
POST /containers/create
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Container name |
| `platform` | string | Platform (e.g., linux/amd64) |

**Request Body:**
```json
{
  "Hostname": "",
  "Domainname": "",
  "User": "",
  "AttachStdin": false,
  "AttachStdout": true,
  "AttachStderr": true,
  "Tty": false,
  "OpenStdin": false,
  "StdinOnce": false,
  "Env": ["FOO=bar", "BAZ=qux"],
  "Cmd": ["/bin/bash", "-c", "echo hello"],
  "Healthcheck": {
    "Test": ["CMD", "curl", "-f", "http://localhost/"],
    "Interval": 30000000000,
    "Timeout": 3000000000,
    "Retries": 3,
    "StartPeriod": 0
  },
  "ArgsEscaped": false,
  "Entrypoint": null,
  "Image": "ubuntu:latest",
  "Volumes": {
    "/tmp": {}
  },
  "WorkingDir": "",
  "MacAddress": "",
  "OnBuild": null,
  "NetworkDisabled": false,
  "StopSignal": "SIGTERM",
  "StopTimeout": 10,
  "HostConfig": {
    "Binds": ["/host/path:/container/path:ro"],
    "Links": null,
    "Memory": 536870912,
    "MemorySwap": -1,
    "MemoryReservation": 0,
    "MemorySwappiness": -1,
    "CpuShares": 1024,
    "CpuPeriod": 0,
    "CpuQuota": 0,
    "CpuRealtimePeriod": 0,
    "CpuRealtimeRuntime": 0,
    "CpusetCpus": "",
    "CpusetMems": "",
    "Devices": [],
    "DeviceCgroupRules": null,
    "DeviceRequests": null,
    "KernelMemory": -1,
    "KernelMemoryTCP": -1,
    "MemoryReservation": 0,
    "NanoCpus": 0,
    "OomKillDisable": false,
    "PidsLimit": -1,
    "Ulimits": null,
    "CpuCount": 0,
    "CpuPercent": 0,
    "IOMaximumIOps": 0,
    "IOMaximumBandwidth": 0,
    "RestartPolicy": {
      "Name": "on-failure",
      "MaximumRetryCount": 3
    },
    "AutoRemove": false,
    "VolumeDriver": "",
    "VolumesFrom": null,
    "CapAdd": ["NET_ADMIN"],
    "CapDrop": ["ALL"],
    "CgroupnsMode": "private",
    "Dns": [],
    "DnsOptions": [],
    "DnsSearch": [],
    "ExtraHosts": [],
    "GroupAdd": [],
    "IpcMode": "private",
    "Cgroup": "",
    "Links": null,
    "OomScoreAdj": 0,
    "PidMode": "",
    "Privileged": false,
    "PublishAllPorts": false,
    "ReadonlyRootfs": false,
    "SecurityOpt": ["seccomp=unconfined", "apparmor=ferrocrate-default"],
    "StorageOpt": null,
    "Tmpfs": { "/run": "rw,size=64m" },
    "UTSMode": "",
    "UsernsMode": "",
    "ShmSize": 67108864,
    "Sysctls": { "net.core.somaxconn": "1024" },
    "Runtime": "runc",
    "ConsoleSize": [0, 0],
    "Isolation": "",
    "Resources": {
      "CpuShares": 0,
      "Memory": 0,
      "NanoCpus": 0,
      "CpuPeriod": 0,
      "CpuQuota": 0,
      "CpuRealtimePeriod": 0,
      "CpuRealtimeRuntime": 0,
      "CpusetCpus": "",
      "CpusetMems": "",
      "Devices": [],
      "DeviceCgroupRules": null,
      "DeviceRequests": null,
      "KernelMemory": -1,
      "KernelMemoryTCP": -1,
      "MemoryReservation": 0,
      "MemorySwap": -1,
      "MemorySwappiness": -1,
      "NanoCpus": 0,
      "OomKillDisable": false,
      "PidsLimit": -1,
      "Ulimits": null,
      "CpuCount": 0,
      "CpuPercent": 0,
      "IOMaximumIOps": 0,
      "IOMaximumBandwidth": 0
    },
    "Mounts": [
      {
        "Target": "/data",
        "Source": "my-volume",
        "Type": "volume",
        "ReadOnly": false,
        "VolumeOptions": {
          "NoCopy": false,
          "Labels": {},
          "DriverConfig": {
            "Name": "local",
            "Options": {}
          }
        }
      }
    ],
    "Init": true,
    "InitPath": "/usr/bin/tini",
    "NetworkMode": "bridge",
    "PortBindings": {
      "80/tcp": [
        {
          "HostIp": "0.0.0.0",
          "HostPort": "8080"
        }
      ]
    },
    "LogConfig": {
      "Type": "json-file",
      "Config": {
        "max-size": "10m",
        "max-file": "3"
      }
    }
  },
  "NetworkingConfig": {
    "EndpointsConfig": {
      "bridge": {
        "IPAMConfig": {
          "IPv4Address": "172.17.0.100"
        },
        "Links": null,
        "Aliases": ["web"]
      }
    }
  }
}
```

**Response:**
```json
{
  "Id": "abc123def456789...",
  "Warnings": []
}
```

#### Inspect Container

```
GET /containers/{id}/json
```

**Response:** (Full container details - see Docker API spec)

Key fields specific to FerroCrate:
```json
{
  "Id": "abc123...",
  "Created": "2026-02-11T10:00:00.000000000Z",
  "Path": "/docker-entrypoint.sh",
  "Args": ["nginx", "-g", "daemon off;"],
  "State": {
    "Status": "running",
    "Running": true,
    "Paused": false,
    "Restarting": false,
    "OOMKilled": false,
    "Dead": false,
    "Pid": 12345,
    "ExitCode": 0,
    "Error": "",
    "StartedAt": "2026-02-11T10:00:01.000000000Z",
    "FinishedAt": "0001-01-01T00:00:00Z",
    "Health": {
      "Status": "healthy",
      "FailingStreak": 0,
      "Log": [
        {
          "Start": "2026-02-11T10:01:00.000000000Z",
          "End": "2026-02-11T10:01:00.100000000Z",
          "ExitCode": 0,
          "Output": ""
        }
      ]
    }
  },
  "Image": "sha256:abc123...",
  "ResolvConfPath": "/var/lib/ferrocrate/containers/abc123.../resolv.conf",
  "HostnamePath": "/var/lib/ferrocrate/containers/abc123.../hostname",
  "HostsPath": "/var/lib/ferrocrate/containers/abc123.../hosts",
  "LogPath": "/var/lib/ferrocrate/containers/abc123.../json.log",
  "Name": "/my-container",
  "RestartCount": 0,
  "Driver": "overlay2",
  "Platform": "linux",
  "MountLabel": "",
  "ProcessLabel": "",
  "AppArmorProfile": "ferrocrate-default",
  "ExecIDs": null,
  "HostConfig": {
    "SecurityOpt": ["no-new-privileges", "seccomp=default"]
  },
  "GraphDriver": {
    "Data": {
      "LowerDir": "/var/lib/ferrocrate/overlay2/l/ABC...:/var/lib/ferrocrate/overlay2/l/DEF...",
      "MergedDir": "/var/lib/ferrocrate/overlay2/abc123.../merged",
      "UpperDir": "/var/lib/ferrocrate/overlay2/abc123.../diff",
      "WorkDir": "/var/lib/ferrocrate/overlay2/abc123.../work"
    },
    "Name": "overlay2"
  },
  "Config": {
    "Hostname": "abc123...",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": true,
    "AttachStderr": true,
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "FOO=bar"],
    "Cmd": ["nginx", "-g", "daemon off;"],
    "Image": "nginx:latest",
    "Volumes": null,
    "WorkingDir": "",
    "Entrypoint": ["/docker-entrypoint.sh"],
    "OnBuild": null,
    "Labels": {
      "com.example.key": "value"
    },
    "StopSignal": "SIGTERM",
    "Healthcheck": {
      "Test": ["CMD", "curl", "-f", "http://localhost/"],
      "Interval": 30000000000,
      "Timeout": 3000000000,
      "Retries": 3
    }
  }
}
```

#### Start Container

```
POST /containers/{id}/start
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `detachKeys` | string | Override default detach keys |

**Response:** 204 No Content

#### Stop Container

```
POST /containers/{id}/stop
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `signal` | string | SIGTERM | Signal to send |
| `t` | int | 10 | Seconds to wait before killing |

**Response:** 204 No Content

#### Kill Container

```
POST /containers/{id}/kill
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `signal` | string | SIGKILL | Signal to send |

**Response:** 204 No Content

#### Restart Container

```
POST /containers/{id}/restart
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `signal` | string | SIGTERM | Signal to send |
| `t` | int | 10 | Seconds to wait before killing |

**Response:** 204 No Content

#### Remove Container

```
DELETE /containers/{id}
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `v` | bool | false | Remove volumes |
| `link` | bool | false | Remove link |
| `force` | bool | false | Force remove running container |

**Response:** 204 No Content

#### Get Container Logs

```
GET /containers/{id}/logs
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `follow` | bool | false | Stream logs |
| `stdout` | bool | false | Include stdout |
| `stderr` | bool | false | Include stderr |
| `since` | int | 0 | Unix timestamp |
| `until` | int | 0 | Unix timestamp |
| `timestamps` | bool | false | Add timestamps |
| `tail` | string | all | Number of lines |

**Response:** Stream with 8-byte header per frame
```
[STREAM_TYPE(1)][0][0][0][SIZE(4)][PAYLOAD...]
```

#### Execute Command in Container

```
POST /containers/{id}/exec
```

**Request Body:**
```json
{
  "AttachStdin": true,
  "AttachStdout": true,
  "AttachStderr": true,
  "DetachKeys": "ctrl-p,ctrl-q",
  "Tty": true,
  "Cmd": ["ls", "-la", "/app"],
  "Env": ["FOO=bar"],
  "User": "root",
  "WorkingDir": "/app"
}
```

**Response:**
```json
{
  "Id": "exec123..."
}
```

#### Start Exec Instance

```
POST /exec/{id}/start
```

**Request Body:**
```json
{
  "Detach": false,
  "Tty": true,
  "ConsoleSize": [80, 24]
}
```

#### Container Stats

```
GET /containers/{id}/stats
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `stream` | bool | true | Stream stats |
| `one-shot` | bool | false | Get single stat |

**Response:**
```json
{
  "read": "2026-02-11T10:00:00.000000000Z",
  "preread": "2026-02-11T09:59:59.000000000Z",
  "pids_stats": {
    "current": 5,
    "limit": 1024
  },
  "blkio_stats": {
    "io_service_bytes_recursive": [
      {"major": 8, "minor": 0, "op": "Read", "value": 1048576},
      {"major": 8, "minor": 0, "op": "Write", "value": 524288}
    ]
  },
  "num_procs": 0,
  "storage_stats": {},
  "cpu_stats": {
    "cpu_usage": {
      "total_usage": 5000000000,
      "percpu_usage": [2500000000, 2500000000],
      "usage_in_kernelmode": 1000000000,
      "usage_in_usermode": 4000000000
    },
    "system_cpu_usage": 100000000000,
    "online_cpus": 2,
    "throttling_data": {
      "periods": 0,
      "throttled_periods": 0,
      "throttled_time": 0
    }
  },
  "precpu_stats": { ... },
  "memory_stats": {
    "usage": 52428800,
    "max_usage": 104857600,
    "limit": 536870912,
    "stats": {
      "active_anon": 10485760,
      "active_file": 20971520,
      "cache": 31457280,
      "inactive_anon": 0,
      "inactive_file": 10485760,
      "mapped_file": 5242880,
      "pgfault": 12345,
      "pgmajfault": 10,
      "pgpgin": 5000,
      "pgpgout": 3000,
      "rss": 20971520,
      "rss_huge": 0,
      "total_active_anon": 10485760,
      "total_active_file": 20971520,
      "total_cache": 31457280,
      "total_inactive_anon": 0,
      "total_inactive_file": 10485760,
      "total_mapped_file": 5242880,
      "total_pgfault": 12345,
      "total_pgmajfault": 10,
      "total_pgpgin": 5000,
      "total_pgpgout": 3000,
      "total_rss": 20971520,
      "total_rss_huge": 0,
      "total_unevictable": 0,
      "total_writeback": 0,
      "unevictable": 0,
      "writeback": 0
    },
    "commit": 0,
    "commitpeak": 0,
    "privateworkingset": 0
  },
  "name": "/my-container",
  "id": "abc123...",
  "networks": {
    "eth0": {
      "rx_bytes": 1048576,
      "rx_dropped": 0,
      "rx_errors": 0,
      "rx_packets": 1000,
      "tx_bytes": 524288,
      "tx_dropped": 0,
      "tx_errors": 0,
      "tx_packets": 500
    }
  }
}
```

### 2.2 Image Operations

#### List Images

```
GET /images/json
```

**Response:**
```json
[
  {
    "Id": "sha256:abc123...",
    "RepoTags": ["nginx:latest", "nginx:1.25"],
    "RepoDigests": ["nginx@sha256:def456..."],
    "Created": 1707667200,
    "Size": 142000000,
    "SharedSize": 0,
    "VirtualSize": 142000000,
    "Labels": {
      "maintainer": "NGINX Docker Maintainers"
    },
    "Containers": 2
  }
]
```

#### Create Image (Pull)

```
POST /images/create
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `fromImage` | string | Image name to pull |
| `fromSrc` | string | Source to import from |
| `repo` | string | Repository name |
| `tag` | string | Tag |
| `message` | string | Commit message |
| `platform` | string | Platform |

**Response:** JSON stream
```json
{"status": "Pulling from library/nginx", "id": "latest"}
{"status": "Pulling fs layer", "progressDetail": {}, "id": "abc123"}
{"status": "Downloading", "progressDetail": {"current": 1024, "total": 1048576}, "id": "abc123"}
{"status": "Download complete", "id": "abc123"}
{"status": "Pull complete", "id": "abc123"}
{"status": "Digest: sha256:def456..."}
{"status": "Status: Downloaded newer image for nginx:latest"}
```

#### Build Image

```
POST /build
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `dockerfile` | string | Path to Dockerfile |
| `t` | string | Tag(s) |
| `extrahosts` | string | Extra hosts |
| `remote` | string | Git URL |
| `q` | bool | Suppress output |
| `nocache` | bool | Disable cache |
| `cachefrom` | string | Cache source images |
| `pull` | string | Pull mode |
| `rm` | bool | Remove intermediate |
| `forcerm` | bool | Force remove intermediate |
| `memory` | int | Memory limit |
| `memswap` | int | Swap limit |
| `cpushares` | int | CPU shares |
| `cpusetcpus` | string | CPUs to use |
| `cpuperiod` | int | CPU period |
| `cpuquota` | int | CPU quota |
| `buildargs` | string | Build args (JSON) |
| `shmsize` | int | SHM size |
| `squash` | bool | Squash layers |
| `labels` | string | Labels (JSON) |
| `networkmode` | string | Network mode |
| `platform` | string | Platform |
| `target` | string | Target stage |
| `outputs` | string | Build outputs |

**Request:** tar stream of build context

**Response:** JSON stream with build output

#### Push Image

```
POST /images/{name}/push
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tag` | string | Tag |

**Headers:**
- `X-Registry-Auth`: Base64 encoded registry auth

### 2.3 Network Operations

#### List Networks

```
GET /networks/json
```

**Response:**
```json
[
  {
    "Name": "bridge",
    "Id": "abc123...",
    "Created": "2026-02-11T10:00:00.000000000Z",
    "Scope": "local",
    "Driver": "bridge",
    "EnableIPv6": false,
    "IPAM": {
      "Driver": "default",
      "Options": null,
      "Config": [
        {
          "Subnet": "172.17.0.0/16",
          "Gateway": "172.17.0.1"
        }
      ]
    },
    "Internal": false,
    "Attachable": false,
    "Ingress": false,
    "ConfigFrom": {
      "Network": ""
    },
    "ConfigOnly": false,
    "Containers": {},
    "Options": {
      "com.docker.network.bridge.default_bridge": "true",
      "com.docker.network.bridge.enable_icc": "true",
      "com.docker.network.bridge.enable_ip_masquerade": "true",
      "com.docker.network.bridge.name": "ferro0"
    },
    "Labels": {}
  }
]
```

### 2.4 Volume Operations

#### List Volumes

```
GET /volumes
```

**Response:**
```json
{
  "Volumes": [
    {
      "Name": "my-volume",
      "Driver": "local",
      "Mountpoint": "/var/lib/ferrocrate/volumes/my-volume/_data",
      "CreatedAt": "2026-02-11T10:00:00.000000000Z",
      "Status": {},
      "Labels": {},
      "Scope": "local",
      "Options": {},
      "UsageData": {
        "Size": 1048576,
        "RefCount": 1
      }
    }
  ],
  "Warnings": []
}
```

### 2.5 System Operations

#### System Info

```
GET /info
```

**Response:**
```json
{
  "ID": "abc123...",
  "Containers": 10,
  "ContainersRunning": 5,
  "ContainersPaused": 0,
  "ContainersStopped": 5,
  "Images": 25,
  "Driver": "overlay2",
  "DriverStatus": [
    ["Backing Filesystem", "extfs"],
    ["Supports d_type", "true"],
    ["Native Overlay Diff", "true"]
  ],
  "SystemStatus": null,
  "Plugins": {
    "Volume": ["local"],
    "Network": ["bridge", "host", "null"],
    "Authorization": null,
    "Log": ["json-file", "journald"]
  },
  "MemoryLimit": true,
  "SwapLimit": true,
  "KernelMemory": false,
  "KernelMemoryTCP": false,
  "CpuCfsPeriod": true,
  "CpuCfsQuota": true,
  "CPUShares": true,
  "CPUSet": true,
  "PidsLimit": true,
  "IPv4Forwarding": true,
  "BridgeNfIptables": true,
  "BridgeNfIp6tables": true,
  "Debug": false,
  "NFd": 25,
  "OomKillDisable": true,
  "NGoroutines": 50,
  "SystemTime": "2026-02-11T10:00:00.000000000Z",
  "LoggingDriver": "json-file",
  "CgroupDriver": "cgroupfs",
  "CgroupVersion": "2",
  "NEventsListener": 0,
  "KernelVersion": "6.1.0-14-generic",
  "OperatingSystem": "Ubuntu 24.04 LTS",
  "OSVersion": "",
  "OSType": "linux",
  "Architecture": "x86_64",
  "IndexServerAddress": "https://index.docker.io/v1/",
  "RegistryConfig": {},
  "NCPU": 8,
  "MemTotal": 16777216000,
  "GenericResources": null,
  "DockerRootDir": "/var/lib/ferrocrate",
  "HttpProxy": "",
  "HttpsProxy": "",
  "NoProxy": "",
  "Name": "hostname",
  "Labels": [],
  "ExperimentalBuild": false,
  "ServerVersion": "1.0.0",
  "Runtimes": {
    "runc": {
      "path": "runc"
    },
    "ferrocrate": {
      "path": "/usr/bin/ferro-exec"
    }
  },
  "DefaultRuntime": "ferrocrate",
  "SecurityOptions": [
    "name=seccomp,profile=default",
    "name=apparmor,profile=ferrocrate-default",
    "name=no-new-privileges"
  ],
  "LiveRestoreEnabled": false,
  "InitBinary": "tini",
  "ContainerdCommit": {"ID": "", "Expected": ""},
  "RuncCommit": {"ID": "", "Expected": ""},
  "InitCommit": {"ID": "", "Expected": ""},
  "Warnings": []
}
```

#### Version

```
GET /version
```

**Response:**
```json
{
  "Platform": {
    "Name": "FerroCrate"
  },
  "Components": [
    {
      "Name": "Engine",
      "Version": "1.0.0",
      "Details": {
        "ApiVersion": "1.45",
        "Arch": "amd64",
        "BuildTime": "2026-02-11T10:00:00.000Z",
        "Experimental": "false",
        "GitCommit": "abc123",
        "GoVersion": "go1.21.0",
        "KernelVersion": "6.1.0-14-generic",
        "MinAPIVersion": "1.12",
        "Os": "linux"
      }
    }
  ],
  "Version": "1.0.0",
  "ApiVersion": "1.45",
  "MinAPIVersion": "1.12",
  "GitCommit": "abc123",
  "GoVersion": "go1.21.0",
  "Os": "linux",
  "Arch": "amd64",
  "KernelVersion": "6.1.0-14-generic",
  "BuildTime": "2026-02-11T10:00:00.000Z"
}
```

#### Events

```
GET /events
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `since` | string | Unix timestamp or duration |
| `until` | string | Unix timestamp or duration |
| `filters` | string | JSON-encoded filters |

**Response:** JSON stream
```json
{
  "Type": "container",
  "Action": "start",
  "Actor": {
    "ID": "abc123...",
    "Attributes": {
      "image": "nginx:latest",
      "name": "my-container"
    }
  },
  "scope": "local",
  "time": 1707667200,
  "timeNano": 1707667200000000000
}
```

---

## 3. Native REST API (Extended)

FerroCrate-specific endpoints for AI features and advanced functionality.

### 3.1 AI Intelligence Endpoints

#### Predict Resources

```
GET /api/v1/containers/{id}/predict
```

**Response:**
```json
{
  "container_id": "abc123...",
  "predictions": {
    "memory": {
      "current_mb": 512,
      "predicted_mb": 640,
      "confidence": 0.85,
      "recommendation": "Consider increasing memory limit to 700MB"
    },
    "cpu": {
      "current_percent": 45,
      "predicted_percent": 62,
      "confidence": 0.78
    }
  },
  "model_version": "wasm-v1.0.0",
  "prediction_time_ms": 0.8,
  "timestamp": "2026-02-11T10:00:00.000Z"
}
```

#### AI Analysis

```
POST /api/v1/ai/analyze
```

**Request Body:**
```json
{
  "query": "Why did my web server container crash?",
  "container_id": "abc123...",
  "include_logs": true,
  "include_metrics": true,
  "detail_level": "comprehensive"
}
```

**Response:**
```json
{
  "analysis_id": "ana_xyz789",
  "query": "Why did my web server container crash?",
  "root_cause": {
    "type": "oom_killed",
    "description": "Container exceeded memory limit and was OOM killed",
    "confidence": 0.95
  },
  "contributing_factors": [
    {
      "factor": "Memory leak in application",
      "evidence": "Memory usage grew from 200MB to 512MB over 2 hours",
      "confidence": 0.80
    },
    {
      "factor": "Insufficient memory limit",
      "evidence": "Limit set to 512MB; peak usage reached 520MB",
      "confidence": 0.90
    }
  ],
  "recommendations": [
    {
      "priority": "high",
      "action": "Increase memory limit to 768MB",
      "command": "ferrocrate update --memory 768m abc123..."
    },
    {
      "priority": "medium",
      "action": "Investigate memory leak in application code",
      "details": "Profile application memory allocation patterns"
    }
  ],
  "evidence": {
    "log_excerpt": "Out of memory: Killed process 1234 (node)",
    "metrics_snapshot": {
      "memory_peak_mb": 520,
      "memory_limit_mb": 512,
      "oom_events": 1
    }
  },
  "routing": {
    "backend": "wasm",
    "latency_ms": 0.9
  },
  "timestamp": "2026-02-11T10:00:00.000Z"
}
```

#### Explain Decision

```
GET /api/v1/ai/decisions/{decision_id}
```

**Response:**
```json
{
  "decision_id": "dec_abc123",
  "action": "increase_memory_limit",
  "target": "container:xyz789",
  "timestamp": "2026-02-11T10:00:00.000Z",
  "reasoning": {
    "trigger": "Anomaly detected: memory usage at 95% of limit",
    "analysis": "Historical patterns show 15% memory growth per hour",
    "factors": [
      "Time of day: peak traffic hours approaching",
      "Recent deployment: new feature may increase memory",
      "Trend: consistent growth over past 3 days"
    ],
    "decision_logic": "If (usage > 90%) AND (growth_trend > 0) THEN increase_limit"
  },
  "input_data": {
    "current_limit_mb": 512,
    "current_usage_mb": 486,
    "growth_rate_mb_per_hour": 12
  },
  "output": {
    "new_limit_mb": 640,
    "applied": true
  },
  "confidence": 0.88
}
```

#### Anomaly Alerts

```
GET /api/v1/alerts
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | all | Filter by severity |
| `container` | string | all | Filter by container |
| `since` | string | 24h | Time range |
| `limit` | int | 50 | Max results |

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert_001",
      "container_id": "abc123...",
      "container_name": "api-server",
      "severity": "high",
      "type": "memory_anomaly",
      "message": "Memory usage exceeded 90% of limit",
      "details": {
        "current_percent": 92,
        "limit_mb": 512,
        "usage_mb": 471
      },
      "recommendation": "Increase memory limit or investigate memory usage",
      "timestamp": "2026-02-11T10:00:00.000Z",
      "acknowledged": false
    }
  ],
  "total": 1
}
```

### 3.2 Security Endpoints

#### Audit Log Query

```
GET /api/v1/audit
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `start` | string | ISO 8601 timestamp |
| `end` | string | ISO 8601 timestamp |
| `event_type` | string | Filter by event type |
| `container` | string | Filter by container |
| `actor` | string | Filter by actor |
| `limit` | int | Max results |

**Response:**
```json
{
  "events": [
    {
      "event_id": "evt_abc123",
      "timestamp": "2026-02-11T10:00:00.000Z",
      "event_type": "container.create",
      "actor": {
        "type": "user",
        "id": "dana",
        "ip": "192.168.1.100"
      },
      "resource": {
        "type": "container",
        "id": "ctr_xyz789",
        "image": "nginx:latest"
      },
      "action": {
        "operation": "create",
        "result": "success"
      },
      "security": {
        "rootless": true,
        "seccomp": "default",
        "capabilities": []
      }
    }
  ],
  "pagination": {
    "total": 150,
    "offset": 0,
    "limit": 50
  }
}
```

#### Security Scan

```
POST /api/v1/security/scan
```

**Request Body:**
```json
{
  "image": "myapp:latest",
  "severity_threshold": "high",
  "include_fixable": true
}
```

**Response:**
```json
{
  "scan_id": "scan_abc123",
  "image": "myapp:latest",
  "status": "completed",
  "summary": {
    "total": 15,
    "critical": 0,
    "high": 3,
    "medium": 5,
    "low": 7,
    "fixable": 10
  },
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "severity": "high",
      "package": "openssl",
      "version": "3.0.0",
      "fixed_version": "3.0.1",
      "description": "Buffer overflow in X.509 certificate verification",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"]
    }
  ],
  "scanned_at": "2026-02-11T10:00:00.000Z"
}
```

### 3.3 Compose Endpoints

#### Compose Project Status

```
GET /api/v1/compose/{project}/status
```

**Response:**
```json
{
  "project": "myapp",
  "status": "running",
  "services": {
    "web": {
      "status": "running",
      "replicas": 2,
      "healthy": 2
    },
    "db": {
      "status": "running",
      "replicas": 1,
      "healthy": 1
    },
    "redis": {
      "status": "running",
      "replicas": 1,
      "healthy": 1
    }
  },
  "networks": ["myapp_default"],
  "volumes": ["myapp_db_data"],
  "started_at": "2026-02-11T08:00:00.000Z"
}
```

### 3.4 Metrics Endpoints

#### Prometheus Metrics

```
GET /metrics
```

**Response:** Prometheus text format
```
# HELP ferrocrate_containers_total Total number of containers
# TYPE ferrocrate_containers_total gauge
ferrocrate_containers_total{state="running"} 5
ferrocrate_containers_total{state="stopped"} 3

# HELP ferrocrate_container_memory_bytes Container memory usage in bytes
# TYPE ferrocrate_container_memory_bytes gauge
ferrocrate_container_memory_bytes{container="web-1"} 5.24288e+07
ferrocrate_container_memory_bytes{container="db-1"} 1.048576e+08

# HELP ferrocrate_container_cpu_seconds_total Total CPU seconds
# TYPE ferrocrate_container_cpu_seconds_total counter
ferrocrate_container_cpu_seconds_total{container="web-1"} 123.45

# HELP ferrocrate_image_pulls_total Total image pulls
# TYPE ferrocrate_image_pulls_total counter
ferrocrate_image_pulls_total{registry="docker.io"} 150

# HELP ferrocrate_ai_decisions_total Total AI decisions made
# TYPE ferrocrate_ai_decisions_total counter
ferrocrate_ai_decisions_total{backend="wasm",result="success"} 50
ferrocrate_ai_decisions_total{backend="claude",result="success"} 5

# HELP ferrocrate_build_duration_seconds Build duration in seconds
# TYPE ferrocrate_build_duration_seconds histogram
ferrocrate_build_duration_seconds_bucket{le="10"} 10
ferrocrate_build_duration_seconds_bucket{le="30"} 25
ferrocrate_build_duration_seconds_bucket{le="60"} 40
ferrocrate_build_duration_seconds_bucket{le="120"} 48
ferrocrate_build_duration_seconds_bucket{le="+Inf"} 50
ferrocrate_build_duration_seconds_sum 1800
ferrocrate_build_duration_seconds_count 50
```

---

## 4. WebSocket Endpoints

### 4.1 Container Attach

```
GET /containers/{id}/attach/ws
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `logs` | bool | Include previous logs |
| `stream` | bool | Stream data |
| `stdin` | bool | Attach to stdin |
| `stdout` | bool | Attach to stdout |
| `stderr` | bool | Attach to stderr |

### 4.2 Exec WebSocket

```
GET /exec/{id}/websocket
```

Provides WebSocket-based exec for interactive terminals.

---

## 5. Error Responses

### 5.1 Standard Error Format

```json
{
  "message": "Container abc123 not found",
  "code": 404,
  "details": {
    "container_id": "abc123"
  }
}
```

### 5.2 Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `container_not_found` | 404 | Container does not exist |
| `image_not_found` | 404 | Image does not exist |
| `container_already_exists` | 409 | Container name conflict |
| `invalid_parameter` | 400 | Invalid request parameter |
| `permission_denied` | 403 | Insufficient permissions |
| `conflict` | 409 | Operation conflicts with state |
| `server_error` | 500 | Internal server error |
| `timeout` | 504 | Operation timeout |

---

## 6. Rate Limiting

### 6.1 Default Limits

| Endpoint Category | Rate Limit |
|-------------------|------------|
| Container operations | 100/min |
| Image operations | 30/min |
| Build operations | 10/min |
| AI operations | 50/min |

### 6.2 Headers

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1707667800
```

---

## 7. API Compatibility Matrix

| Feature | Docker API | FerroCrate API |
|---------|-----------|----------------|
| Container CRUD | Yes | Yes |
| Image Pull/Push | Yes | Yes |
| Build | Yes | Yes |
| Networks | Yes | Yes |
| Volumes | Yes | Yes |
| Events | Yes | Yes |
| AI Diagnostics | No | Yes |
| Predictive Scaling | No | Yes |
| Anomaly Detection | No | Yes |
| Audit Log | No | Yes |
| Security Scan | No | Yes |
| Prometheus Metrics | No | Yes |

---

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Last Updated | 2026-02-11 |
| API Version | Docker v1.45 / Native v1 |
| Author | FerroCrate Team |
