# FerroCrate API Schemas

> JSON schemas for FerroCrate domain objects, aligned with OCI and Docker compatibility.

## Overview

FerroCrate uses JSON schemas for:
1. **API serialization** - HTTP API and CLI JSON output
2. **Configuration files** - Container specs, compose files
3. **Persistence** - Database and file storage formats
4. **Docker compatibility** - Matching Docker API schemas where applicable

---

## Core Schemas

### Container Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ferrocrate.dev/schemas/container.json",
  "title": "Container",
  "description": "A FerroCrate container instance",
  "type": "object",
  "required": ["id", "image", "status", "created"],
  "properties": {
    "id": {
      "type": "string",
      "description": "Unique container identifier (UUID or name)",
      "pattern": "^[a-f0-9]{64}$|^[a-zA-Z0-9][a-zA-Z0-9_.-]+$",
      "examples": ["a1b2c3d4e5f6...", "my-container"]
    },
    "name": {
      "type": ["string", "null"],
      "description": "Human-readable container name",
      "pattern": "^[a-zA-Z0-9][a-zA-Z0-9_.-]+$"
    },
    "image": {
      "$ref": "#/$defs/image_reference",
      "description": "Image reference (ID or name:tag)"
    },
    "image_id": {
      "type": "string",
      "description": "Content-addressable image digest",
      "pattern": "^sha256:[a-f0-9]{64}$"
    },
    "status": {
      "$ref": "#/$defs/container_status",
      "description": "Current container status"
    },
    "state": {
      "$ref": "#/$defs/container_state",
      "description": "Detailed container state"
    },
    "config": {
      "$ref": "#/$defs/container_config",
      "description": "Container configuration"
    },
    "network_settings": {
      "$ref": "#/$defs/network_settings",
      "description": "Network configuration"
    },
    "mounts": {
      "type": "array",
      "items": { "$ref": "#/$defs/mount" },
      "description": "Volume and bind mounts"
    },
    "labels": {
      "type": "object",
      "additionalProperties": { "type": "string" },
      "description": "User-defined labels"
    },
    "created": {
      "type": "string",
      "format": "date-time",
      "description": "Creation timestamp (ISO 8601)"
    },
    "started_at": {
      "type": ["string", "null"],
      "format": "date-time"
    },
    "finished_at": {
      "type": ["string", "null"],
      "format": "date-time"
    },
    "exit_code": {
      "type": ["integer", "null"],
      "minimum": 0,
      "maximum": 255
    },
    "pid": {
      "type": ["integer", "null"],
      "description": "Host process ID when running"
    },
    "host_config": {
      "$ref": "#/$defs/host_config",
      "description": "Host-specific configuration"
    }
  },

  "$defs": {
    "container_status": {
      "type": "string",
      "enum": ["created", "running", "paused", "restarting", "exited", "dead"]
    },

    "container_state": {
      "type": "object",
      "properties": {
        "status": { "$ref": "#/$defs/container_status" },
        "running": { "type": "boolean" },
        "paused": { "type": "boolean" },
        "restarting": { "type": "boolean" },
        "oom_killed": { "type": "boolean" },
        "dead": { "type": "boolean" },
        "pid": { "type": ["integer", "null"] },
        "exit_code": { "type": ["integer", "null"] },
        "error": { "type": "string" },
        "started_at": { "type": "string", "format": "date-time" },
        "finished_at": { "type": ["string", "null"], "format": "date-time" }
      }
    },

    "container_config": {
      "type": "object",
      "properties": {
        "hostname": { "type": "string" },
        "domainname": { "type": "string" },
        "user": { "type": "string" },
        "attach_stdin": { "type": "boolean", "default": false },
        "attach_stdout": { "type": "boolean", "default": true },
        "attach_stderr": { "type": "boolean", "default": true },
        "tty": { "type": "boolean", "default": false },
        "open_stdin": { "type": "boolean", "default": false },
        "stdin_once": { "type": "boolean", "default": false },
        "env": {
          "type": "array",
          "items": { "type": "string", "pattern": "^[^=]+=.+$" }
        },
        "cmd": {
          "type": "array",
          "items": { "type": "string" }
        },
        "entrypoint": {
          "type": ["array", "null"],
          "items": { "type": "string" }
        },
        "image": { "type": "string" },
        "working_dir": { "type": "string" },
        "labels": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        },
        "stop_signal": {
          "type": "string",
          "default": "SIGTERM"
        },
        "stop_timeout": {
          "type": "integer",
          "default": 10,
          "minimum": 0
        },
        "healthcheck": { "$ref": "#/$defs/health_config" }
      }
    },

    "host_config": {
      "type": "object",
      "properties": {
        "memory": {
          "type": "integer",
          "description": "Memory limit in bytes"
        },
        "memory_swap": { "type": "integer" },
        "memory_reservation": { "type": "integer" },
        "cpu_shares": { "type": "integer", "minimum": 0 },
        "cpu_period": { "type": "integer", "minimum": 0 },
        "cpu_quota": { "type": "integer" },
        "cpu_percent": { "type": "integer", "minimum": 0, "maximum": 100 },
        "cpus": { "type": "number", "minimum": 0 },
        "pids_limit": { "type": "integer" },
        "privileged": { "type": "boolean", "default": false },
        "readonly_rootfs": { "type": "boolean", "default": false },
        "security_opt": {
          "type": "array",
          "items": { "type": "string" }
        },
        "cap_add": {
          "type": "array",
          "items": { "type": "string" }
        },
        "cap_drop": {
          "type": "array",
          "items": { "type": "string" }
        },
        "network_mode": { "type": "string" },
        "port_bindings": {
          "type": "object",
          "additionalProperties": {
            "type": "array",
            "items": { "$ref": "#/$defs/port_binding" }
          }
        },
        "restart_policy": { "$ref": "#/$defs/restart_policy" },
        "auto_remove": { "type": "boolean", "default": false },
        "runtime": { "type": "string", "default": "runc" },
        "userns_mode": { "type": "string" },
        "cgroupns_mode": { "type": "string", "enum": ["private", "host"] }
      }
    },

    "restart_policy": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string",
          "enum": ["no", "always", "on-failure", "unless-stopped"]
        },
        "maximum_retry_count": {
          "type": "integer",
          "minimum": 0
        }
      }
    },

    "health_config": {
      "type": "object",
      "required": ["test"],
      "properties": {
        "test": {
          "type": "array",
          "items": { "type": "string" },
          "minItems": 1,
          "description": "Test command: ['NONE'] to disable, ['CMD', ...] or ['CMD-SHELL', ...]"
        },
        "interval": {
          "type": "integer",
          "minimum": 0,
          "description": "Interval in nanoseconds"
        },
        "timeout": {
          "type": "integer",
          "minimum": 0
        },
        "retries": {
          "type": "integer",
          "minimum": 0
        },
        "start_period": {
          "type": "integer",
          "minimum": 0
        }
      }
    },

    "mount": {
      "type": "object",
      "required": ["type", "destination"],
      "properties": {
        "type": {
          "type": "string",
          "enum": ["bind", "volume", "tmpfs"]
        },
        "source": { "type": "string" },
        "destination": {
          "type": "string",
          "description": "Container path"
        },
        "mode": { "type": "string" },
        "rw": { "type": "boolean", "default": true },
        "propagation": {
          "type": "string",
          "enum": ["private", "rprivate", "shared", "rshared", "slave", "rslave"]
        }
      }
    },

    "network_settings": {
      "type": "object",
      "properties": {
        "bridge": { "type": "string" },
        "sandbox_id": { "type": "string" },
        "hairpin_mode": { "type": "boolean" },
        "link_local_ipv6_address": { "type": "string" },
        "link_local_ipv6_prefix_length": { "type": "integer" },
        "ports": {
          "type": "object",
          "additionalProperties": {
            "type": "array",
            "items": { "$ref": "#/$defs/port_binding" }
          }
        },
        "sandbox_key": { "type": "string" },
        "networks": {
          "type": "object",
          "additionalProperties": { "$ref": "#/$defs/endpoint_settings" }
        }
      }
    },

    "endpoint_settings": {
      "type": "object",
      "properties": {
        "ip_address": { "type": "string" },
        "ip_prefix_length": { "type": "integer" },
        "gateway": { "type": "string" },
        "ipv6_gateway": { "type": "string" },
        "mac_address": { "type": "string" },
        "network_id": { "type": "string" },
        "endpoint_id": { "type": "string" },
        "aliases": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },

    "port_binding": {
      "type": "object",
      "properties": {
        "host_ip": { "type": "string" },
        "host_port": { "type": "string" }
      }
    },

    "image_reference": {
      "type": "string",
      "pattern": "^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(:[a-zA-Z0-9._-]+)?(@sha256:[a-f0-9]{64})?$",
      "examples": ["nginx:latest", "ghcr.io/ferrocrate/app:v1.0.0"]
    }
  }
}
```

---

### Image Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ferrocrate.dev/schemas/image.json",
  "title": "Image",
  "description": "A FerroCrate container image",
  "type": "object",
  "required": ["id", "manifest", "config"],
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^sha256:[a-f0-9]{64}$",
      "description": "Content-addressable image digest"
    },
    "repo_tags": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Repository tags (e.g., ['nginx:latest', 'nginx:1.21'])"
    },
    "repo_digests": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Repository digests"
    },
    "manifest": {
      "$ref": "#/$defs/manifest"
    },
    "config": {
      "$ref": "#/$defs/image_config"
    },
    "layers": {
      "type": "array",
      "items": { "$ref": "#/$defs/layer_descriptor" }
    },
    "size": {
      "type": "integer",
      "description": "Total size in bytes"
    },
    "virtual_size": {
      "type": "integer",
      "description": "Virtual size including shared layers"
    },
    "created": {
      "type": "string",
      "format": "date-time"
    },
    "architecture": {
      "type": "string",
      "enum": ["amd64", "arm64", "riscv64", "arm", "386"]
    },
    "os": {
      "type": "string",
      "enum": ["linux", "windows"]
    },
    "labels": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    },
    "history": {
      "type": "array",
      "items": { "$ref": "#/$defs/history_entry" }
    }
  },

  "$defs": {
    "manifest": {
      "type": "object",
      "description": "OCI Image Manifest",
      "required": ["schemaVersion", "mediaType", "config", "layers"],
      "properties": {
        "schemaVersion": { "const": 2 },
        "mediaType": {
          "type": "string",
          "enum": [
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json"
          ]
        },
        "config": { "$ref": "#/$defs/descriptor" },
        "layers": {
          "type": "array",
          "items": { "$ref": "#/$defs/descriptor" }
        },
        "annotations": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        }
      }
    },

    "descriptor": {
      "type": "object",
      "required": ["mediaType", "digest", "size"],
      "properties": {
        "mediaType": { "type": "string" },
        "digest": {
          "type": "string",
          "pattern": "^sha256:[a-f0-9]{64}$"
        },
        "size": { "type": "integer", "minimum": 0 },
        "urls": {
          "type": "array",
          "items": { "type": "string", "format": "uri" }
        },
        "annotations": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        }
      }
    },

    "image_config": {
      "type": "object",
      "description": "OCI Image Configuration",
      "properties": {
        "architecture": { "type": "string" },
        "os": { "type": "string" },
        "variant": { "type": "string" },
        "config": {
          "type": "object",
          "properties": {
            "user": { "type": "string" },
            "env": {
              "type": "array",
              "items": { "type": "string" }
            },
            "entrypoint": {
              "type": ["array", "null"],
              "items": { "type": "string" }
            },
            "cmd": {
              "type": ["array", "null"],
              "items": { "type": "string" }
            },
            "working_dir": { "type": "string" },
            "labels": {
              "type": "object",
              "additionalProperties": { "type": "string" }
            },
            "stop_signal": { "type": "string" },
            "exposed_ports": {
              "type": "object",
              "additionalProperties": { "type": "object" }
            },
            "volumes": {
              "type": "object",
              "additionalProperties": { "type": "object" }
            },
            "healthcheck": { "type": "object" }
          }
        },
        "rootfs": {
          "type": "object",
          "required": ["type", "diff_ids"],
          "properties": {
            "type": { "const": "layers" },
            "diff_ids": {
              "type": "array",
              "items": {
                "type": "string",
                "pattern": "^sha256:[a-f0-9]{64}$"
              }
            }
          }
        },
        "history": {
          "type": "array",
          "items": { "$ref": "#/$defs/history_entry" }
        }
      }
    },

    "layer_descriptor": {
      "type": "object",
      "properties": {
        "digest": {
          "type": "string",
          "pattern": "^sha256:[a-f0-9]{64}$"
        },
        "blake3_hash": {
          "type": "string",
          "pattern": "^[a-f0-9]{64}$",
          "description": "Blake3 hash for content-addressable storage"
        },
        "size": { "type": "integer" },
        "media_type": { "type": "string" },
        "compressed_size": { "type": "integer" },
        "local_path": { "type": "string" }
      }
    },

    "history_entry": {
      "type": "object",
      "properties": {
        "created": {
          "type": "string",
          "format": "date-time"
        },
        "created_by": { "type": "string" },
        "comment": { "type": "string" },
        "empty_layer": { "type": "boolean" }
      }
    }
  }
}
```

---

### Network Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ferrocrate.dev/schemas/network.json",
  "title": "Network",
  "type": "object",
  "required": ["id", "name", "driver"],
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[a-f0-9]{64}$"
    },
    "name": { "type": "string" },
    "driver": {
      "type": "string",
      "enum": ["bridge", "host", "overlay", "none", "macvlan"]
    },
    "scope": {
      "type": "string",
      "enum": ["local", "swarm", "global"]
    },
    "ipv4_enabled": { "type": "boolean" },
    "ipv6_enabled": { "type": "boolean" },
    "subnet": { "type": "string", "format": "ipv4cidr" },
    "gateway": { "type": "string", "format": "ipv4" },
    "ip_range": { "type": "string" },
    "ipam": { "$ref": "#/$defs/ipam" },
    "internal": { "type": "boolean" },
    "attachable": { "type": "boolean" },
    "ingress": { "type": "boolean" },
    "labels": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    },
    "options": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    },
    "containers": {
      "type": "object",
      "additionalProperties": { "$ref": "#/$defs/network_container" }
    },
    "created": {
      "type": "string",
      "format": "date-time"
    }
  },

  "$defs": {
    "ipam": {
      "type": "object",
      "properties": {
        "driver": { "type": "string", "default": "default" },
        "config": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "subnet": { "type": "string" },
              "gateway": { "type": "string" },
              "ip_range": { "type": "string" },
              "aux_addresses": {
                "type": "object",
                "additionalProperties": { "type": "string" }
              }
            }
          }
        }
      }
    },

    "network_container": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "endpoint_id": { "type": "string" },
        "mac_address": { "type": "string" },
        "ipv4_address": { "type": "string" },
        "ipv6_address": { "type": "string" }
      }
    }
  }
}
```

---

### Volume Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ferrocrate.dev/schemas/volume.json",
  "title": "Volume",
  "type": "object",
  "required": ["name", "driver"],
  "properties": {
    "name": { "type": "string" },
    "driver": { "type": "string", "default": "local" },
    "mountpoint": { "type": "string" },
    "type": {
      "type": "string",
      "enum": ["volume", "tmpfs", "nfs", "cifs"]
    },
    "scope": {
      "type": "string",
      "enum": ["local", "global"]
    },
    "labels": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    },
    "options": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    },
    "usage_data": {
      "type": "object",
      "properties": {
        "size": { "type": "integer" },
        "ref_count": { "type": "integer" }
      }
    },
    "status": {
      "type": "object",
      "additionalProperties": {}
    },
    "created_at": {
      "type": "string",
      "format": "date-time"
    }
  }
}
```

---

### Intelligence Layer Schemas

#### Prediction Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ferrocrate.dev/schemas/prediction.json",
  "title": "ResourcePrediction",
  "type": "object",
  "required": ["resources", "confidence", "source", "timestamp"],
  "properties": {
    "resources": {
      "type": "object",
      "properties": {
        "memory": {
          "type": "object",
          "properties": {
            "min": { "type": "integer" },
            "max": { "type": "integer" },
            "recommended": { "type": "integer" }
          }
        },
        "cpu": {
          "type": "object",
          "properties": {
            "min": { "type": "number" },
            "max": { "type": "number" },
            "recommended": { "type": "number" }
          }
        }
      }
    },
    "confidence": {
      "type": "number",
      "minimum": 0,
      "maximum": 1
    },
    "reasoning": { "type": "string" },
    "source": {
      "type": "string",
      "enum": ["wasm_inference", "local_llm", "cloud_api", "historical"]
    },
    "model_version": { "type": "string" },
    "timestamp": {
      "type": "string",
      "format": "date-time"
    },
    "container_id": { "type": "string" }
  }
}
```

#### Anomaly Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ferrocrate.dev/schemas/anomaly.json",
  "title": "Anomaly",
  "type": "object",
  "required": ["id", "container_id", "type", "severity", "detected_at"],
  "properties": {
    "id": { "type": "string" },
    "container_id": { "type": "string" },
    "type": {
      "type": "string",
      "enum": [
        "memory_leak",
        "cpu_spike",
        "network_anomaly",
        "disk_io_issue",
        "unexpected_process",
        "resource_exhaustion",
        "security_violation"
      ]
    },
    "severity": {
      "type": "string",
      "enum": ["info", "warning", "critical", "emergency"]
    },
    "description": { "type": "string" },
    "evidence": {
      "type": "object",
      "additionalProperties": { "type": "number" }
    },
    "baseline": {
      "type": "object",
      "additionalProperties": { "type": "number" }
    },
    "deviation_scores": {
      "type": "object",
      "additionalProperties": { "type": "number" }
    },
    "remediation": {
      "type": "array",
      "items": { "$ref": "#/$defs/remediation" }
    },
    "detected_at": {
      "type": "string",
      "format": "date-time"
    },
    "resolved": { "type": "boolean" },
    "resolved_at": {
      "type": ["string", "null"],
      "format": "date-time"
    }
  },

  "$defs": {
    "remediation": {
      "type": "object",
      "properties": {
        "action": {
          "type": "string",
          "enum": [
            "restart_container",
            "scale_out",
            "increase_memory",
            "kill_process",
            "alert"
          ]
        },
        "description": { "type": "string" },
        "automatic": { "type": "boolean" },
        "risk_level": {
          "type": "string",
          "enum": ["low", "medium", "high"]
        }
      }
    }
  }
}
```

---

## Docker Compose Compatibility Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ferrocrate.dev/schemas/compose.json",
  "title": "ComposeSpecification",
  "description": "FerroCrate Compose file (docker-compose.yml compatible)",
  "type": "object",
  "properties": {
    "version": {
      "type": "string",
      "pattern": "^3\\.[0-9]+$",
      "description": "Compose file format version"
    },
    "services": {
      "type": "object",
      "additionalProperties": { "$ref": "#/$defs/service" }
    },
    "networks": {
      "type": "object",
      "additionalProperties": { "$ref": "#/$defs/network_config" }
    },
    "volumes": {
      "type": "object",
      "additionalProperties": { "$ref": "#/$defs/volume_config" }
    },
    "configs": {
      "type": "object",
      "additionalProperties": { "$ref": "#/$defs/config_config" }
    },
    "secrets": {
      "type": "object",
      "additionalProperties": { "$ref": "#/$defs/secret_config" }
    },
    "x-ferrocrate": {
      "type": "object",
      "description": "FerroCrate-specific extensions"
    }
  },

  "$defs": {
    "service": {
      "type": "object",
      "properties": {
        "image": { "type": "string" },
        "build": {
          "oneOf": [
            { "type": "string" },
            { "$ref": "#/$defs/build_config" }
          ]
        },
        "command": {
          "oneOf": [
            { "type": "string" },
            { "type": "array", "items": { "type": "string" } }
          ]
        },
        "entrypoint": {
          "oneOf": [
            { "type": "string" },
            { "type": "array", "items": { "type": "string" } }
          ]
        },
        "environment": {
          "oneOf": [
            { "type": "array", "items": { "type": "string" } },
            { "type": "object", "additionalProperties": { "type": ["string", "number", "null"] } }
          ]
        },
        "env_file": {
          "oneOf": [
            { "type": "string" },
            { "type": "array", "items": { "type": "string" } }
          ]
        },
        "ports": {
          "type": "array",
          "items": {
            "oneOf": [
              { "type": "integer" },
              { "type": "string" },
              { "$ref": "#/$defs/port_mapping" }
            ]
          }
        },
        "volumes": {
          "type": "array",
          "items": {
            "oneOf": [
              { "type": "string" },
              { "$ref": "#/$defs/service_volume" }
            ]
          }
        },
        "networks": {
          "oneOf": [
            { "type": "array", "items": { "type": "string" } },
            { "type": "object", "additionalProperties": { "$ref": "#/$defs/service_network" } }
          ]
        },
        "depends_on": {
          "oneOf": [
            { "type": "array", "items": { "type": "string" } },
            { "type": "object", "additionalProperties": { "$ref": "#/$defs/depends_condition" } }
          ]
        },
        "restart": {
          "type": "string",
          "enum": ["no", "always", "on-failure", "unless-stopped"]
        },
        "deploy": { "$ref": "#/$defs/deploy_config" },
        "healthcheck": { "$ref": "#/$defs/healthcheck" },
        "labels": {
          "oneOf": [
            { "type": "array", "items": { "type": "string" } },
            { "type": "object", "additionalProperties": { "type": "string" } }
          ]
        },
        "scale": { "type": "integer", "minimum": 0 },
        "profiles": {
          "type": "array",
          "items": { "type": "string" }
        },
        "privileged": { "type": "boolean" },
        "user": { "type": "string" },
        "working_dir": { "type": "string" },
        "hostname": { "type": "string" },
        "extra_hosts": {
          "type": "array",
          "items": { "type": "string" }
        },
        "ulimits": {
          "type": "object",
          "additionalProperties": {
            "oneOf": [
              { "type": "integer" },
              { "type": "object", "properties": { "soft": { "type": "integer" }, "hard": { "type": "integer" } } }
            ]
          }
        }
      }
    },

    "build_config": {
      "type": "object",
      "properties": {
        "context": { "type": "string" },
        "dockerfile": { "type": "string" },
        "args": {
          "type": "object",
          "additionalProperties": { "type": ["string", "number"] }
        },
        "cache_from": { "type": "array", "items": { "type": "string" } },
        "target": { "type": "string" },
        "labels": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        }
      }
    },

    "port_mapping": {
      "type": "object",
      "properties": {
        "target": { "type": "integer" },
        "published": { "type": "integer" },
        "protocol": { "type": "string", "enum": ["tcp", "udp"] },
        "mode": { "type": "string", "enum": ["host", "ingress"] }
      }
    },

    "service_volume": {
      "type": "object",
      "properties": {
        "type": { "type": "string", "enum": ["volume", "bind", "tmpfs"] },
        "source": { "type": "string" },
        "target": { "type": "string" },
        "read_only": { "type": "boolean" },
        "volume": { "type": "object" }
      }
    },

    "deploy_config": {
      "type": "object",
      "properties": {
        "replicas": { "type": "integer" },
        "resources": {
          "type": "object",
          "properties": {
            "limits": { "$ref": "#/$defs/resource" },
            "reservations": { "$ref": "#/$defs/resource" }
          }
        },
        "restart_policy": {
          "type": "object",
          "properties": {
            "condition": { "type": "string", "enum": ["none", "on-failure", "any"] },
            "delay": { "type": "string" },
            "max_attempts": { "type": "integer" },
            "window": { "type": "string" }
          }
        }
      }
    },

    "resource": {
      "type": "object",
      "properties": {
        "cpus": { "type": "number" },
        "memory": { "type": "string" }
      }
    },

    "depends_condition": {
      "type": "object",
      "properties": {
        "condition": {
          "type": "string",
          "enum": ["service_started", "service_healthy", "service_completed_successfully"]
        }
      }
    },

    "healthcheck": {
      "type": "object",
      "properties": {
        "test": {
          "type": "array",
          "items": { "type": "string" }
        },
        "interval": { "type": "string" },
        "timeout": { "type": "string" },
        "retries": { "type": "integer" },
        "start_period": { "type": "string" },
        "disable": { "type": "boolean" }
      }
    },

    "network_config": {
      "type": "object",
      "properties": {
        "driver": { "type": "string" },
        "driver_opts": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        },
        "attachable": { "type": "boolean" },
        "enable_ipv6": { "type": "boolean" },
        "ipam": { "$ref": "#/$defs/ipam_config" },
        "internal": { "type": "boolean" },
        "labels": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        },
        "external": {
          "oneOf": [
            { "type": "boolean" },
            { "type": "object", "properties": { "name": { "type": "string" } } }
          ]
        }
      }
    },

    "volume_config": {
      "type": "object",
      "properties": {
        "driver": { "type": "string" },
        "driver_opts": {
          "type": "object",
          "additionalProperties": { "type": ["string", "number"] }
        },
        "external": {
          "oneOf": [
            { "type": "boolean" },
            { "type": "object", "properties": { "name": { "type": "string" } } }
          ]
        },
        "labels": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        }
      }
    },

    "ipam_config": {
      "type": "object",
      "properties": {
        "driver": { "type": "string" },
        "config": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "subnet": { "type": "string" },
              "gateway": { "type": "string" }
            }
          }
        }
      }
    },

    "config_config": {
      "type": "object",
      "properties": {
        "file": { "type": "string" },
        "external": {
          "oneOf": [
            { "type": "boolean" },
            { "type": "object", "properties": { "name": { "type": "string" } } }
          ]
        },
        "labels": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        }
      }
    },

    "secret_config": {
      "type": "object",
      "properties": {
        "file": { "type": "string" },
        "external": {
          "oneOf": [
            { "type": "boolean" },
            { "type": "object", "properties": { "name": { "type": "string" } } }
          ]
        },
        "labels": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        }
      }
    },

    "service_network": {
      "type": "object",
      "properties": {
        "aliases": { "type": "array", "items": { "type": "string" } },
        "ipv4_address": { "type": "string" },
        "ipv6_address": { "type": "string" }
      }
    }
  }
}
```

---

## Schema Usage in Rust

```rust
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

/// Container specification with JSON schema derivation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContainerSpec {
    /// Unique container identifier
    pub id: ContainerId,

    /// Image reference (ID or name:tag)
    pub image: String,

    /// Container status
    pub status: ContainerStatus,

    /// Creation timestamp
    pub created: chrono::DateTime<chrono::Utc>,

    /// User-defined labels
    #[serde(default)]
    pub labels: HashMap<String, String>,

    /// Container configuration
    #[serde(default)]
    pub config: ContainerConfig,

    /// Network settings
    #[serde(default)]
    pub network_settings: NetworkSettings,
}

// Generate JSON schema at compile time
pub const CONTAINER_SCHEMA: &str = schema_for!(ContainerSpec);
```

---

## Schema Summary

| Schema | Purpose | Compatibility |
|--------|---------|---------------|
| Container | Container inspection API | Docker API v1.45 |
| Image | Image inspection API | OCI Image Spec v1.1 |
| Network | Network management | Docker API v1.45 |
| Volume | Volume management | Docker API v1.45 |
| Prediction | AI resource prediction | FerroCrate-specific |
| Anomaly | Anomaly detection | FerroCrate-specific |
| Compose | Multi-container definition | docker-compose v3.x |

All schemas:
- Follow JSON Schema Draft 07
- Use Rust's `serde` for serialization
- Use `schemars` for schema derivation
- Maintain Docker API compatibility where applicable
