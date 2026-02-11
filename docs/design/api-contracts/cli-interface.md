# FerroCrate CLI Interface

This document describes the FerroCrate command-line interface, designed for Docker CLI compatibility while adding AI-native features.

## Command Structure

```bash
ferrocrate <command> [options] [arguments]
```

## Global Options

| Option | Description |
|--------|-------------|
| `--config` | Location of client config file |
| `-D, --debug` | Enable debug mode |
| `-H, --host` | Daemon socket to connect to |
| `-l, --log-level` | Set log level (trace/debug/info/warn/error) |
| `--tls` | Use TLS |
| `--tlscert` | TLS certificate file |
| `--tlskey` | TLS key file |
| `--tlscacert` | TLS CA certificate |
| `--tlsverify` | Use TLS and verify remote |
| `-v, --version` | Print version information |
| `--no-ai` | Disable all AI features |
| `--format` | Output format (text/json/yaml) |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FERROCRATE_HOST` | `unix:///var/run/ferrocrate.sock` | Daemon socket |
| `FERROCRATE_CONFIG` | `~/.ferrocrate/config.json` | Config file path |
| `FERROCRATE_NO_AI` | `false` | Disable AI features |
| `FERROCRATE_LOG_LEVEL` | `info` | Log level |
| `FERROCRATE_FORMAT` | `text` | Output format |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid usage |
| 125 | Daemon error |
| 126 | Container command not executable |
| 127 | Container command not found |
| 137 | Container received SIGKILL |
| 139 | Container received SIGSEGV |

## Commands

### Container Commands

#### ferrocrate run

Run a container.

```bash
ferrocrate run [OPTIONS] IMAGE [COMMAND] [ARG...]

# Examples
ferrocrate run -d -p 8080:80 nginx:latest
ferrocrate run -it --rm alpine sh
ferrocrate run --gpus all nvidia/cuda:latest nvidia-smi
```

| Option | Description |
|--------|-------------|
| `-d, --detach` | Run in background |
| `-i, --interactive` | Keep STDIN open |
| `-t, --tty` | Allocate pseudo-TTY |
| `--rm` | Remove on exit |
| `-p, --publish` | Publish port |
| `-P, --publish-all` | Publish all exposed ports |
| `-v, --volume` | Bind mount volume |
| `-e, --env` | Environment variables |
| `--env-file` | Read env from file |
| `--name` | Container name |
| `--hostname` | Container hostname |
| `--network` | Network mode |
| `--restart` | Restart policy |
| `-m, --memory` | Memory limit |
| `--cpus` | CPU limit |
| `--gpus` | GPU devices |
| `--privileged` | Extended privileges |
| `--security-opt` | Security options |
| `--read-only` | Read-only rootfs |

#### ferrocrate ps

List containers.

```bash
ferrocrate ps [OPTIONS]

# Examples
ferrocrate ps -a
ferrocrate ps --format json
ferrocrate ps -q -f status=running
```

| Option | Description |
|--------|-------------|
| `-a, --all` | Show all containers |
| `-q, --quiet` | Only display IDs |
| `-l, --latest` | Show latest container |
| `-n, --last` | Show n last containers |
| `--format` | Format output |
| `-f, --filter` | Filter containers |
| `--no-trunc` | Don't truncate output |

#### ferrocrate exec

Execute command in container.

```bash
ferrocrate exec [OPTIONS] CONTAINER COMMAND [ARG...]

# Examples
ferrocrate exec -it mycontainer sh
ferrocrate exec mycontainer cat /etc/hosts
```

#### ferrocrate logs

View container logs.

```bash
ferrocrate logs [OPTIONS] CONTAINER

# Examples
ferrocrate logs -f mycontainer
ferrocrate logs --tail 100 mycontainer
```

| Option | Description |
|--------|-------------|
| `-f, --follow` | Follow log output |
| `--tail` | Number of lines |
| `-t, --timestamps` | Show timestamps |
| `--since` | Show logs since timestamp |
| `--until` | Show logs before timestamp |

### Image Commands

#### ferrocrate build

Build an image.

```bash
ferrocrate build [OPTIONS] PATH | URL | -

# Examples
ferrocrate build -t myapp:latest .
ferrocrate build -f Dockerfile.prod -t myapp:prod .
ferrocrate build --no-cache -t myapp:clean .
```

| Option | Description |
|--------|-------------|
| `-t, --tag` | Image name:tag |
| `-f, --file` | Dockerfile path |
| `--no-cache` | Disable cache |
| `--build-arg` | Build arguments |
| `--target` | Build target stage |
| `--platform` | Target platform |
| `--label` | Metadata labels |

#### ferrocrate pull

Pull an image.

```bash
ferrocrate pull [OPTIONS] NAME[:TAG]

# Examples
ferrocrate pull nginx:latest
ferrocrate pull --platform linux/arm64 alpine
```

#### ferrocrate push

Push an image.

```bash
ferrocrate push [OPTIONS] NAME[:TAG]

# Examples
ferrocrate push myregistry/myapp:latest
```

#### ferrocrate images

List images.

```bash
ferrocrate images [OPTIONS]

# Examples
ferrocrate images
ferrocrate images -f dangling=true
```

### Compose Commands

#### ferrocrate compose

Multi-container orchestration.

```bash
ferrocrate compose [OPTIONS] [COMMAND]

# Examples
ferrocrate compose up -d
ferrocrate compose down
ferrocrate compose logs -f
ferrocrate compose ps
```

| Command | Description |
|---------|-------------|
| `up` | Create and start |
| `down` | Stop and remove |
| `start` | Start services |
| `stop` | Stop services |
| `restart` | Restart services |
| `ps` | List containers |
| `logs` | View logs |
| `exec` | Execute command |
| `build` | Build images |
| `pull` | Pull images |
| `push` | Push images |
| `config` | Validate and view |

### AI Commands (FerroCrate Specific)

#### ferrocrate ask

Natural language container management.

```bash
ferrocrate ask "QUESTION"

# Examples
ferrocrate ask "why did my web server crash?"
ferrocrate ask "which containers are using the most memory?"
ferrocrate ask "optimize my docker-compose for production"
```

#### ferrocrate explain

Explain AI decision.

```bash
ferrocrate explain DECISION_ID

# Examples
ferrocrate explain restart-a1b2c3
ferrocrate explain resource-prediction-web-001
```

#### ferrocrate predict

Resource prediction.

```bash
ferrocrate predict CONTAINER [OPTIONS]

# Examples
ferrocrate predict web-container --horizon 24h
ferrocrate predict --all
```

### System Commands

#### ferrocrate info

System information.

```bash
ferrocrate info [OPTIONS]
```

#### ferrocrate migrate

Migration from Docker.

```bash
ferrocrate migrate [OPTIONS]

# Examples
ferrocrate migrate --dry-run
ferrocrate migrate --from docker
```

## Shell Completion

Install completions:

```bash
# Bash
ferrocrate completion bash > /etc/bash_completion.d/ferrocrate

# Zsh
ferrocrate completion zsh > "${fpath[1]}/_ferrocrate"

# Fish
ferrocrate completion fish > ~/.config/fish/completions/ferrocrate.fish
```
