# Backend/API Dev Guide

## Docker-Compat Path (`ferro-cli`)

- Entry point: `ferro-cli/src/main.rs`
- Daemon command: `ferro-cli daemon --docker-compat --socket <path>`
- Request flow:
  1. `run_daemon` accepts Unix socket connections.
  2. `handle_docker_compat_connection` parses HTTP and routes Docker-compatible endpoints.
  3. Endpoints map to `ferro-core` runtime/image/volume operations.

### Important helpers

- `read_http_request`: hardened request parser for malformed headers/body edge cases.
- `normalize_docker_api_path`: maps versioned routes (for example `/v1.45/...`) to unversioned handlers.
- `docker_error_response`: consistent Docker-style JSON error payloads.

### Tests

- `ferro-cli/tests/docker_compat_integration.rs`
- `ferro-cli/tests/api_compat_matrix.rs`

## CRI gRPC Path (`ferro-cri`)

- Entry point: `ferro-cri/src/server.rs`
- Server startup: `ferro_cri::server::serve(<socket_path>)`
- gRPC services:
  - `RuntimeService`: `Version`, `Status`
  - `ImageService`: `ListImages`, `ImageStatus`, `PullImage`, `RemoveImage`

### Runtime/image behavior

- `PullImage` is wired to `ferro_core::image_fetch::pull_image_with_store`.
- `RemoveImage` removes by reference/canonical reference and digest matches.
- `ListImages.filter` is applied as case-insensitive substring match over reference/digest.
- `Status.verbose` and `ImageStatus.verbose` populate `info` maps.

### Tests

- Unit coverage: `ferro-cri/src/server.rs` tests
- Socket integration: `ferro-cri/tests/socket_integration.rs`
