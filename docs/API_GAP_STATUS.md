# API Gap Status (Close-the-Gaps)

Date: 2026-02-15

## Summary

- Completed: 15
- Pending: 0

## Checklist

1. How to work in backend/api via ferro-cli daemon path and ferro-cri gRPC path.
- Status: Completed
- Evidence: `docs/backend-api-dev-guide.md`

2. Add Docker API version-prefix handling so /v1.45/... routes resolve the same as unversioned routes in ferro-cli/src/main.rs.
- Status: Completed
- Evidence: `ferro-cli/src/main.rs` (`normalize_docker_api_path`, routing normalization)

3. Add missing Docker-compat route coverage tests for all implemented endpoints (/_ping, /version, /info, containers, images).
- Status: Completed
- Evidence: `ferro-cli/tests/docker_compat_integration.rs`

4. Implement CRI PullImage in ferro-cri/src/server.rs by wiring to ferro-core image pull flow.
- Status: Completed
- Evidence: `ferro-cri/src/server.rs` (`pull_image` -> `ferro_core::image_fetch::pull_image_with_store`)

5. Implement CRI RemoveImage in ferro-cri/src/server.rs by wiring to image remove logic.
- Status: Completed
- Evidence: `ferro-cri/src/server.rs` (`remove_image` reference/canonical/digest removal)

6. Decide and implement behavior for CRI ListImages.filter (currently accepted but ignored).
- Status: Completed
- Evidence: `ferro-cri/src/server.rs` (`list_images` case-insensitive filter over reference/digest)

7. Decide and implement behavior for CRI ImageStatus.verbose and Status.verbose info payloads (currently mostly ignored).
- Status: Completed
- Evidence: `ferro-cri/src/server.rs` (`status` and `image_status` populate `info` when `verbose=true`)

8. Add integration tests for CRI socket server startup and request/response behavior (not just unit trait calls).
- Status: Completed
- Evidence: `ferro-cri/tests/socket_integration.rs`

9. Add daemon-mode integration tests for Docker socket request parsing and response codes.
- Status: Completed
- Evidence: `ferro-cli/tests/docker_compat_integration.rs`

10. Harden manual HTTP parsing in read_http_request for malformed headers and larger body edge cases.
- Status: Completed
- Evidence: `ferro-cli/src/main.rs` (`read_http_request` header/body limits, request/header/content-length validation)

11. Normalize error mapping to Docker-style JSON error payloads consistently across routes.
- Status: Completed
- Evidence: `ferro-cli/src/main.rs` (`docker_error_response`, `docker_status_for_error`)

12. Reconcile docs vs implementation for native REST /api/v1 endpoints: either implement or mark as planned in docs.
- Status: Completed
- Evidence: `docs/specification/api-contracts.md` implementation status note; `docs/ROADMAP.md` CRI status sync

13. Add API compatibility matrix in tests to track “implemented / partial / unsupported” endpoints.
- Status: Completed
- Evidence: `ferro-cli/tests/api_compat_matrix.rs`

14. Run full workspace tests and fix any regressions introduced by API work (cargo test --workspace).
- Status: Completed
- Evidence: workspace test run passed after fixes (including `ferro-net` compatibility test updates)

15. Add CI gate for API contract tests so parity doesn’t drift again.
- Status: Completed
- Evidence: `.github/workflows/ci.yml` includes dedicated API contract test jobs/commands
