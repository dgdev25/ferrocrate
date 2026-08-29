# Test Harness Guidelines

- `cargo test` and Rust's built-in `libtest` harness execute the workspace test suite. There is no custom suite runner, timeout, retry, or fail-fast layer under `tests/common/`.
- Use `tempfile::TempDir` for per-test filesystem isolation; its `Drop` implementation removes the temporary directory automatically.
- Prefer deterministic tests without network access.
- Use `httptest` for mocked registry flows.
- Place reusable JSON fixtures under `tests/fixtures/`.
