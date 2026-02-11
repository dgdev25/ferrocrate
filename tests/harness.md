# Test Harness Guidelines

- Prefer deterministic tests without network access.
- Use `httptest` for mocked registry flows.
- Place reusable JSON fixtures under `tests/fixtures/`.
