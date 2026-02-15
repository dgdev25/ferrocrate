# Paid Artifact Gateway

This gateway provides authenticated paid-channel artifact delivery and installer token issuance.

## What it does

- Supports auth modes:
  - `session` via signed session JWT
  - `entitlement` via signed entitlement envelope
  - `hybrid` (default), which accepts either.
- Issues short-lived bearer download tokens.
- Serves paid artifacts from a local artifact root only when token is valid.
- Enforces token/tag matching and desktop artifact entitlement.
- Includes rate limiting, request IDs, optional TLS, audit logs, and token revocation checks.

## Endpoints

- `POST /v1/token`
  - Session auth:
    - `Authorization: Bearer <session-jwt>`
  - Entitlement auth:
    - Request body: entitlement envelope JSON (same format as `entitlement.lic`)
  - Optional header: `X-Ferrocrate-Tag: <tag>`
  - Response: `{"token":"...","expires_at":<unix>,"plan":"pro|enterprise"}`

- `GET /v1/releases/<tag>/<asset>`
  - Header: `Authorization: Bearer <download-token>`
  - Returns artifact bytes from `${PAID_ARTIFACT_ROOT}/<tag>/<asset>`

## Run

```bash
export PAID_ARTIFACT_ROOT="$PWD/dist/releases"
export PAID_GATEWAY_SIGNING_SECRET="replace-with-long-random-secret"
export PAID_GATEWAY_AUTH_MODE="session"
export PAID_SESSION_JWT_SECRET="replace-with-shared-session-jwt-secret"
export PAID_GATEWAY_AUDIT_LOG="$PWD/paid-gateway-audit.log"

./scripts/paid-artifact-gateway.py
```

Defaults:
- bind address: `127.0.0.1:9090`
- token TTL: `900` seconds
- auth mode: `hybrid`
- rate limit: `120` requests/minute per IP

Optional hardening env:
- `PAID_GATEWAY_TLS_CERT` + `PAID_GATEWAY_TLS_KEY`
- `PAID_GATEWAY_REVOKED_TOKENS` (path to newline-delimited SHA256 token hashes)
- `PAID_GATEWAY_REQUEST_BODY_MAX`

## Installer wiring

For macOS:

```bash
export PAID_RELEASE_BASE_URL="http://127.0.0.1:9090/v1/releases/{tag}"
export PAID_RELEASE_TOKEN_ENDPOINT="http://127.0.0.1:9090/v1/token"
export PAID_SESSION_TOKEN="<session-jwt>"

scripts/install-macos.sh --channel paid
```

For Windows PowerShell:

```powershell
$env:PAID_RELEASE_BASE_URL = 'http://127.0.0.1:9090/v1/releases/{tag}'
$env:PAID_RELEASE_TOKEN_ENDPOINT = 'http://127.0.0.1:9090/v1/token'
$env:PAID_SESSION_TOKEN = '<session-jwt>'

.\scripts\install-windows.ps1 -Channel paid
```

## Notes

- This implementation is suitable for self-hosted/private deployments and CI environments.
- For entitlement-only flow, set `PAID_GATEWAY_AUTH_MODE=entitlement` and configure `FERROCRATE_ENTITLEMENT_PUBKEY`.
