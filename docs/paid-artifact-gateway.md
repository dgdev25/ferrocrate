# Paid Artifact Gateway

This gateway provides authenticated paid-channel artifact delivery and installer token issuance.

## What it does

- Verifies signed entitlement envelopes using `ferrocrate entitlement status --json`.
- Issues short-lived bearer download tokens.
- Serves paid artifacts from a local artifact root only when token is valid.
- Enforces token/tag matching and desktop artifact entitlement.

## Endpoints

- `POST /v1/token`
  - Request body: entitlement envelope JSON (same format as `entitlement.lic`)
  - Optional header: `X-Ferrocrate-Tag: <tag>`
  - Response: `{"token":"...","expires_at":<unix>,"plan":"pro|enterprise"}`

- `GET /v1/releases/<tag>/<asset>`
  - Header: `Authorization: Bearer <token>`
  - Returns artifact bytes from `${PAID_ARTIFACT_ROOT}/<tag>/<asset>`

## Run

```bash
export PAID_ARTIFACT_ROOT="$PWD/dist/releases"
export PAID_GATEWAY_SIGNING_SECRET="replace-with-long-random-secret"
export FERROCRATE_ENTITLEMENT_PUBKEY="<base64-ed25519-public-key>"
export FERROCRATE_BIN="ferrocrate"

./scripts/paid-artifact-gateway.py
```

Defaults:
- bind address: `127.0.0.1:9090`
- token TTL: `900` seconds

## Installer wiring

For macOS:

```bash
export PAID_RELEASE_BASE_URL="http://127.0.0.1:9090/v1/releases/{tag}"
export PAID_RELEASE_TOKEN_ENDPOINT="http://127.0.0.1:9090/v1/token"
export PAID_ENTITLEMENT_FILE="$HOME/.ferrocrate/entitlement.lic"

scripts/install-macos.sh --channel paid
```

For Windows PowerShell:

```powershell
$env:PAID_RELEASE_BASE_URL = 'http://127.0.0.1:9090/v1/releases/{tag}'
$env:PAID_RELEASE_TOKEN_ENDPOINT = 'http://127.0.0.1:9090/v1/token'
$env:PAID_ENTITLEMENT_FILE = "$HOME\.ferrocrate\entitlement.lic"

.\scripts\install-windows.ps1 -Channel paid
```

## Notes

- This implementation is suitable for self-hosted/private deployments and CI environments.
- Production hardening should add mTLS, audit logging to centralized sink, rate limiting, and object storage backends.
