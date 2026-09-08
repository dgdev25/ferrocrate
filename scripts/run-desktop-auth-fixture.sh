#!/usr/bin/env bash
# Run a candidate bridge under real disposable account services, never user stores.
# Usage: bash scripts/run-desktop-auth-fixture.sh <bridge command> [args...]
set -euo pipefail
if [[ "${FERROCRATE_AUTH_FIXTURE_ACTIVE:-}" != 1 ]]; then
  [[ $# -gt 0 ]] || { echo 'Provide the candidate bridge command' >&2; exit 2; }
  fixture_dir=$(mktemp -d /tmp/ferrocrate-account-ui.XXXXXX)
  trap 'rm -rf "$fixture_dir"' EXIT
  dbus-run-session -- env FERROCRATE_AUTH_FIXTURE_ACTIVE=1 \
    FERROCRATE_AUTH_FIXTURE_DIR="$fixture_dir" bash "$0" "$@"
  exit
fi
umask 077
export XDG_DATA_HOME="$FERROCRATE_AUTH_FIXTURE_DIR/data"
export GNOME_KEYRING_CONTROL="$FERROCRATE_AUTH_FIXTURE_DIR/keyring"
export FERROCRATE_DESKTOP_AUTH_CONFIG="$FERROCRATE_AUTH_FIXTURE_DIR/desktop-auth.json"
export FERROCRATE_AUTH_FILE="$FERROCRATE_AUTH_FIXTURE_DIR/registry-auth.json"
export DOCKER_CONFIG="$FERROCRATE_AUTH_FIXTURE_DIR/docker"
export PAID_ARTIFACT_ROOT="$FERROCRATE_AUTH_FIXTURE_DIR/artifacts"
export PAID_GATEWAY_AUDIT_LOG="$FERROCRATE_AUTH_FIXTURE_DIR/gateway-audit.jsonl"
export PAID_GATEWAY_AUTH_MODE=session
export PAID_GATEWAY_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export PAID_SESSION_JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export PAID_GATEWAY_BIND="127.0.0.1:${FERROCRATE_AUTH_FIXTURE_PORT:-49191}"
mkdir -p "$XDG_DATA_HOME" "$GNOME_KEYRING_CONTROL" "$DOCKER_CONFIG" "$PAID_ARTIFACT_ROOT"
python3 - <<'PY'
import os, socket
host, port = os.environ['PAID_GATEWAY_BIND'].split(':')
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((host, int(port)))
    except OSError as error:
        raise SystemExit(f'Fixture gateway port is unavailable: {error}')
PY
printf '%s' 'ferrocrate-disposable-keyring-proof' | \
  gnome-keyring-daemon --unlock --foreground --components=secrets \
    --control-directory="$GNOME_KEYRING_CONTROL" >"$FERROCRATE_AUTH_FIXTURE_DIR/keyring.log" 2>&1 &
keyring_pid=$!
python3 scripts/paid-artifact-gateway.py >"$FERROCRATE_AUTH_FIXTURE_DIR/gateway.log" 2>&1 &
gateway_pid=$!
trap 'kill "$gateway_pid" "$keyring_pid" 2>/dev/null || true; wait "$gateway_pid" "$keyring_pid" 2>/dev/null || true' EXIT
FIXTURE_GATEWAY_PID="$gateway_pid" python3 - <<'PY'
import base64, hashlib, hmac, json, os, pathlib, time, urllib.request, urllib.error
root = pathlib.Path(os.environ['FERROCRATE_AUTH_FIXTURE_DIR'])
encode = lambda obj: base64.urlsafe_b64encode(json.dumps(obj, separators=(',', ':')).encode()).decode().rstrip('=')
header = encode({'alg': 'HS256', 'typ': 'JWT'})
payload = encode({'sub': 'disposable-ui-account', 'plan': 'pro', 'exp': int(time.time()) + 3600})
message = f'{header}.{payload}'
signature = base64.urlsafe_b64encode(hmac.new(os.environ['PAID_SESSION_JWT_SECRET'].encode(), message.encode(), hashlib.sha256).digest()).decode().rstrip('=')
session = f'{message}.{signature}'
(root / 'session.jwt').write_text(session)
host, port = os.environ['PAID_GATEWAY_BIND'].split(':')
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    try:
        os.kill(int(os.environ['FIXTURE_GATEWAY_PID']), 0)
    except ProcessLookupError:
        raise SystemExit('Fixture gateway exited before becoming ready; inspect its private log')
    request = urllib.request.Request(f'http://{host}:{port}/v1/token', method='POST',
        headers={'Authorization': f'Bearer {session}', 'X-Ferrocrate-Tag': 'latest'})
    try:
        with urllib.request.urlopen(request, timeout=.2) as response:
            issued = json.load(response)
        payload, received = issued['token'].rsplit('.', 1)
        expected = hmac.new(os.environ['PAID_GATEWAY_SIGNING_SECRET'].encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(received, expected):
            raise SystemExit('Gateway readiness response does not belong to this fixture')
        break
    except urllib.error.HTTPError:
        raise SystemExit('Gateway did not authenticate this fixture session')
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        time.sleep(.1)
    except (ValueError, KeyError, TypeError):
        raise SystemExit('Gateway returned an invalid fixture readiness response')
else: raise SystemExit('Gateway did not become ready')
(root / 'fixture-info.json').write_text(json.dumps({'release_base_url': f'http://{host}:{port}/v1/releases', 'token_endpoint': f'http://{host}:{port}/v1/token', 'issuance_endpoint': None, 'session_file': str(root / 'session.jwt')}, indent=2))
print(f'Isolated account fixture: {root} (session file is secret; do not log it)', flush=True)
PY
keyring_ready=0
for attempt in {1..50}; do
  kill -0 "$gateway_pid" 2>/dev/null || { echo 'Fixture gateway exited before command launch' >&2; exit 1; }
  kill -0 "$keyring_pid" 2>/dev/null || { echo 'Fixture keyring exited before becoming ready' >&2; exit 1; }
  if timeout 1s gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.NameHasOwner org.freedesktop.secrets | rg -q true; then keyring_ready=1; break; fi
  sleep 0.1
done
[[ "$keyring_ready" == 1 ]] || { echo 'Fixture private keyring did not become ready' >&2; exit 1; }
"$@"
