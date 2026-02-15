#!/usr/bin/env python3
"""Authenticated paid artifact gateway for FerroCrate installers.

Endpoints:
- POST /v1/token
  Auth:
    - session mode: Authorization: Bearer <session-jwt>
    - entitlement mode: entitlement envelope JSON body
    - hybrid mode: either session-jwt or entitlement envelope
  Response: {"token":"...","expires_at":<unix>,"plan":"..."}

- GET /v1/releases/<tag>/<asset>
  Header: Authorization: Bearer <download-token>
  Response: artifact bytes from PAID_ARTIFACT_ROOT/<tag>/<asset>
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pathlib
import random
import ssl
import subprocess
import tempfile
import time
from collections import defaultdict, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

BIND = os.environ.get("PAID_GATEWAY_BIND", "127.0.0.1:9090")
ARTIFACT_ROOT = pathlib.Path(os.environ.get("PAID_ARTIFACT_ROOT", "dist/releases"))
TOKEN_TTL_SECONDS = int(os.environ.get("PAID_TOKEN_TTL_SECONDS", "900"))
SIGNING_SECRET = os.environ.get("PAID_GATEWAY_SIGNING_SECRET", "")
ENTITLEMENT_PUBKEY = os.environ.get("FERROCRATE_ENTITLEMENT_PUBKEY", "")
FERROCRATE_BIN = os.environ.get("FERROCRATE_BIN", "ferrocrate")
AUTH_MODE = os.environ.get("PAID_GATEWAY_AUTH_MODE", "hybrid")
SESSION_JWT_SECRET = os.environ.get("PAID_SESSION_JWT_SECRET", "")
AUDIT_LOG_PATH = os.environ.get("PAID_GATEWAY_AUDIT_LOG", "")
RATE_LIMIT_RPM = int(os.environ.get("PAID_GATEWAY_RATE_LIMIT_RPM", "120"))
REQUEST_BODY_MAX = int(os.environ.get("PAID_GATEWAY_REQUEST_BODY_MAX", str(128 * 1024)))
TLS_CERT_PATH = os.environ.get("PAID_GATEWAY_TLS_CERT", "")
TLS_KEY_PATH = os.environ.get("PAID_GATEWAY_TLS_KEY", "")
REVOKED_TOKEN_HASHES_PATH = os.environ.get("PAID_GATEWAY_REVOKED_TOKENS", "")

_RATE_BUCKETS: dict[str, deque[int]] = defaultdict(deque)
_USED_SESSION_JTI: dict[str, int] = {}
_REVOKED_CACHE: tuple[float, set[str]] = (0.0, set())


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(raw: str) -> bytes:
    pad = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + pad).encode("ascii"))


def sign_payload(payload_b64: str) -> str:
    return hmac.new(SIGNING_SECRET.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_sha256_b64url(secret: str, message: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()
    return b64url_encode(digest)


def now_ts() -> int:
    return int(time.time())


def random_id() -> str:
    return b64url_encode(os.urandom(24))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_revoked_hashes() -> set[str]:
    global _REVOKED_CACHE
    if not REVOKED_TOKEN_HASHES_PATH:
        return set()
    path = pathlib.Path(REVOKED_TOKEN_HASHES_PATH)
    if not path.exists() or not path.is_file():
        return set()
    now = time.time()
    last_load, cached = _REVOKED_CACHE
    if now - last_load < 5.0:
        return cached
    try:
        hashes = {line.strip().lower() for line in path.read_text().splitlines() if line.strip()}
    except OSError:
        hashes = set()
    _REVOKED_CACHE = (now, hashes)
    return hashes


def audit(event: str, data: dict[str, Any]) -> None:
    if not AUDIT_LOG_PATH:
        return
    payload = {"ts": now_ts(), "event": event, **data}
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
    except OSError:
        pass


def validate_rate_limit(client_ip: str) -> None:
    if RATE_LIMIT_RPM <= 0:
        return
    now = now_ts()
    bucket = _RATE_BUCKETS[client_ip]
    while bucket and now - bucket[0] >= 60:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_RPM:
        raise ValueError("rate limit exceeded")
    bucket.append(now)


def session_claims_from_jwt(token: str) -> dict[str, Any]:
    if not SESSION_JWT_SECRET:
        raise ValueError("PAID_SESSION_JWT_SECRET is required for session mode")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid session jwt format")
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac_sha256_b64url(SESSION_JWT_SECRET, signing_input)
    if not hmac.compare_digest(sig_b64, expected_sig):
        raise ValueError("invalid session jwt signature")

    header = json.loads(b64url_decode(header_b64))
    if str(header.get("alg", "")).upper() != "HS256":
        raise ValueError("unsupported session jwt algorithm")

    claims = json.loads(b64url_decode(payload_b64))
    exp = int(claims.get("exp", 0))
    if exp <= now_ts():
        raise ValueError("session jwt expired")
    jti = str(claims.get("jti", "")).strip()
    if jti:
        previous = _USED_SESSION_JTI.get(jti)
        if previous and previous > now_ts() - 5:
            raise ValueError("session jwt replay detected")
        _USED_SESSION_JTI[jti] = now_ts()
    return claims


def claims_to_plan_features(claims: dict[str, Any]) -> dict[str, Any]:
    plan = str(claims.get("plan", "free"))
    features_raw = claims.get("features", [])
    features = set(features_raw if isinstance(features_raw, list) else [])
    return {
        "subject": claims.get("sub") or claims.get("customer") or "unknown",
        "plan": plan,
        "features": list(features),
    }


def issue_token(entitlement: dict[str, Any], tag: str) -> dict[str, Any]:
    exp = now_ts() + TOKEN_TTL_SECONDS
    plan = str(entitlement.get("plan", "free"))
    features = set(entitlement.get("features") or [])
    desktop_allowed = plan in {"pro", "enterprise"} or "desktop" in features
    payload = {
        "channel": "paid",
        "tag": tag,
        "exp": exp,
        "iat": now_ts(),
        "jti": random_id(),
        "sub": entitlement.get("subject", "unknown"),
        "plan": plan,
        "desktop_allowed": desktop_allowed,
    }
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = sign_payload(payload_b64)
    token = f"{payload_b64}.{signature}"
    audit("token_issued", {"tag": tag, "plan": plan, "subject": payload.get("sub")})
    return {"token": token, "expires_at": exp, "plan": plan}


def verify_token(token: str, tag: str) -> dict[str, Any]:
    try:
        payload_b64, sig = token.split(".", 1)
    except ValueError as err:
        raise ValueError("invalid token format") from err

    revoked = load_revoked_hashes()
    if token_hash(token) in revoked:
        raise ValueError("token revoked")

    expected = sign_payload(payload_b64)
    if not hmac.compare_digest(sig, expected):
        raise ValueError("invalid token signature")
    payload = json.loads(b64url_decode(payload_b64))
    if int(payload.get("exp", 0)) <= now_ts():
        raise ValueError("token expired")
    if payload.get("channel") != "paid":
        raise ValueError("token channel mismatch")
    if payload.get("tag") != tag:
        raise ValueError("token tag mismatch")
    return payload


def parse_entitlement_status(raw: str) -> dict[str, Any]:
    parsed = json.loads(raw)
    if parsed.get("status") != "ok":
        raise ValueError(f"entitlement rejected: status={parsed.get('status')}")
    return parsed


def verify_entitlement(envelope: dict[str, Any]) -> dict[str, Any]:
    if not ENTITLEMENT_PUBKEY:
        raise ValueError("FERROCRATE_ENTITLEMENT_PUBKEY is required")

    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        json.dump(envelope, handle)
        entitlement_path = handle.name

    env = os.environ.copy()
    env["FERROCRATE_ENTITLEMENT_FILE"] = entitlement_path
    env["FERROCRATE_ENTITLEMENT_PUBKEY"] = ENTITLEMENT_PUBKEY
    try:
        proc = subprocess.run(
            [FERROCRATE_BIN, "entitlement", "status", "--json"],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        try:
            os.unlink(entitlement_path)
        except OSError:
            pass

    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "entitlement validation failed"
        raise ValueError(message)
    return parse_entitlement_status(proc.stdout)


def extract_envelope(body: bytes) -> dict[str, Any]:
    if not body:
        raise ValueError("request body required for entitlement mode")
    parsed = json.loads(body.decode("utf-8"))
    if "payload" in parsed and "signature" in parsed:
        return parsed
    if isinstance(parsed.get("entitlement"), dict):
        return parsed["entitlement"]
    raise ValueError("expected entitlement envelope JSON")


def entitlement_from_request(headers: Any, body: bytes) -> dict[str, Any]:
    auth = headers.get("Authorization", "")
    session = headers.get("X-Ferrocrate-Session", "")
    session_token = ""
    if auth.startswith("Bearer "):
        session_token = auth[len("Bearer ") :].strip()
    if not session_token and session.strip():
        session_token = session.strip()

    if AUTH_MODE not in {"session", "entitlement", "hybrid"}:
        raise ValueError("invalid PAID_GATEWAY_AUTH_MODE (expected session|entitlement|hybrid)")

    if AUTH_MODE in {"session", "hybrid"} and session_token:
        claims = session_claims_from_jwt(session_token)
        return claims_to_plan_features(claims)

    if AUTH_MODE == "session":
        raise ValueError("session authentication required")

    envelope = extract_envelope(body)
    return verify_entitlement(envelope)


class Handler(BaseHTTPRequestHandler):
    server_version = "ferro-paid-gateway/0.2"

    def _json(self, status: HTTPStatus, payload: dict[str, Any], request_id: str = "") -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        if request_id:
            self.send_header("X-Request-Id", request_id)
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:  # noqa: N802
        request_id = self.headers.get("X-Request-Id", random_id())
        client_ip = self.client_address[0]
        try:
            validate_rate_limit(client_ip)
            if self.path != "/v1/token":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"}, request_id=request_id)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > REQUEST_BODY_MAX:
                raise ValueError("invalid content length")
            body = self.rfile.read(length)
            principal = entitlement_from_request(self.headers, body)
            tag = self.headers.get("X-Ferrocrate-Tag", "latest")
            result = issue_token(principal, tag)
            audit("token_request_ok", {"request_id": request_id, "ip": client_ip, "tag": tag})
            self._json(HTTPStatus.OK, result, request_id=request_id)
        except Exception as err:  # noqa: BLE001
            audit("token_request_denied", {"request_id": request_id, "ip": client_ip, "error": str(err)})
            self._json(HTTPStatus.UNAUTHORIZED, {"error": str(err)}, request_id=request_id)

    def do_GET(self) -> None:  # noqa: N802
        request_id = self.headers.get("X-Request-Id", random_id())
        client_ip = self.client_address[0]
        try:
            validate_rate_limit(client_ip)
            parts = self.path.strip("/").split("/")
            if len(parts) != 4 or parts[0] != "v1" or parts[1] != "releases":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"}, request_id=request_id)
                return
            tag, asset = parts[2], parts[3]

            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                raise ValueError("missing bearer token")
            token = auth[len("Bearer ") :].strip()
            claims = verify_token(token, tag)

            if "ferro-desktop" in asset and not claims.get("desktop_allowed", False):
                raise ValueError("desktop artifact not permitted for token")
            safe_asset = pathlib.PurePath(asset)
            if safe_asset.name != asset or any(part in {"..", ""} for part in safe_asset.parts):
                raise ValueError("invalid artifact name")

            artifact_path = ARTIFACT_ROOT / tag / asset
            if not artifact_path.exists() or not artifact_path.is_file():
                self._json(HTTPStatus.NOT_FOUND, {"error": "artifact not found"}, request_id=request_id)
                return
            with artifact_path.open("rb") as handle:
                data = handle.read()

            audit("artifact_download_ok", {"request_id": request_id, "ip": client_ip, "tag": tag, "asset": asset})
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Request-Id", request_id)
            self.end_headers()
            self.wfile.write(data)
        except Exception as err:  # noqa: BLE001
            audit("artifact_download_denied", {"request_id": request_id, "ip": client_ip, "error": str(err)})
            self._json(HTTPStatus.UNAUTHORIZED, {"error": str(err)}, request_id=request_id)


def main() -> None:
    if not SIGNING_SECRET:
        raise SystemExit("PAID_GATEWAY_SIGNING_SECRET is required")
    if ":" not in BIND:
        raise SystemExit("PAID_GATEWAY_BIND must be host:port")

    host, port_str = BIND.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port_str)), Handler)

    if TLS_CERT_PATH and TLS_KEY_PATH:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(f"paid artifact gateway listening on https://{BIND}")
    else:
        print(f"paid artifact gateway listening on http://{BIND}")

    random.seed(time.time_ns())
    server.serve_forever()


if __name__ == "__main__":
    main()
