#!/usr/bin/env python3
"""Authenticated paid artifact gateway for FerroCrate installers.

Endpoints:
- POST /v1/token
  Body: entitlement envelope JSON (same content as entitlement.lic)
  Response: {"token":"...","expires_at":<unix>}

- GET /v1/releases/<tag>/<asset>
  Header: Authorization: Bearer <token>
  Response: artifact bytes from PAID_ARTIFACT_ROOT/<tag>/<asset>
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pathlib
import subprocess
import tempfile
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

BIND = os.environ.get("PAID_GATEWAY_BIND", "127.0.0.1:9090")
ARTIFACT_ROOT = pathlib.Path(os.environ.get("PAID_ARTIFACT_ROOT", "dist/releases"))
TOKEN_TTL_SECONDS = int(os.environ.get("PAID_TOKEN_TTL_SECONDS", "900"))
SIGNING_SECRET = os.environ.get("PAID_GATEWAY_SIGNING_SECRET", "")
ENTITLEMENT_PUBKEY = os.environ.get("FERROCRATE_ENTITLEMENT_PUBKEY", "")
FERROCRATE_BIN = os.environ.get("FERROCRATE_BIN", "ferrocrate")


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(raw: str) -> bytes:
    pad = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + pad).encode("ascii"))


def sign_payload(payload_b64: str) -> str:
    return hmac.new(SIGNING_SECRET.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_token(entitlement: dict[str, Any], tag: str) -> dict[str, Any]:
    exp = int(time.time()) + TOKEN_TTL_SECONDS
    plan = str(entitlement.get("plan", "free"))
    features = set(entitlement.get("features") or [])
    desktop_allowed = plan in {"pro", "enterprise"} or "desktop" in features
    payload = {
        "channel": "paid",
        "tag": tag,
        "exp": exp,
        "plan": plan,
        "desktop_allowed": desktop_allowed,
    }
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = sign_payload(payload_b64)
    return {"token": f"{payload_b64}.{signature}", "expires_at": exp, "plan": plan}


def verify_token(token: str, tag: str) -> dict[str, Any]:
    try:
        payload_b64, sig = token.split(".", 1)
    except ValueError as err:
        raise ValueError("invalid token format") from err
    expected = sign_payload(payload_b64)
    if not hmac.compare_digest(sig, expected):
        raise ValueError("invalid token signature")
    payload = json.loads(b64url_decode(payload_b64))
    if int(payload.get("exp", 0)) <= int(time.time()):
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
    if not SIGNING_SECRET:
        raise ValueError("PAID_GATEWAY_SIGNING_SECRET is required")
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
    parsed = json.loads(body.decode("utf-8"))
    if "payload" in parsed and "signature" in parsed:
        return parsed
    if isinstance(parsed.get("entitlement"), dict):
        return parsed["entitlement"]
    raise ValueError("expected entitlement envelope JSON")


class Handler(BaseHTTPRequestHandler):
    server_version = "ferro-paid-gateway/0.1"

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/token":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            envelope = extract_envelope(body)
            status = verify_entitlement(envelope)
            tag = self.headers.get("X-Ferrocrate-Tag", "latest")
            self._json(HTTPStatus.OK, issue_token(status, tag))
        except Exception as err:  # noqa: BLE001
            self._json(HTTPStatus.UNAUTHORIZED, {"error": str(err)})

    def do_GET(self) -> None:  # noqa: N802
        parts = self.path.strip("/").split("/")
        if len(parts) != 4 or parts[0] != "v1" or parts[1] != "releases":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        tag, asset = parts[2], parts[3]

        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "missing bearer token"})
            return
        token = auth[len("Bearer ") :].strip()

        try:
            claims = verify_token(token, tag)
            if "ferro-desktop" in asset and not claims.get("desktop_allowed", False):
                raise ValueError("desktop artifact not permitted for token")
            safe_asset = pathlib.PurePath(asset)
            if safe_asset.name != asset or any(part in {"..", ""} for part in safe_asset.parts):
                raise ValueError("invalid artifact name")
            artifact_path = ARTIFACT_ROOT / tag / asset
            if not artifact_path.exists() or not artifact_path.is_file():
                self._json(HTTPStatus.NOT_FOUND, {"error": "artifact not found"})
                return
            with artifact_path.open("rb") as handle:
                data = handle.read()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as err:  # noqa: BLE001
            self._json(HTTPStatus.UNAUTHORIZED, {"error": str(err)})


def main() -> None:
    if ":" not in BIND:
        raise SystemExit("PAID_GATEWAY_BIND must be host:port")
    host, port_str = BIND.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port_str)), Handler)
    print(f"paid artifact gateway listening on {BIND}")
    server.serve_forever()


if __name__ == "__main__":
    main()
