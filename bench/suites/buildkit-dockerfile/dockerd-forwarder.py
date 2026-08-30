#!/usr/bin/env python3
"""Minimal dockerd socket forwarder for BuildKit's integration harness."""

import json
import os
import signal
import socket
import sys
import threading


def socket_path(args: list[str]) -> str | None:
    for index, arg in enumerate(args):
        if arg == "--host" and index + 1 < len(args):
            host = args[index + 1]
            return host[len("unix://") :] if host.startswith("unix://") else host
    return None


def option_path(args: list[str], name: str) -> str | None:
    for index, arg in enumerate(args):
        if arg == name and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(f"{name}="):
            return arg.split("=", 1)[1]
    return None


def gate_path(args: list[str], routes: dict[str, str]) -> str:
    config_path = option_path(args, "--config-file")
    if config_path is None:
        raise ValueError("worker daemon config is missing --config-file")
    try:
        with open(config_path, encoding="utf-8") as config_file:
            config = json.load(config_file)
    except (OSError, ValueError) as error:
        raise ValueError(f"worker daemon config cannot be read: {error}") from error

    builder = config.get("builder", {})
    entitlements = builder.get("Entitlements", builder.get("entitlements", {}))
    network_host = entitlements.get("network-host") is True
    security_insecure = entitlements.get("security-insecure") is True
    if network_host and security_insecure:
        route = "all"
    elif network_host:
        route = "network-host"
    elif security_insecure:
        route = "security-insecure"
    else:
        route = "none"
    target = routes.get(route)
    if not target:
        raise ValueError(f"worker daemon route is not configured: {route}")
    return target


def pump(source: socket.socket, destination: socket.socket) -> None:
    try:
        while data := source.recv(65536):
            destination.sendall(data)
    except OSError:
        pass
    finally:
        for connection in (source, destination):
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


PING_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Api-Version: 1.43\r\n"
    b"Builder-Version: 2\r\n"
    b"Ostype: linux\r\n"
    b"Docker-Experimental: false\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)


def request_head(connection: socket.socket) -> bytes:
    request = b""
    while b"\r\n\r\n" not in request and len(request) < 65536:
        chunk = connection.recv(4096)
        if not chunk:
            break
        request += chunk
    return request


def handle(connection: socket.socket, gate: str) -> None:
    request = request_head(connection)
    line = request.split(b"\r\n", 1)[0].split()
    if (
        len(line) >= 2
        and line[0] == b"HEAD"
        and line[1].rstrip(b"/").endswith(b"_ping")
    ):
        connection.sendall(PING_RESPONSE)
        connection.close()
        return
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(gate)
    except OSError:
        connection.close()
        upstream.close()
        return
    if request:
        try:
            upstream.sendall(request)
        except OSError:
            connection.close()
            upstream.close()
            return
    threading.Thread(
        target=pump, args=(connection, upstream), daemon=True
    ).start()
    pump(upstream, connection)


def stop_cleanly(_signum: int, _frame: object) -> None:
    raise SystemExit(0)


def main() -> int:
    path = socket_path(sys.argv[1:])
    if path is None:
        return 1
    routes = {
        "none": os.environ.get("BK_GATE_NONE", ""),
        "network-host": os.environ.get("BK_GATE_NETWORK_HOST", ""),
        "security-insecure": os.environ.get("BK_GATE_SECURITY_INSECURE", ""),
        "all": os.environ.get("BK_GATE_ALL", ""),
    }
    try:
        gate = gate_path(sys.argv[1:], routes)
    except ValueError as error:
        print(f"dockerd forwarder: {error}", file=sys.stderr)
        return 2
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(128)
    signal.signal(signal.SIGINT, stop_cleanly)
    signal.signal(signal.SIGTERM, stop_cleanly)
    try:
        while True:
            connection, _ = listener.accept()
            threading.Thread(
                target=handle, args=(connection, gate), daemon=True
            ).start()
    finally:
        listener.close()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    sys.exit(main())
