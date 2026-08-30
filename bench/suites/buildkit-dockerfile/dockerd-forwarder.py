#!/usr/bin/env python3
"""Minimal dockerd socket forwarder for BuildKit's integration harness."""

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


def handle(connection: socket.socket, gate: str) -> None:
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(gate)
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
    gate = os.environ["BK_GATE"]
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
