#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
forwarder="$ROOT_DIR/bench/suites/buildkit-dockerfile/dockerd-forwarder.py"

python3 - "$forwarder" <<'PYEOF'
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

forwarder = sys.argv[1]
with tempfile.TemporaryDirectory() as work:
    sock = pathlib.Path(work, "dockerd.sock")
    env = dict(os.environ, BK_GATE=str(pathlib.Path(work, "gate.sock")))
    proc = subprocess.Popen(
        [sys.executable, forwarder, "--host", f"unix://{sock}"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(100):
        if sock.exists():
            break
        if proc.poll() is not None:
            break
        time.sleep(0.01)
    else:
        proc.kill()
        raise AssertionError("dockerd forwarder did not create its socket")

    proc.send_signal(signal.SIGINT)
    stdout, stderr = proc.communicate(timeout=5)
    assert proc.returncode == 0, (proc.returncode, stdout, stderr)
    assert "Traceback" not in stderr, stderr

print("buildkit dockerd forwarder tests passed")
PYEOF
