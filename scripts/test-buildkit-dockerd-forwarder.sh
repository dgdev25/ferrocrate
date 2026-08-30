#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
forwarder="$ROOT_DIR/bench/suites/buildkit-dockerfile/dockerd-forwarder.py"
runner="$ROOT_DIR/bench/suites/run-suite.sh"

python3 - "$forwarder" "$runner" <<'PYEOF'
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

forwarder, runner = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("dockerd_forwarder", forwarder)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as work:
    work = pathlib.Path(work)
    routes = {
        "none": str(work / "none.sock"),
        "network-host": str(work / "network.sock"),
        "security-insecure": str(work / "security.sock"),
        "all": str(work / "all.sock"),
    }
    for name, expected in (
        ("none", routes["none"]),
        ("network", routes["network-host"]),
        ("security", routes["security-insecure"]),
        ("all", routes["all"]),
    ):
        config = work / f"{name}.json"
        entitlements = {}
        if name in ("network", "all"):
            entitlements["network-host"] = True
        if name in ("security", "all"):
            entitlements["security-insecure"] = True
        config.write_text(json.dumps({"builder": {"Entitlements": entitlements}}))
        assert module.gate_path(["--config-file", str(config)], routes) == expected

    missing = work / "missing.json"
    try:
        module.gate_path(["--config-file", str(missing)], routes)
    except ValueError as error:
        assert "daemon config" in str(error)
    else:
        raise AssertionError("missing worker daemon config must fail closed")

    sock = pathlib.Path(work, "dockerd.sock")
    config = pathlib.Path(work, "worker.json")
    config.write_text('{"builder":{"Entitlements":{}}}')
    env = dict(os.environ, BK_GATE_NONE=str(pathlib.Path(work, "gate.sock")))
    proc = subprocess.Popen(
        [
            sys.executable,
            forwarder,
            "--host",
            f"unix://{sock}",
            "--config-file",
            str(config),
        ],
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

runner_source = pathlib.Path(runner).read_text()
assert 'PRE=(unshare -Ur env TEST_DOCKERD=1' in runner_source
assert '--privileged --pid host --network host' in runner_source
assert 'exec "$container" chmod 666 "/host$socket"' in runner_source

print("buildkit dockerd forwarder tests passed")
PYEOF
