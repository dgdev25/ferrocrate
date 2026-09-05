"""Exercise readiness failure propagation without mutating host namespaces."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("verify-release-readiness.sh").resolve()


class ReadinessScopeTests(unittest.TestCase):
    def run_gate(self, scope="rootful,apparmor,rootless", uid="1000", rootless=0, apparmor=0):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "scripts").mkdir()
            (root / "bin").mkdir()
            for name in ["verify-host-matrix-evidence", "test-cri-rootful-recovery", "verify-mac-policy", "test-apparmor-enforcement", "compat-evidence", "test-check-linux-binary-compat", "verify-rootless"]:
                code = rootless if name == "verify-rootless" else 0
                (root / "scripts" / f"{name}.sh").write_text(f"#!/bin/bash\nexit {code}\n")
            for name, body in {"cargo": "exit 0", "id": f"echo {uid}", "aa-status": f"exit {apparmor}"}.items():
                p = root / "bin" / name
                p.write_text(f"#!/bin/bash\n{body}\n")
                p.chmod(0o755)
            env = dict(os.environ, PATH=f"{root / 'bin'}:{os.environ['PATH']}", FERROCRATE_REPO_ROOT=temp, FERROCRATE_READINESS_REQUIRED=scope)
            return subprocess.run(["bash", str(SCRIPT)], env=env, text=True, capture_output=True)

    def test_required_rootful_cannot_skip(self):
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_required_apparmor_cannot_skip(self):
        self.assertNotEqual(self.run_gate(uid="0", apparmor=1).returncode, 0)

    def test_required_rootless_failure_is_fatal(self):
        self.assertNotEqual(self.run_gate(scope="rootless", rootless=1).returncode, 0)

    def test_optional_host_rows_are_explicit(self):
        result = self.run_gate(scope="none", rootless=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not-required", result.stdout)
        self.assertNotIn("readiness checks passed", result.stdout)

    def test_all_required_checks_pass(self):
        result = self.run_gate(uid="0")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_misspelled_scope_fails_closed(self):
        self.assertNotEqual(self.run_gate(scope="rootles").returncode, 0)


if __name__ == "__main__":
    unittest.main()
