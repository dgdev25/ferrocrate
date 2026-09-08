import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("local-release-gate.sh").resolve()


class LocalGateTests(unittest.TestCase):
    def run_gate(self, fail="", args=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "scripts").mkdir()
            for name in ("cargo", "bash", "python3", "node", "npm", "docker", "git"):
                path = root / "bin" / name
                path.write_text('''#!/bin/bash
set -eu
name="${0##*/}"
printf '%s %s\n' "$name" "$*" >>"$FIXTURE_CALLS"
if [[ "$name $*" == *"$FIXTURE_FAIL"* && -n "$FIXTURE_FAIL" ]]; then exit 23; fi
if [[ "$name" == git && "$*" == *rev-parse* ]]; then printf '%040d\n' 1; fi
exit 0
''')
                path.chmod(0o755)
            env = dict(os.environ, PATH=f"{root / 'bin'}:{os.environ['PATH']}",
                       FERROCRATE_REPO_ROOT=directory, CARGO_TARGET_DIR=str(root / "target"),
                       FERROCRATE_CARGO=str(root / "bin/cargo"), GITHUB_SHA="0" * 39 + "1",
                       FERROCRATE_RELEASE_ARTIFACT_DIR=str(root / "artifacts"),
                       FIXTURE_CALLS=str(root / "calls"), FIXTURE_FAIL=fail,
                       FERROCRATE_CANDIDATE_EVIDENCE=str(root / "candidate.json"))
            result = subprocess.run(["/bin/bash", str(SCRIPT), *args], env=env, capture_output=True, text=True)
            calls = (root / "calls").read_text() if (root / "calls").exists() else ""
            return result, calls

    def test_failed_readiness_stops_before_packaging(self):
        result, calls = self.run_gate("bash scripts/verify-release-readiness.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("local release gate passed", result.stdout)
        self.assertNotIn("bash scripts/build-release-artifacts.sh", calls)

    def test_candidate_evidence_failure_stops_gate(self):
        result, calls = self.run_gate("check-candidate-evidence.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("local release gate passed", result.stdout)

    def test_dependency_failure_stops_gate(self):
        for command in ("cargo audit", "npm audit", "check-advisory-exceptions.py"):
            result, _ = self.run_gate(command)
            self.assertNotEqual(result.returncode, 0, command)

    def test_skipped_gate_cannot_claim_release_pass(self):
        result, _ = self.run_gate(args=("--skip-workspace", "--skip-format"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("partial", result.stdout.lower())
        self.assertNotIn("local release gate passed", result.stdout)

    def test_full_gate_executes_new_contracts_and_frontend(self):
        result, calls = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in ("check-release-workflows.py", "test_release_workflow_contracts.py", "test_local_release_gate.py",
                        "test_readiness_scope.py", "test_candidate_evidence.py", "test-suite", "release-artifacts.test.mjs",
                        "check-advisory-exceptions.py", "cargo audit", "npm audit", "typecheck", "lint"):
            if command == "test-suite":
                command = "test_suite_*.py"
            self.assertIn(command, calls)


if __name__ == "__main__":
    unittest.main()
