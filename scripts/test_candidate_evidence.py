import importlib.util
import hashlib
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check-candidate-evidence.py")


class EvidenceTests(unittest.TestCase):
    def validator(self):
        self.assertTrue(SCRIPT.exists(), "candidate evidence validator is missing")
        spec = importlib.util.spec_from_file_location("candidate_evidence", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self, root):
        module = self.validator()
        (root / "result.log").write_text("candidate fixture output\n")
        record = {"status": "pass", "source_commit": "a" * 40, "source_dirty": False,
                  "exit_code": 0, "command": "fixture-check", "host": "fixture-host",
                  "toolchain": "fixture-toolchain", "binary_sha256": "b" * 64,
                  "files": [{"path": "result.log", "sha256": hashlib.sha256((root / "result.log").read_bytes()).hexdigest()}]}
        import copy
        return module, {"schema_version": 1, "source_commit": "a" * 40, "source_dirty": False,
                        "checks": {name: copy.deepcopy(record) for name in (*module.REQUIRED_CHECKS, "host:fixture")}}

    def test_complete_bound_evidence_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module, manifest = self.fixture(root)
            self.assertEqual(module.validate(manifest, "a" * 40, ["fixture"], root), [])

    def test_historical_dirty_missing_skipped_or_failed_rows_block(self):
        for mutation in ("historical", "dirty", "missing", "skipped", "failed", "unsupported", "empty"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                module, manifest = self.fixture(root)
                record = manifest["checks"]["host:fixture"]
                if mutation == "historical": record["source_commit"] = "c" * 40
                elif mutation == "dirty": record["source_dirty"] = True
                elif mutation == "missing": del manifest["checks"]["host:fixture"]
                elif mutation == "empty": record["files"] = []
                else: record["status"] = mutation
                self.assertTrue(module.validate(manifest, "a" * 40, ["fixture"], root))

    def test_modified_artifact_and_path_escape_block(self):
        for mutation in ("modified", "escape"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                module, manifest = self.fixture(root)
                if mutation == "modified": (root / "result.log").write_text("replaced output")
                else: manifest["checks"]["host:fixture"]["files"][0]["path"] = "../outside"
                self.assertTrue(module.validate(manifest, "a" * 40, ["fixture"], root))

    def test_global_candidate_mismatch_and_empty_bundle_block(self):
        module = self.validator()
        self.assertTrue(module.validate({}, "a" * 40, ["fixture"], Path(".")))


if __name__ == "__main__":
    unittest.main()
