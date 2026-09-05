import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("suite-scoreboard.py")


class ScoreboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.selection = {"candidate_head": "candidate", "suites": {}}

    def records(self, suite, engine, rows, **overrides):
        path = self.root / f"{suite}-{engine}.jsonl"
        records = [dict(suite=suite, engine=engine, head="candidate", run="run-1",
                        suite_head="upstream", step=step, status=status, **extra)
                   for step, status, extra in rows]
        for row in records:
            row.update(overrides)
        path.write_text("".join(json.dumps(row) + "\n" for row in records))
        entry = self.selection["suites"].setdefault(suite, {"suite_head": "upstream"})
        entry[engine] = {"path": str(path), "head": "candidate", "run": "run-1"}
        return path

    def report(self):
        path = self.root / "selection.json"
        path.write_text(json.dumps(self.selection))
        result = subprocess.run([sys.executable, str(SCRIPT), "--selection", str(path), "--json"],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("{"), "scoreboard ignored explicit selection/JSON arguments")
        return json.loads(result.stdout)

    def test_requires_explicit_selection(self):
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.root)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_only_selected_files_count_even_when_newer_evidence_exists(self):
        self.records("cli", "ferrocrate", [("test", "fail", {})])
        self.records("cli", "docker", [("test", "pass", {})])
        (self.root / "newer-ferrocrate.jsonl").write_text('{"status":"pass"}\n')
        row = self.report()["suites"]["cli"]
        self.assertEqual(row["counts"]["product_fail"], 1)
        self.assertFalse(row["qualified"])

    def test_mismatched_candidate_or_suite_cannot_be_paired(self):
        for field in ("head", "suite_head", "run"):
            with self.subTest(field=field):
                self.records("cli", "ferrocrate", [("test", "fail", {})], **{field: "other"})
                self.records("cli", "docker", [("test", "pass", {})])
                row = self.report()["suites"]["cli"]
                self.assertEqual(row["counts"]["product_fail"], 0)
                self.assertEqual(row["counts"]["fail_unpaired"], 1)
                self.assertTrue(row["provenance_errors"])

    def test_leaf_aggregate_harness_scope_and_absence_are_distinct(self):
        rows = [("TestParent", "fail", {}), ("TestParent/child", "fail", {}),
                ("broken", "error", {}), ("skipped", "skip", {}),
                ("outside", "unsupported", {"reason": "scope", "scope_ref": "matrix#outside"}),
                ("shared", "fail", {})]
        self.records("cli", "ferrocrate", rows)
        self.records("cli", "docker", [("TestParent/child", "pass", {}),
                                         ("missing", "skip", {}), ("shared", "fail", {})])
        row = self.report()["suites"]["cli"]
        for key in ("aggregate_fail", "product_fail", "harness_error", "skip", "unsupported", "shared_fail", "absent"):
            self.assertEqual(row["counts"][key], 1, key)

    def test_cri_failures_need_no_docker_oracle_and_blank_hooks_are_not_passes(self):
        self.records("critest", "ferrocrate", [("critest-summary", "fail", {}),
                     ("", "pass", {}), ("spec1", "pass", {}), ("spec2", "fail", {}), ("spec3", "skip", {})])
        row = self.report()["suites"]["critest"]
        self.assertEqual(row["oracle"], "not-applicable")
        self.assertEqual(row["counts"]["pass"], 1)
        self.assertEqual(row["counts"]["product_fail"], 1)
        self.assertEqual(row["counts"]["skip"], 1)
        self.assertEqual(row["counts"]["aggregate_fail"], 1)
        self.assertFalse(row["qualified"])

    def test_missing_oracle_and_empty_files_do_not_qualify(self):
        self.records("cli", "ferrocrate", [("test", "pass", {})])
        self.records("oci-runtime", "ferrocrate", [])
        report = self.report()
        self.assertEqual(report["suites"]["cli"]["counts"]["no_oracle"], 1)
        self.assertFalse(report["suites"]["cli"]["qualified"])
        self.assertFalse(report["suites"]["oci-runtime"]["qualified"])

    def test_legacy_missing_suite_revision_remains_unverified(self):
        self.records("cli", "ferrocrate", [("test", "pass", {})], suite_head=None)
        self.records("cli", "docker", [("test", "pass", {})], suite_head=None)
        row = self.report()["suites"]["cli"]
        self.assertTrue(row["provenance_errors"])
        self.assertFalse(row["qualified"])

    def test_duplicate_names_are_not_silently_overwritten(self):
        self.records("cli", "ferrocrate", [("test", "fail", {}), ("test", "pass", {})])
        self.records("cli", "docker", [("test", "pass", {})])
        row = self.report()["suites"]["cli"]
        self.assertTrue(row["evidence_errors"])
        self.assertFalse(row["qualified"])

    def test_different_packages_do_not_collapse(self):
        rows = [("Test", "pass", {"package": "one"}), ("Test", "pass", {"package": "two"})]
        self.records("cli", "ferrocrate", rows)
        self.records("cli", "docker", rows)
        row = self.report()["suites"]["cli"]
        self.assertEqual(row["counts"]["pass"], 2)
        self.assertTrue(row["qualified"])

    def test_empty_scope_and_unjustified_unsupported_do_not_qualify(self):
        for extra in ({}, {"reason": "scope", "scope_ref": "matrix#outside"}):
            self.records("cli", "ferrocrate", [("test", "unsupported", extra)])
            self.records("cli", "docker", [("test", "pass", {})])
            self.assertFalse(self.report()["suites"]["cli"]["qualified"])

    def test_check_exits_nonzero_for_unqualified_selection(self):
        self.records("cli", "ferrocrate", [("test", "fail", {})])
        self.report()
        result = subprocess.run([sys.executable, str(SCRIPT), "--selection",
                                 str(self.root / "selection.json"), "--check"], capture_output=True)
        self.assertEqual(result.returncode, 1)

    def test_skipped_oracle_is_not_qualifying_evidence(self):
        self.records("cli", "ferrocrate", [("test", "pass", {})])
        self.records("cli", "docker", [("test", "skip", {})])
        self.assertFalse(self.report()["suites"]["cli"]["qualified"])

    def test_omitted_suite_and_expected_test_are_explicit_absences(self):
        self.selection["suites"]["oci-runtime"] = {"suite_head": "upstream"}
        self.records("cli", "ferrocrate", [("test", "pass", {})])
        self.records("cli", "docker", [("test", "pass", {})])
        self.selection["suites"]["cli"]["expected_steps"] = ["test", "never-run"]
        report = self.report()
        self.assertEqual(report["suites"]["cli"]["counts"]["absent"], 1)
        self.assertTrue(report["suites"]["oci-runtime"]["evidence_errors"])
        self.assertFalse(report["qualified"])

    def test_digest_mismatch_blocks_file_replacement(self):
        self.records("cli", "ferrocrate", [("test", "pass", {})])
        self.records("cli", "docker", [("test", "pass", {})])
        self.selection["suites"]["cli"]["ferrocrate"]["sha256"] = "wrong"
        self.assertFalse(self.report()["suites"]["cli"]["qualified"])

    def test_explicit_harness_record_is_not_hidden_by_summary_name(self):
        self.records("cli", "ferrocrate", [("package-summary", "error", {"record_type": "leaf"})])
        row = self.report()["suites"]["cli"]
        self.assertEqual(row["counts"]["harness_error"], 1)


if __name__ == "__main__":
    unittest.main()
