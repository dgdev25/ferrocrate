import importlib.util
import json
from pathlib import Path
import unittest


PARSER = Path(__file__).parent / "suites" / "parse-results.py"


class ParserTests(unittest.TestCase):
    def parser(self):
        self.assertTrue(PARSER.exists(), "suite producer needs a testable provenance-preserving parser")
        spec = importlib.util.spec_from_file_location("suite_results", PARSER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_go_retains_package_and_marks_parent_aggregate(self):
        events = [dict(Package="one", Test="Test", Action="fail"),
                  dict(Package="one", Test="Test/child", Action="fail"),
                  dict(Package="two", Test="Test", Action="pass")]
        rows = self.parser().parse_go("\n".join(map(json.dumps, events)), None)
        self.assertEqual(len(rows), 3)
        parent = next(row for row in rows if row["package"] == "one" and row["step"] == "Test")
        self.assertEqual(parent["record_type"], "aggregate")

    def test_go_aborted_tests_and_empty_runs_are_harness_errors(self):
        for output in ("", json.dumps(dict(Package="one", Test="Test", Action="run"))):
            rows = self.parser().parse_go(output, None)
            self.assertTrue(any(row["status"] == "error" for row in rows))

    def test_skip_list_does_not_erase_an_executed_failure(self):
        rows = self.parser().parse_go(json.dumps(dict(Package="one", Test="Test", Action="fail")), "Test")
        self.assertEqual(rows[0]["status"], "fail")

    def test_cri_hook_is_not_a_passing_spec(self):
        report = [{"SpecReports": [
            {"State": "passed", "LeafNodeType": "BeforeSuite", "LeafNodeText": None},
            {"State": "passed", "ContainerHierarchyTexts": ["runtime"], "LeafNodeText": "starts"},
            {"State": "failed", "LeafNodeText": "stops", "Failure": {"Message": "failure"}},
            {"State": "pending", "LeafNodeText": "pending"}]}]
        rows = self.parser().parse_cri(report)
        self.assertEqual(sum(row["record_type"] == "leaf" for row in rows), 3)
        self.assertEqual(rows[0]["record_type"], "aggregate")
        self.assertEqual(rows[2]["status"], "fail")


if __name__ == "__main__":
    unittest.main()
