import importlib.util
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/check-release-workflows.py"


class WorkflowContracts(unittest.TestCase):
    def validator(self):
        self.assertTrue(SCRIPT.exists(), "release workflow contract validator is missing")
        spec = importlib.util.spec_from_file_location("workflow_contract", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def workflows(self):
        return {path.name: yaml.safe_load(path.read_text()) for path in (ROOT / ".github/workflows").glob("*.y*ml")}

    def test_current_workflows_satisfy_contract(self):
        self.assertEqual(self.validator().validate(self.workflows()), [])

    def test_hosted_runner_in_matrix_is_rejected(self):
        workflows = self.workflows()
        workflows["ci.yml"]["jobs"]["build-unit-warnings"]["strategy"]["matrix"]["include"][0]["runner"] = "ubuntu-latest"
        self.assertTrue(self.validator().validate(workflows))

    def test_hosted_canary_and_external_reusable_are_rejected(self):
        for job in ({"runs-on": "ubuntu-latest", "steps": []}, {"uses": "other/repo/.github/workflows/ci.yml@main"}):
            workflows = self.workflows()
            workflows["extra.yml"] = {"jobs": {"unsafe": job}}
            self.assertTrue(self.validator().validate(workflows))

    def test_publication_must_depend_on_validation_and_qualification(self):
        for removed in ("candidate-validation", "candidate-qualification"):
            workflows = self.workflows()
            workflows["release.yml"]["jobs"]["publish"]["needs"].remove(removed)
            self.assertTrue(self.validator().validate(workflows))

    def test_publication_cannot_run_after_failure(self):
        workflows = self.workflows()
        workflows["release.yml"]["jobs"]["publish"]["if"] = "${{ always() }}"
        self.assertTrue(self.validator().validate(workflows))

    def test_qualification_cannot_ignore_gate_failure(self):
        for mutation in ("continue", "mask", "wrong-sha"):
            workflows = self.workflows()
            job = workflows["release.yml"]["jobs"]["candidate-qualification"]
            step = next(step for step in job["steps"] if "local-release-gate.sh" in step.get("run", ""))
            if mutation == "continue":
                step["continue-on-error"] = True
            elif mutation == "mask":
                step["run"] = step["run"].replace('bash scripts/local-release-gate.sh --version "$GITHUB_REF_NAME"', 'bash scripts/local-release-gate.sh --version "$GITHUB_REF_NAME" || true')
            else:
                job["steps"][0]["with"] = {"ref": "main"}
            self.assertTrue(self.validator().validate(workflows), mutation)

    def test_qualification_step_cannot_be_conditionally_skipped(self):
        workflows = self.workflows()
        job = workflows["release.yml"]["jobs"]["candidate-qualification"]
        step = next(step for step in job["steps"] if "local-release-gate.sh" in step.get("run", ""))
        step["if"] = "false"
        self.assertTrue(self.validator().validate(workflows))

    def test_ci_cannot_replace_runtime_execution_with_build(self):
        workflows = self.workflows()
        job = workflows["ci.yml"]["jobs"]["build-unit-warnings"]
        for step in job["steps"]:
            if "cargo test --workspace" in step.get("run", ""):
                step["run"] = "cargo build --workspace --all-features --locked"
        self.assertTrue(self.validator().validate(workflows))


if __name__ == "__main__":
    unittest.main()
