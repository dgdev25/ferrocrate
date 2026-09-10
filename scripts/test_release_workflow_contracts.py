import importlib.util
from pathlib import Path
import tempfile
import unittest
import yaml
import tomllib

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

    def workspace_members(self):
        with (ROOT / "Cargo.toml").open("rb") as handle:
            return {Path(member).name for member in tomllib.load(handle)["workspace"]["members"]}

    def test_current_workflows_satisfy_contract(self):
        self.assertEqual(self.validator().validate(self.workflows(), self.workspace_members()), [])

    def test_hosted_runner_in_matrix_is_rejected(self):
        workflows = self.workflows()
        workflows["ci.yml"]["jobs"]["build-unit-warnings"]["strategy"]["matrix"]["include"][0]["runner"] = "ubuntu-latest"
        self.assertTrue(self.validator().validate(workflows))

    def test_matrix_runner_requires_ferro_lab_label(self):
        workflows = self.workflows()
        workflows["ci.yml"]["jobs"]["build-unit-warnings"]["strategy"]["matrix"]["include"][0]["runner"] = ["self-hosted", "linux", "x64"]
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

    def test_required_workspace_member_cannot_disappear(self):
        members = self.workspace_members()
        members.remove("ferro-cri")
        self.assertTrue(self.validator().validate(self.workflows(), members))

    def test_ci_requires_desktop_gate_commands(self):
        workflows = self.workflows()
        unit = next(step for step in workflows["ci.yml"]["jobs"]["build-unit-warnings"]["steps"] if step.get("name") == "Unit gates")
        unit["run"] = unit["run"].replace("npm run --prefix apps/ferro-desktop-ui typecheck\n", "")
        self.assertTrue(self.validator().validate(workflows, self.workspace_members()))

    def test_pull_request_target_and_missing_fork_guard_are_rejected(self):
        workflows = self.workflows()
        workflows["ci.yml"][True]["pull_request_target"] = {}
        workflows["ci.yml"]["jobs"]["build-unit-warnings"].pop("if")
        errors = self.validator().validate(workflows, self.workspace_members())
        self.assertTrue(any("pull_request_target" in error for error in errors))
        self.assertTrue(any("same-repository guard" in error for error in errors))

    def test_desktop_gate_cannot_be_masked_or_skipped(self):
        workflows = self.workflows()
        unit = next(step for step in workflows["ci.yml"]["jobs"]["build-unit-warnings"]["steps"] if step.get("name") == "Unit gates")
        unit["run"] = unit["run"].replace(
            "npm run --prefix apps/ferro-desktop-ui test",
            "npm run --prefix apps/ferro-desktop-ui test || true",
        )
        errors = self.validator().validate(workflows, self.workspace_members())
        self.assertTrue(any("desktop gate failure must propagate" in error for error in errors))

    def test_load_workflows_includes_yaml_suffix(self):
        validator = self.validator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "visible.yaml").write_text("name: Visible\njobs: {}\n")
            self.assertIn("visible.yaml", validator.load_workflows(root))


if __name__ == "__main__":
    unittest.main()
