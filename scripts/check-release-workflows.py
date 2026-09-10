#!/usr/bin/env python3
"""Fail closed on hosted-runner fallback or weakened candidate publication gates.

Requires PyYAML supplied by the self-hosted runner's managed toolchain.
"""
from pathlib import Path
import re
import tomllib
try:
    import yaml
except ImportError:
    raise SystemExit("workflow validation requires PyYAML on the self-hosted runner")


REQUIRED_WORKSPACE_MEMBERS = {"ferro-core", "ferro-cri", "ferro-compose", "ferro-net", "ferro-desktop"}
REQUIRED_DESKTOP_COMMANDS = {
    "cargo test --manifest-path apps/ferro-desktop-ui/src-tauri/Cargo.toml",
    "npm run --prefix apps/ferro-desktop-ui test",
    "npm run --prefix apps/ferro-desktop-ui typecheck",
    "npm run --prefix apps/ferro-desktop-ui lint",
    "npm run --prefix apps/ferro-desktop-ui build",
}


def validate(workflows, workspace_members=None):
    errors = []
    def require(condition, message):
        if not condition:
            errors.append(message)

    def self_hosted(value, allow_qualified=False):
        if isinstance(value, dict):
            value = value.get("labels")
        if value == "self-hosted":
            return False
        if not isinstance(value, list) or "self-hosted" not in value:
            return False
        if not all(isinstance(v, str) and "${{" not in v for v in value):
            return False
        return "ferro-lab" in value or allow_qualified and "ferro-release-qualified" in value

    for filename, workflow in workflows.items():
        for name, job in workflow.get("jobs", {}).items():
            label = f"{filename}/{name}"
            if "uses" in job:
                local = job["uses"].removeprefix("./.github/workflows/")
                require(job["uses"].startswith("./.github/workflows/") and local in workflows,
                        label + ": reusable workflow must be a validated local file")
                continue
            runner = job.get("runs-on")
            if runner == "${{ matrix.runner }}":
                matrix = job.get("strategy", {}).get("matrix", {})
                values = [entry.get("runner") for entry in matrix.get("include", [])]
                values += matrix.get("runner", [])
                require(bool(values) and all(self_hosted(value) for value in values), label + ": matrix runner must always be self-hosted ferro-lab")
            else:
                require(self_hosted(runner, name == "candidate-qualification"), label + ": runner must explicitly be self-hosted ferro-lab")
    release = workflows.get("release.yml", {}).get("jobs", {})
    ci = workflows.get("ci.yml", {}).get("jobs", {})
    if workspace_members is not None:
        for member in sorted(REQUIRED_WORKSPACE_MEMBERS):
            require(member in workspace_members, "workspace must include " + member)
    validation = release.get("candidate-validation", {})
    qualification = release.get("candidate-qualification", {})
    publish = release.get("publish", {})
    require(validation.get("uses") == "./.github/workflows/ci.yml", "candidate-validation must invoke local CI")
    needs = publish.get("needs", [])
    require(isinstance(needs, list) and {"candidate-validation", "candidate-qualification", "cli", "linux-desktop", "macos-desktop", "windows-desktop"} <= set(needs), "publication must depend on all candidate and packaging jobs")
    require(publish.get("if") in (None, "success()", "${{ success() }}"), "publication may not bypass dependency success")
    require(qualification.get("needs") == "candidate-validation", "qualification must follow candidate validation")
    require("ferro-release-qualified" in qualification.get("runs-on", []), "privileged qualification requires its dedicated runner label")
    require(qualification.get("env", {}).get("FERROCRATE_READINESS_REQUIRED") == "rootful,apparmor,rootless", "qualification must retain all required host modes")
    for name, job in [("candidate-validation", validation), ("candidate-qualification", qualification), *ci.items()]:
        require(not job.get("continue-on-error"), name + ": candidate job cannot ignore failure")
        for step in job.get("steps", []):
            require(not step.get("continue-on-error"), name + ": candidate step cannot ignore failure")
    for name, job in release.items():
        for step in job.get("steps", []):
            if step.get("uses", "").startswith("actions/checkout@"):
                require(step.get("with", {}).get("ref") == "${{ github.sha }}", name + ": checkout must pin github.sha")
    for name, job in ci.items():
        for step in job.get("steps", []):
            if step.get("uses", "").startswith("actions/checkout@"):
                require(step.get("with", {}).get("ref") == "${{ github.sha }}", name + ": reusable CI checkout must pin github.sha")
    gate_steps = [step for step in qualification.get("steps", []) if "local-release-gate.sh" in step.get("run", "")]
    require(qualification.get("if") in (None, "success()", "${{ success() }}"), "qualification job cannot be conditionally skipped")
    require(len(gate_steps) == 1, "qualification must run exactly one full local release gate")
    for step in gate_steps:
        script = step["run"]
        require(step.get("if") in (None, "success()", "${{ success() }}"), "qualification gate cannot be conditionally skipped")
        require(step.get("shell") == "bash", "qualification gate must use fail-fast Bash")
        require(re.search(r'^\s*bash scripts/local-release-gate\.sh --version "\$GITHUB_REF_NAME"\s*$', script, re.M), "local gate must be unconditional, full and failure-propagating")
        require("set +e" not in script and "|| true" not in script, "local gate failure must not be masked")
        require('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in script, "qualification must assert the candidate SHA")
    runtime_steps = [step for step in ci.get("build-unit-warnings", {}).get("steps", [])
                     if re.search(r'^\s*cargo test --workspace --all-features --locked(?: -- --test-threads=1)?\s*$', step.get("run", ""), re.M)]
    require(bool(runtime_steps), "CI must execute the supported workspace tests")
    for step in runtime_steps:
        require(step.get("if") in (None, "success()", "${{ success() }}"), "runtime tests cannot be conditionally skipped")
        require(step.get("shell") == "bash", "runtime tests require fail-fast Bash")
        require("set +e" not in step["run"] and "|| true" not in step["run"], "runtime test failures must propagate")
    ci_commands = "\n".join(step.get("run", "") for job in ci.values() for step in job.get("steps", []))
    for command in sorted(REQUIRED_DESKTOP_COMMANDS):
        require(command in ci_commands, "CI must execute desktop gate: " + command)
    return errors


def main():
    root = Path(__file__).resolve().parents[1]
    workflows = {path.name: yaml.safe_load(path.read_text()) for path in (root / ".github/workflows").glob("*.yml")}
    with (root / "Cargo.toml").open("rb") as handle:
        workspace_members = {Path(member).name for member in tomllib.load(handle)["workspace"]["members"]}
    errors = validate(workflows, workspace_members)
    if errors:
        print("\n".join(errors))
        return 1
    print("Release workflow contracts passed: self-hosted only; candidate-bound failure-propagating publication")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
