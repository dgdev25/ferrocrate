#!/usr/bin/env python3
"""Normalize borrowed-suite output without hiding aggregates or incomplete runs."""
import argparse
import json
import re
from pathlib import Path


def fault(message, step="harness"):
    return {"step": step, "status": "error", "record_type": "leaf", "stderr_tail": message}


def parse_go(output, skip_pattern):
    tests, logs, packages = {}, {}, {}
    no_test_packages = set()
    faults = []
    pattern = re.compile(skip_pattern) if skip_pattern else None
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            faults.append(fault("malformed go test JSON event", f"harness-json-{len(faults)}"))
            continue
        package, name, action = event.get("Package", ""), event.get("Test"), event.get("Action")
        if not name:
            if action == "output" and "[no test files]" in event.get("Output", ""):
                no_test_packages.add(package)
            if action in ("pass", "fail", "skip"):
                packages[package] = action
            continue
        key = (package, name)
        if action == "run":
            tests.setdefault(key, "error")
        elif action in ("pass", "fail", "skip"):
            tests[key] = action
        elif action == "output":
            logs.setdefault(key, []).append(event.get("Output", ""))
    rows = []
    for (package, name), status in sorted(tests.items()):
        aggregate = any(p == package and child.startswith(name + "/") for p, child in tests)
        tail = "".join(line for line in "".join(logs.get((package, name), [])).splitlines(keepends=True)
                       if "framework.go:147" not in line)[-800:]
        rows.append({"package": package, "step": name, "status": status,
                     "record_type": "aggregate" if aggregate else "leaf",
                     "scope_skip_match": bool(pattern and pattern.search(name)),
                     "stderr_tail": tail if status in ("fail", "error") else ""})
    for package, status in sorted(packages.items()):
        has_tests = any(p == package for p, _ in tests)
        explicit_helper = package in no_test_packages
        rows.append({"package": package, "step": "package-summary",
                     "status": status if has_tests or explicit_helper else "error",
                     "record_type": "aggregate" if has_tests or explicit_helper else "leaf",
                     "stderr_tail": "" if has_tests or explicit_helper else "package completed without test records"})
    rows.extend(faults)
    return rows or [fault("go test collected no records")]


def parse_cri(report):
    rows = []
    for suite in report if isinstance(report, list) else [report]:
        for index, spec in enumerate(suite.get("SpecReports", [])):
            state = spec.get("State")
            status = {"passed": "pass", "failed": "fail", "panicked": "fail", "timedout": "fail",
                      "skipped": "skip", "pending": "skip"}.get(state, "error")
            name = " / ".join(filter(None, (spec.get("ContainerHierarchyTexts") or []) + [spec.get("LeafNodeText")]))
            node_type = spec.get("LeafNodeType", "")
            hook = node_type in ("BeforeSuite", "AfterSuite", "SynchronizedBeforeSuite", "SynchronizedAfterSuite") or not name
            failures = spec.get("Failures") or ([spec["Failure"]] if spec.get("Failure") else [])
            rows.append({"step": name or f"hook-{node_type or 'unnamed'}-{index}", "status": status,
                         "record_type": "aggregate" if hook else "leaf",
                         "stderr_tail": " | ".join(f.get("Message", "") for f in failures)[-800:]})
    return rows or [fault("CRI JSON report contained no specs")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("go", "critest"))
    for arg in ("input", "output", "suite", "engine", "run", "head", "suite-head"):
        parser.add_argument("--" + arg, required=True)
    parser.add_argument("--skip-pattern")
    args = parser.parse_args()
    try:
        text = Path(args.input).read_text()
        rows = parse_go(text, args.skip_pattern) if args.kind == "go" else parse_cri(json.loads(text))
    except (OSError, ValueError, TypeError, AttributeError) as error:
        rows = [fault(f"cannot parse {args.kind} results: {error}")]
    provenance = {"source": args.suite, "suite": args.suite, "engine": args.engine,
                  "run": args.run, "head": args.head, "suite_head": args.suite_head}
    with open(args.output, "a") as output:
        for row in rows:
            row.update(provenance)
            row.update(exit=1 if row["status"] in ("fail", "error") else 0, ms=0)
            output.write(json.dumps(row, separators=(",", ":")) + "\n")
    return 2 if any(row["status"] == "error" for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
