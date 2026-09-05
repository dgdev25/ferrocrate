#!/usr/bin/env python3
"""Report explicitly selected suite evidence. Never select runs by file age.

Observed passes are not a release claim. --check fails unless every selected
suite qualifies; the selection must enumerate the required release scope.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path

CATEGORIES = ("pass", "product_fail", "shared_fail", "fail_unpaired", "harness_error",
              "unsupported", "skip", "absent", "no_oracle", "aggregate_pass",
              "aggregate_fail", "aggregate_skip", "aggregate_other")


def load_evidence(selection, suite, engine, candidate, suite_head, base):
    result = {"records": [], "provenance_errors": [], "evidence_errors": [], "path": None}
    if not selection:
        result["evidence_errors"].append(f"{engine}: absent result file")
        return result
    path = base / selection["path"]
    result["path"] = str(path.resolve())
    try:
        payload = path.read_bytes()
    except OSError as error:
        result["evidence_errors"].append(f"{engine}: {error}")
        return result
    result["sha256"] = hashlib.sha256(payload).hexdigest()
    if selection.get("sha256") and selection["sha256"] != result["sha256"]:
        result["provenance_errors"].append(f"{engine}: file digest mismatch")
    expected = {"suite": suite, "engine": engine, "run": selection.get("run"),
                "head": selection.get("head"), "suite_head": suite_head}
    if engine == "ferrocrate" and selection.get("head") != candidate:
        result["provenance_errors"].append("ferrocrate: selected head differs from candidate")
    for number, line in enumerate(payload.decode("utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("record must be an object")
        except ValueError as error:
            result["evidence_errors"].append(f"{engine}: line {number}: {error}")
            continue
        for field, value in expected.items():
            if not value or record.get(field) != value:
                message = f"{engine}: missing or mismatched {field}"
                if message not in result["provenance_errors"]:
                    result["provenance_errors"].append(message)
        result["records"].append(record)
    if not result["records"]:
        result["evidence_errors"].append(f"{engine}: no test records")
    return result


def split_records(evidence):
    """Keep Go parents and suite summaries outside leaf totals; reject duplicates."""
    leaves, aggregates = {}, []
    records = evidence["records"]
    keys = {(r.get("package", ""), r.get("step", "")) for r in records}
    for record in records:
        step = record.get("step", "")
        package = record.get("package", "")
        key = (package, step)
        if not isinstance(step, str) or not step.strip():
            evidence["evidence_errors"].append("unnamed test/hook cannot be counted as a passing spec")
            aggregates.append(dict(record, status="error"))
        elif (record.get("record_type") == "aggregate" or
              record.get("record_type") != "leaf" and (
                  step.endswith(("-summary", "-suite")) or
                  any(p == package and child.startswith(step + "/") for p, child in keys))):
            aggregates.append(record)
        elif key in leaves:
            evidence["evidence_errors"].append(f"duplicate test identity: {package}::{step}")
        else:
            leaves[key] = record
    return leaves, aggregates


def summarize(suite, selection, candidate, base):
    suite_head = selection.get("suite_head")
    ferro = load_evidence(selection.get("ferrocrate"), suite, "ferrocrate", candidate, suite_head, base)
    # CRI has a specification oracle, not a Docker implementation oracle.
    contract = suite == "critest"
    docker = (load_evidence(selection.get("docker"), suite, "docker", candidate, suite_head, base)
              if not contract else {"records": [], "provenance_errors": [], "evidence_errors": []})
    f, aggregates = split_records(ferro)
    d, docker_aggregates = split_records(docker)
    provenance = ferro["provenance_errors"] + docker["provenance_errors"]
    errors = ferro["evidence_errors"] + docker["evidence_errors"]
    comparable = not provenance and not errors
    counts = dict.fromkeys(CATEGORIES, 0)
    details = []
    for record in aggregates:
        status = record.get("status")
        category = "aggregate_" + (status if status in ("pass", "fail", "skip") else "other")
        counts[category] += 1
    for key, record in f.items():
        status = record.get("status")
        oracle = d.get(key) if comparable else None
        if not contract and (oracle is None or oracle.get("status") != "pass"):
            counts["no_oracle"] += 1
        if status == "pass":
            category = "pass"
        elif status == "skip":
            category = "skip"
        elif status == "unsupported" and record.get("reason") and record.get("scope_ref"):
            category = "unsupported"
        elif status == "fail":
            if contract or oracle and oracle.get("status") == "pass":
                category = "product_fail"
            elif oracle and oracle.get("status") == "fail":
                category = "shared_fail"
            else:
                category = "fail_unpaired"
        else:
            category = "harness_error"
        counts[category] += 1
        details.append({"package": key[0], "step": key[1], "category": category,
                        "status": status, "stderr_tail": record.get("stderr_tail", "")})
    # Every observed Docker leaf absent on Ferro is coverage, even if Docker skipped it.
    missing = set(d) - set(f)
    for step in selection.get("expected_steps", []):
        key = ("", step) if isinstance(step, str) else (step.get("package", ""), step["step"])
        if key not in f:
            missing.add(key)
    counts["absent"] = len(missing)
    for package, step in sorted(missing):
        details.append({"package": package, "step": step, "category": "absent"})
    bad = ("product_fail", "shared_fail", "fail_unpaired", "harness_error", "skip", "absent",
           "no_oracle", "aggregate_fail", "aggregate_skip", "aggregate_other")
    qualified = counts["pass"] > 0 and not provenance and not errors and not any(counts[k] for k in bad)
    return {"counts": counts, "ferro_leaf_total": len(f), "docker_leaf_total": len(d),
            "ferro_raw_status": dict(collections.Counter(r.get("status", "invalid") for r in ferro["records"])),
            "docker_aggregate_total": len(docker_aggregates),
            "oracle": "not-applicable" if contract else "paired" if comparable and d else "unavailable",
            "qualified": qualified, "provenance_errors": provenance, "evidence_errors": errors,
            "evidence": {"ferrocrate": {k: v for k, v in ferro.items() if k != "records"},
                         "docker": {k: v for k, v in docker.items() if k != "records"}},
            "details": details}


def build_report(selection, base):
    candidate = selection.get("candidate_head")
    if not isinstance(candidate, str) or not candidate.strip():
        raise ValueError("selection requires candidate_head")
    suites = selection.get("suites")
    if not isinstance(suites, dict) or not suites:
        raise ValueError("selection requires a nonempty suites mapping of required scope")
    rows = {name: summarize(name, entry, candidate, base) for name, entry in sorted(suites.items())}
    return {"candidate_head": candidate, "suites": rows,
            "qualified": all(row["qualified"] for row in rows.values())}


def markdown(report):
    lines = ["# Selected suite evidence", "", f"Candidate: `{report['candidate_head']}`", "",
             "Pass means an observed leaf pass, not full release qualification. Shared failures remain untriaged;",
             "they are not automatically harness faults. Unsupported requires an explicit reason and scope reference.",
             "No-oracle overlaps observed statuses. Aggregate rows are excluded from leaf counts.", "",
             "| Suite | F leaves | D leaves | Pass | Product fail | Shared fail | Unpaired fail | Harness | Unsupported | Skip | Absent | No oracle | Qualified |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|"]
    for suite, row in report["suites"].items():
        c = row["counts"]
        values = [suite, row["ferro_leaf_total"], row["docker_leaf_total"]]
        values += [c[k] for k in CATEGORIES[:9]]
        values += ["yes" if row["qualified"] else "no"]
        lines.append("| " + " | ".join(map(str, values)) + " |")
    for suite, row in report["suites"].items():
        lines.extend(["", f"## {suite}", "", f"Oracle: {row['oracle']}. Raw Ferro statuses: `{json.dumps(row['ferro_raw_status'], sort_keys=True)}`.",
                      f"Aggregate statuses: pass={row['counts']['aggregate_pass']}, fail={row['counts']['aggregate_fail']}, skip={row['counts']['aggregate_skip']}, other={row['counts']['aggregate_other']}."])
        for engine, evidence in row["evidence"].items():
            if evidence.get("path"):
                lines.append(f"- {engine}: `{evidence['path']}`; SHA-256 `{evidence.get('sha256', 'unavailable')}`")
        lines += [f"- {error}" for error in row["provenance_errors"] + row["evidence_errors"]]
    lines += ["", "Selection qualified: " + ("yes" if report["qualified"] else "no"),
              "Only the explicitly selected suite scope is assessed. This report does not qualify other release gates."]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", required=True, type=Path, help="explicit candidate/suite/run selection JSON")
    parser.add_argument("--json", action="store_true", help="include machine-readable per-case classifications")
    parser.add_argument("--check", action="store_true", help="exit 1 when selected scope does not qualify")
    args = parser.parse_args()
    try:
        report = build_report(json.loads(args.selection.read_text()), args.selection.resolve().parent)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else markdown(report))
    return 1 if args.check and not report["qualified"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
