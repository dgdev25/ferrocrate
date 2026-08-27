#!/usr/bin/env python3
"""Compare each borrowed suite's Ferrocrate run against its Docker run.

Reports four categories, never three. A test Docker ran that Ferrocrate did not
is missing coverage, not a pass: BuildKit alone runs 2562 cases against several
workers while Ferrocrate provides one, so a naive pass count reads as 99%
success over 15% of the suite."""
import json, glob, os, sys, collections

ROOTS = sys.argv[1:] or ["."]

def load(path):
    out = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                record = json.loads(line)
                out[record["step"]] = record["status"]
    return out

def newest():
    """newest file per (suite, engine) across every clone given"""
    best = {}
    for root in ROOTS:
        for path in glob.glob(os.path.join(root, "bench/results/*/suite-*.jsonl")):
            name = os.path.basename(path)[len("suite-"):-len(".jsonl")]
            suite, _, engine = name.rpartition("-")
            key = (suite, engine)
            if key not in best or os.path.getmtime(path) > os.path.getmtime(best[key]):
                best[key] = path
    return best

def main():
    best = newest()
    suites = sorted({s for s, _ in best})
    rows, totals = [], collections.Counter()
    for suite in suites:
        fpath, dpath = best.get((suite, "ferrocrate")), best.get((suite, "docker"))
        if not fpath:
            rows.append(f"| {suite} | — | — | — | — | no Ferrocrate run |")
            continue
        f = load(fpath)
        d = load(dpath) if dpath else {}
        product = sum(1 for k, v in f.items() if v == "fail" and d.get(k) == "pass")
        both = sum(1 for k, v in f.items() if v == "fail" and d.get(k) == "fail")
        notrun = sum(1 for k, v in d.items() if v == "pass" and k not in f)
        passed = sum(1 for v in f.values() if v == "pass")
        totals["product"] += product; totals["notrun"] += notrun; totals["pass"] += passed
        note = "" if not notrun else f"{notrun} Docker cases absent from the Ferrocrate run"
        rows.append(f"| {suite} | {len(f)} | {len(d) or '—'} | {passed} | {product} | {both} | {notrun} | {note} |")
    print("| Suite | Ferro tests | Docker tests | Ferro pass | Product fail | Fail on both | Not run | Note |")
    print("|---|---:|---:|---:|---:|---:|---:|---|")
    for row in rows:
        print(row)
    print(f"\nProduct failures across suites: {totals['product']}")
    print(f"Docker cases never run on Ferrocrate: {totals['notrun']} (missing coverage, not passes)")

if __name__ == "__main__":
    main()
