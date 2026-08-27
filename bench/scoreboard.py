#!/usr/bin/env python3
"""Build bench/results/SCOREBOARD.md from the newest result set per app and engine.

Parity rule: a Ferrocrate step counts as a product failure only when the same
step passed on Docker in the same run set. Steps failing on both engines are
app or env failures; steps listed in the manifest skip are boundaries."""
import json, glob, os, collections, datetime

BENCH = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(BENCH, "results")
GROUPS = [("engine", ["version", "info", "doctor"]),
          ("image", ["pull-base", "build", "images", "image-inspect", "history", "tag", "save", "rmi-tag", "load"]),
          ("lifecycle", ["run-detached", "health", "ps", "logs", "inspect", "top", "stats", "exec", "cp-out", "cp-in", "diff", "pause", "unpause", "restart", "stop", "start", "rename", "commit", "export", "kill", "wait", "rm", "rmi-committed"]),
          ("data", ["data-write", "data-read", "volume-ls", "volume-inspect", "volume-rm"]),
          ("network", ["network-ls", "network-create", "network-run", "network-rm"]),
          ("compose", ["compose-up", "compose-health", "compose-ps", "compose-logs", "compose-down"]),
          ("errors", ["err-bad-image", "err-no-container", "err-port-in-use"]),
          ("extras", ["events", "system-df", "container-prune", "image-prune", "search"])]
GROUP_OF = {s: g for g, steps in GROUPS for s in steps}

def latest():
    """newest jsonl per (app, engine)"""
    files = {}
    for f in sorted(glob.glob(os.path.join(RES, "*", "*.jsonl"))):
        name = os.path.basename(f)[:-6]
        # Result files are named <app>-<engine>. The fuzzer and any other
        # producer that writes here uses its own shape and has no engine pair,
        # so it is not a scoreboard row.
        app, _, engine = name.rpartition("-")
        if engine not in ("ferrocrate", "docker"):
            continue
        # Borrowed suites write into the same directory but are not applications.
        # Counting them here mixed 108 CLI e2e cases into the app totals.
        if app.startswith("suite-"):
            continue
        files[(app, engine)] = f
    return files

def load(f):
    out = {}
    with open(f) as fh:
        for line in fh:
            line = line.strip()
            if line:
                r = json.loads(line); out[r["step"]] = r
    return out

def classify(step, ferro, docker):
    if ferro["status"] == "skip": return "boundary"
    if ferro["status"] == "pass": return "pass"
    if docker is None: return "unpaired"
    if docker["status"] == "pass": return "product"
    return "app-or-env"

def main():
    files = latest(); apps = sorted({a for a, _ in files})
    rows, per_group, tickets = [], collections.Counter(), []
    for app in apps:
        ferro = load(files[(app, "ferrocrate")]) if (app, "ferrocrate") in files else {}
        dock = load(files[(app, "docker")]) if (app, "docker") in files else {}
        counts = collections.Counter()
        for step, r in ferro.items():
            c = classify(step, r, dock.get(step)); counts[c] += 1
            per_group[(GROUP_OF.get(step, "other"), c)] += 1
            if c == "product":
                tickets.append((app, step, r["exit"], r["stderr_tail"][:160]))
        total = sum(counts.values())
        run = next(iter(ferro.values()))["run"] if ferro else "-"
        dpass = sum(1 for r in dock.values() if r["status"] == "pass")
        fcol = f"{counts['pass']}/{total}" if ferro else "no run"
        rows.append(f"| {app} | {run} | {fcol} | {dpass}/{len(dock) or '-'} | {counts['product']} | {counts['app-or-env']} | {counts['boundary']} | {counts['unpaired']} |")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    md = [f"# Real-app bench scoreboard", "", f"Generated {now} from the newest result file per app and engine.",
          "Product = fails on Ferrocrate, passes on Docker. App/env = fails on both. Boundary = manifest skip.", "",
          "| App | Run | Ferrocrate pass | Docker pass | Product | App/env | Boundary | Unpaired |", "|---|---|---:|---:|---:|---:|---:|---:|", *rows, "",
          "## By group (Ferrocrate)", "", "| Group | Pass | Product | App/env | Boundary |", "|---|---:|---:|---:|---:|"]
    for g, _ in GROUPS + [("other", [])]:
        md.append(f"| {g} | {per_group[(g,'pass')]} | {per_group[(g,'product')]} | {per_group[(g,'app-or-env')]} | {per_group[(g,'boundary')]} |")
    md += ["", "## Open product failures (ticket candidates)", "", "| App | Step | Exit | Ferrocrate stderr (tail) |", "|---|---|---:|---|"]
    md += [f"| {a} | {s} | {e} | `{t.replace('|','/')}` |" for a, s, e, t in tickets] or ["| — | — | — | none |"]
    with open(os.path.join(RES, "SCOREBOARD.md"), "w") as fh: fh.write("\n".join(md) + "\n")
    print(f"scoreboard: {len(apps)} apps, {len(tickets)} product failures -> {os.path.join(RES, 'SCOREBOARD.md')}")

if __name__ == "__main__":
    main()
