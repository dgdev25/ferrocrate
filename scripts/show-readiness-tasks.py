#!/usr/bin/env python3
"""Print the active roadmap; checkboxes remain the completion source of truth."""
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
roadmap = root / "docs/PRODUCTION-READINESS-ROADMAP-2026-09-05.md"
state = json.loads((root / "docs/internal/evidence-raw/closeout-2026-09-05/tasks.json").read_text())
tasks = re.findall(r"^- \[([ x])\] (R\d+) — (.*)$", roadmap.read_text(), re.M)
done = sum(checked == "x" for checked, _, _ in tasks)
print(f"FerroCrate production readiness | {done}/{len(tasks)} complete")
for checked, key, description in tasks:
    status = "done" if checked == "x" else state.get(key, "todo")
    glyph = {"done": "☑", "todo": "☐", "in_progress": "■", "blocked": "✖"}[status]
    print(f"{glyph} {key} {description.split('Acceptance:')[0].strip()}")
