#!/usr/bin/env bash
set -euo pipefail

register="${1:-docs/evidence/performance/benchmark-register.md}"
if [[ ! -f "$register" ]]; then
  echo "benchmark register not found: $register" >&2
  exit 2
fi

python3 - "$register" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
start = text.find("## Current comparison snapshot")
end = text.find("## Update protocol", start)
if start < 0 or end < 0:
    raise SystemExit("benchmark register gate failed: missing current snapshot section")
section = text[start:end]
rows = []
for line in section.splitlines():
    if not line.startswith("|") or line.startswith("|---") or line.startswith("| Feature"):
        continue
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    if len(cells) != 10:
        raise SystemExit(f"benchmark register gate failed: malformed snapshot row: {line}")
    rows.append(cells)

if len(rows) != 10:
    raise SystemExit(f"benchmark register gate failed: expected 10 snapshot rows, found {len(rows)}")
for row in rows:
    feature = row[0]
    if not feature:
        raise SystemExit("benchmark register gate failed: empty feature name")
    for idx in (4, 8):
        if not re.fullmatch(r"[+-]?\d+(?:\.\d+)?%", row[idx]):
            raise SystemExit(f"benchmark register gate failed: {feature} lacks percentage delta")
    links = re.findall(r"\(([^)]+\.md)\)", row[9])
    if not links:
        raise SystemExit(f"benchmark register gate failed: {feature} has no report link")
    for link in links:
        target = (path.parent / link).resolve()
        if not target.is_file():
            raise SystemExit(f"benchmark register gate failed: missing report {link}")

ids = re.findall(r"^\| (B-\d{3}) \|", text, flags=re.MULTILINE)
if not ids or len(ids) != len(set(ids)):
    raise SystemExit("benchmark register gate failed: benchmark IDs are missing or duplicated")

print(f"benchmark register gate passed: {len(rows)} snapshot rows, {len(ids)} unique benchmark IDs, linked reports present")
PY
