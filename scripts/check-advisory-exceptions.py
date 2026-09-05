#!/usr/bin/env python3
"""Fail release validation when the existing temporary acceptance expires."""
from datetime import date
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parents[1]
accepted = {"RUSTSEC-2025-0141": date(2026, 9, 30)}
ignored = tomllib.loads((root / ".cargo/audit.toml").read_text())["advisories"]["ignore"]
for advisory in ignored:
    if advisory not in accepted or date.today() >= accepted[advisory]:
        raise SystemExit(f"Unreviewed or expired advisory exception: {advisory}")
print(f"Advisory exceptions valid: {len(ignored)}; owner Platform Runtime Team")
