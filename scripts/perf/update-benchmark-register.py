#!/usr/bin/env python3
"""Refresh the Docker comparison snapshot from two dated reports.

The command is deliberately explicit: without --apply it prints the proposed
table and never mutates the register. With --apply it replaces only the
``Current comparison snapshot`` table using an atomic same-directory rename.
Historical reports are never edited.
"""

from __future__ import annotations

import argparse
import os
import re
import tempfile
from pathlib import Path

FEATURES = [
    "Image pull (warm)",
    "Container run/exit",
    "Dockerfile build",
    "Image list",
    "Network create/remove",
    "Volume create/remove",
    "Network list",
    "API ping",
    "API version",
    "API info",
]


def parse_report(path: Path) -> dict[str, tuple[str, str]]:
    rows: dict[str, tuple[str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or line.startswith("|---") or line.startswith("| Feature"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 5:
            continue
        feature, docker, ferro = cells[:3]
        canonical = next((name for name in FEATURES if name.casefold() == feature.casefold()), None)
        if canonical is not None:
            if not re.fullmatch(r"\d+", docker) or not re.fullmatch(r"\d+", ferro):
                raise SystemExit(f"{path}: non-numeric median for {feature}")
            if canonical in rows:
                raise SystemExit(f"{path}: duplicate feature {canonical}")
            rows[canonical] = (docker, ferro)
    if set(rows) != set(FEATURES):
        missing = ", ".join(feature for feature in FEATURES if feature not in rows)
        raise SystemExit(f"{path}: missing benchmark rows: {missing}")
    return rows


def relative_report(register: Path, report: Path) -> str:
    return os.path.relpath(report, register.parent).replace(os.sep, "/")


def report_head(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"- Ferrocrate commit: `?([^`\s]+)`?\s*$", line)
        if match:
            return match.group(1)
    raise SystemExit(f"{path}: missing Ferrocrate commit metadata")


def update_register_metadata(
    text: str, head: str, ip_link: str, nft_link: str
) -> str:
    text, replacements = re.subn(
        r"(The latest paired refresh was completed at head `)[^`]+(`)",
        rf"\g<1>{head}\g<2>",
        text,
        count=1,
    )
    if replacements != 1:
        raise SystemExit("register is missing latest paired refresh metadata")
    text, replacements = re.subn(
        r"(Latest benchmark-relevant implementation head: `)[^`]+(`)",
        rf"\g<1>{head}\g<2>",
        text,
        count=1,
    )
    if replacements != 1:
        raise SystemExit("register is missing latest implementation metadata")
    text, replacements = re.subn(
        r"(milliseconds from commit `)[^`]+(` on the current Ubuntu host)",
        rf"\g<1>{head}\g<2>",
        text,
        count=1,
    )
    if replacements != 1:
        raise SystemExit("register is missing snapshot commit metadata")

    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if not re.match(r"\| B-00(?:[1-9]|10) \|", line):
            continue
        lines[index] = re.sub(
            r"\]\([^)]*-docker-comparison-current-head-[^)]+-iptables\.md\)",
            f"]({ip_link})",
            line,
        )
        lines[index] = re.sub(
            r"\]\([^)]*-docker-comparison-current-head-[^)]+-nftables\.md\)",
            f"]({nft_link})",
            lines[index],
        )
    return "".join(lines)


def snapshot(iptables: dict[str, tuple[str, str]], nftables: dict[str, tuple[str, str]], ip_link: str, nft_link: str) -> str:
    lines = [
        "| Feature | Docker (iptables) | Ferrocrate (iptables) | Delta | Relative | Docker (nftables) | Ferrocrate (nftables) | Delta | Relative | Detailed reports |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for feature in FEATURES:
        docker_i, ferro_i = map(int, iptables[feature])
        docker_n, ferro_n = map(int, nftables[feature])
        delta_i = ferro_i - docker_i
        delta_n = ferro_n - docker_n
        rel_i = "n/a" if docker_i == 0 else f"{delta_i * 100 / docker_i:+.1f}%"
        rel_n = "n/a" if docker_n == 0 else f"{delta_n * 100 / docker_n:+.1f}%"
        lines.append(
            f"| {feature} | {docker_i} | {ferro_i} | {delta_i:+d} | {rel_i} | "
            f"{docker_n} | {ferro_n} | {delta_n:+d} | {rel_n} | "
            f"[iptables]({ip_link}); [nftables]({nft_link}) |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("iptables_report", type=Path)
    parser.add_argument("nftables_report", type=Path)
    parser.add_argument("--register", type=Path, default=Path("docs/evidence/performance/benchmark-register.md"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    iptables = parse_report(args.iptables_report)
    nftables = parse_report(args.nftables_report)
    ip_head = report_head(args.iptables_report)
    nft_head = report_head(args.nftables_report)
    if ip_head != nft_head:
        raise SystemExit(
            f"paired reports have different Ferrocrate commits: {ip_head} vs {nft_head}"
        )
    ip_link = relative_report(args.register, args.iptables_report)
    nft_link = relative_report(args.register, args.nftables_report)
    table = snapshot(iptables, nftables, ip_link, nft_link)

    text = args.register.read_text(encoding="utf-8")
    start = text.find("## Current comparison snapshot")
    end = text.find("## Update protocol", start)
    if start < 0 or end < 0:
        raise SystemExit("register is missing Current comparison snapshot or Update protocol")
    section = text[start:end]
    table_start = section.find("| Feature |")
    if table_start < 0:
        raise SystemExit("register snapshot table header not found")
    replacement = section[:table_start].rstrip() + "\n\n" + table + "\n\n"
    updated = text[:start] + replacement + text[start + end - start :]
    updated = update_register_metadata(updated, ip_head, ip_link, nft_link)
    if not args.apply:
        print(table)
        return 0

    args.register.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=args.register.parent, delete=False) as handle:
        handle.write(updated)
        temporary = Path(handle.name)
    os.replace(temporary, args.register)
    print(f"updated benchmark register: {args.register}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
