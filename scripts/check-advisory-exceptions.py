#!/usr/bin/env python3
"""Validate dated exceptions and audit the standalone Tauri lock without hiding findings."""
import argparse
from datetime import date
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TAURI_LOCK = 'apps/ferro-desktop-ui/src-tauri/Cargo.lock'
ROOT_ACCEPTED = {'RUSTSEC-2025-0141': date(2026, 9, 30)}


def package_key(package):
    return f"{package['name']}@{package['version']}"


def dependency_graph(packages):
    graph = {}
    for package in packages:
        edges = set()
        for dependency in package.get('dependencies', []):
            fields = dependency.split()
            for candidate in packages:
                if candidate['name'] == fields[0] and (len(fields) == 1 or candidate['version'] == fields[1]):
                    edges.add(package_key(candidate))
        graph[package_key(package)] = edges
    return graph


def validate_policy(root=ROOT, today=None):
    today = today or date.today()
    config = tomllib.loads((root / '.cargo/audit.toml').read_text())
    ignored = config.get('advisories', {}).get('ignore', [])
    if config != {'advisories': {'ignore': ignored}} or len(ignored) != len(set(ignored)):
        raise ValueError('Root audit policy must not filter targets, severity, or warning classes')
    for advisory in ignored:
        if advisory not in ROOT_ACCEPTED or today >= ROOT_ACCEPTED[advisory]:
            raise ValueError(f'Unreviewed or expired root advisory exception: {advisory}')

    desktop = tomllib.loads((root / '.cargo/audit-tauri.toml').read_text())
    if desktop.get('lockfile') != TAURI_LOCK or desktop.get('schema') != 1:
        raise ValueError('Desktop exceptions must bind the standalone Tauri lockfile')
    packages = tomllib.loads((root / TAURI_LOCK).read_text())['package']
    graph = dependency_graph(packages)
    by_key = {package_key(package): package for package in packages}
    accepted = {}
    for entry in desktop['exceptions']:
        advisory = entry['id']
        if not re.fullmatch(r'RUSTSEC-\d{4}-\d{4}', advisory) or advisory in accepted:
            raise ValueError(f'Invalid or duplicate desktop advisory: {advisory}')
        if entry['kind'] not in {'unmaintained', 'unsound'}:
            raise ValueError(f'Cannot accept vulnerability or other warning class: {advisory}')
        reviewed, expires = entry['reviewed'], entry['expires']
        if not isinstance(reviewed, date) or not isinstance(expires, date) or not (reviewed <= today < expires) or (expires - reviewed).days > 30:
            raise ValueError(f'Unreviewed or expired desktop advisory exception: {advisory}')
        for field in ['owner', 'reason', 'action']:
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                raise ValueError(f'Missing {field} for desktop advisory: {advisory}')
        key = package_key(entry)
        package = by_key.get(key)
        if package is None or package.get('checksum') != entry['checksum'] or package.get('source') != 'registry+https://github.com/rust-lang/crates.io-index':
            raise ValueError(f'Desktop exception package changed or disappeared: {advisory} {key}')
        path = entry['dependency_path']
        if not path or path[0] != 'ferro-desktop-ui@0.1.0' or path[-1] != key or any(b not in graph.get(a, set()) for a, b in zip(path, path[1:])):
            raise ValueError(f'Desktop dependency path changed: {advisory}')
        accepted[advisory] = entry
    return ignored, accepted, len(packages)


def validate_report(report, ignored, accepted, package_count):
    settings = report['settings']
    if (set(settings['ignore']) != set(ignored) or settings['target_arch'] or settings['target_os']
            or settings['severity'] is not None
            or set(settings['informational_warnings']) != {'unmaintained', 'unsound', 'notice'}):
        raise ValueError('Audit report suppressed advisories or warning classes outside root policy')
    if report['lockfile']['dependency-count'] != package_count:
        raise ValueError('Audit report does not cover the complete standalone Tauri lock')
    vulnerabilities = report['vulnerabilities']
    if vulnerabilities['found'] or vulnerabilities['count'] or vulnerabilities['list']:
        raise ValueError('Standalone Tauri lock contains vulnerability findings; exceptions do not apply')
    count = 0
    for kind, warnings in report['warnings'].items():
        for warning in warnings:
            advisory = (warning.get('advisory') or {}).get('id', '<no advisory ID>')
            entry = accepted.get(advisory)
            package = warning['package']
            if (entry is None or kind != entry['kind'] or warning['kind'] != kind
                    or warning['advisory'].get('informational') != kind
                    or package_key(package) != package_key(entry)
                    or package.get('checksum') != entry['checksum']):
                raise ValueError(f'Unaccepted standalone Tauri warning: {kind} {advisory} {package_key(package)}')
            count += 1
    return count


def audit_tauri(cargo, root, ignored, accepted, package_count):
    lock_path = root / TAURI_LOCK
    before = lock_path.read_bytes()
    # Keep all findings visible: no desktop --ignore switches or category
    # suppression. A nonzero warning result is accepted only after exact
    # advisory/package/checksum/classification checks below.
    result = subprocess.run(
        [cargo, 'audit', '--deny', 'warnings', '--file', TAURI_LOCK, '--json'],
        cwd=root, text=True, capture_output=True, timeout=300,
    )
    if result.returncode not in (0, 1):
        raise ValueError(f'cargo audit failed ({result.returncode}): {result.stderr.strip()}')
    if before != lock_path.read_bytes():
        raise ValueError('Standalone Tauri lock changed during the audit')
    count = validate_report(json.loads(result.stdout), ignored, accepted, package_count)
    if result.returncode != (1 if count else 0):
        raise ValueError('cargo audit status does not match the validated warning report')
    print(f'Standalone Tauri audit passed: {package_count} packages; {count} dated exceptions; all other findings denied')
    for advisory in sorted(accepted):
        entry = accepted[advisory]
        print(f"  {advisory} {package_key(entry)} ({entry['kind']}), expires {entry['expires']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit-tauri', action='store_true')
    parser.add_argument('--cargo', default='cargo')
    args = parser.parse_args()
    try:
        ignored, accepted, package_count = validate_policy()
        if args.audit_tauri:
            audit_tauri(args.cargo, ROOT, ignored, accepted, package_count)
        else:
            print(f'Advisory exceptions valid: {len(ignored)} root, {len(accepted)} standalone Tauri')
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f'Dependency policy failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
