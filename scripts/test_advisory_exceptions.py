#!/usr/bin/env python3
"""Regression coverage for the standalone desktop dependency policy."""
from pathlib import Path
from datetime import date
import copy
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
import yaml
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


SPEC = importlib.util.spec_from_file_location('advisory_policy', ROOT / 'scripts/check-advisory-exceptions.py')
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.ignored, self.accepted, self.count = POLICY.validate_policy(today=date(2026, 9, 8))
        self.entry = next(iter(self.accepted.values()))
        self.warning = {
            'kind': self.entry['kind'],
            'advisory': {'id': self.entry['id'], 'informational': self.entry['kind']},
            'package': {key: self.entry[key] for key in ['name', 'version', 'checksum']},
        }
        self.report = {
            'settings': {'ignore': self.ignored, 'target_arch': [], 'target_os': [], 'severity': None,
                         'informational_warnings': ['unmaintained', 'unsound', 'notice']},
            'lockfile': {'dependency-count': self.count},
            'vulnerabilities': {'found': False, 'count': 0, 'list': []},
            'warnings': {self.entry['kind']: [self.warning]},
        }

    def validate(self, report=None):
        return POLICY.validate_report(report or self.report, self.ignored, self.accepted, self.count)

    def test_exact_reviewed_warning_is_accepted(self):
        self.assertEqual(self.validate(), 1)

    def test_new_advisory_is_denied(self):
        self.warning['advisory']['id'] = 'RUSTSEC-2099-0001'
        with self.assertRaisesRegex(ValueError, 'Unaccepted'):
            self.validate()

    def test_changed_version_or_checksum_is_denied(self):
        for key in ['version', 'checksum']:
            report = copy.deepcopy(self.report)
            report['warnings'][self.entry['kind']][0]['package'][key] = 'changed'
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'Unaccepted'):
                self.validate(report)

    def test_reclassified_warning_is_denied(self):
        self.warning['advisory']['informational'] = 'unsound'
        with self.assertRaisesRegex(ValueError, 'Unaccepted'):
            self.validate()

    def test_vulnerabilities_are_never_accepted(self):
        self.report['vulnerabilities'] = {'found': True, 'count': 1, 'list': [self.warning]}
        with self.assertRaisesRegex(ValueError, 'vulnerability findings'):
            self.validate()

    def test_yanked_warning_is_denied(self):
        self.report['warnings'] = {'yanked': [{'kind': 'yanked', 'package': self.warning['package']}]}
        with self.assertRaisesRegex(ValueError, 'Unaccepted'):
            self.validate()

    def test_hidden_warnings_or_wrong_lock_are_denied(self):
        for key, value in [('ignore', self.ignored + [self.entry['id']]), ('target_os', ['linux']),
                           ('severity', 'high'), ('informational_warnings', ['unmaintained'])]:
            report = copy.deepcopy(self.report)
            report['settings'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'suppressed'):
                self.validate(report)
        self.report['lockfile']['dependency-count'] -= 1
        with self.assertRaisesRegex(ValueError, 'complete standalone'):
            self.validate()

    def test_expiry_fails_on_the_review_deadline(self):
        with self.assertRaisesRegex(ValueError, 'expired'):
            POLICY.validate_policy(today=date(2026, 9, 30))

    def policy_fixture(self, temp):
        root = Path(temp)
        for relative in ['.cargo/audit.toml', '.cargo/audit-tauri.toml', POLICY.TAURI_LOCK]:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        return root

    def test_changed_dependency_path_and_root_ignore_fail(self):
        for file, old, new in [('.cargo/audit-tauri.toml', 'tauri@2.11.5', 'tauri@0.0.0'),
                                ('.cargo/audit.toml', 'RUSTSEC-2025-0141', 'RUSTSEC-2099-0001')]:
            with tempfile.TemporaryDirectory() as temp:
                root = self.policy_fixture(temp)
                path = root / file
                path.write_text(path.read_text().replace(old, new))
                with self.subTest(file=file), self.assertRaises(ValueError):
                    POLICY.validate_policy(root, date(2026, 9, 8))

    def test_desktop_expiry_is_enforced_independently_of_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.policy_fixture(temp)
            path = root / '.cargo/audit-tauri.toml'
            path.write_text(path.read_text().replace('expires = 2026-09-30', 'expires = 2026-09-08'))
            with self.assertRaisesRegex(ValueError, 'expired desktop'):
                POLICY.validate_policy(root, date(2026, 9, 8))

    def test_audit_runs_exact_lock_and_deny_warnings_without_desktop_ignores(self):
        result = subprocess.CompletedProcess([], 1, json.dumps(self.report), '')
        with patch.object(POLICY.subprocess, 'run', return_value=result) as run, patch('builtins.print'):
            POLICY.audit_tauri('/chosen/cargo', ROOT, self.ignored, self.accepted, self.count)
        self.assertEqual(run.call_args.args[0], ['/chosen/cargo', 'audit', '--deny', 'warnings', '--file', POLICY.TAURI_LOCK, '--json'])
        self.assertEqual(run.call_args.kwargs['cwd'], ROOT)

    def test_tool_failure_and_inconsistent_exit_status_fail_closed(self):
        for code, output in [(2, ''), (1, '{}'), (0, json.dumps(self.report)), (1, 'not json')]:
            result = subprocess.CompletedProcess([], code, output, 'audit failed')
            with patch.object(POLICY.subprocess, 'run', return_value=result), self.subTest(code=code, output=output), self.assertRaises((ValueError, KeyError)):
                POLICY.audit_tauri('cargo', ROOT, self.ignored, self.accepted, self.count)


class AuditGateTests(unittest.TestCase):
    def test_ci_and_local_gate_audit_standalone_tauri_lock(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
        steps = workflow['jobs']['build-unit-warnings']['steps']
        policy = next(step for step in steps if step.get('name') == 'Dependency policy')
        self.assertEqual(policy.get('if'), "runner.os == 'Linux'")
        self.assertFalse(policy.get('continue-on-error', False))
        commands = [line.strip() for line in policy['run'].splitlines()]
        self.assertIn('cargo audit --deny warnings', commands)
        self.assertIn('python3 scripts/check-advisory-exceptions.py --audit-tauri', commands)
        local = (ROOT / 'scripts/local-release-gate.sh').read_text()
        self.assertIn('"$cargo_bin" audit --deny warnings\npython3 scripts/test_advisory_exceptions.py\npython3 scripts/check-advisory-exceptions.py --audit-tauri --cargo "$cargo_bin"\n', local)


if __name__ == '__main__':
    unittest.main()
