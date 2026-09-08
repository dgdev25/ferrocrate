#!/usr/bin/env python3
"""Validate immutable same-candidate evidence for the entire advertised release scope."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

REQUIRED_CHECKS = (
    "rootless-compose", "storage-crash-recovery", "migration-rollback", "capacity-100-containers",
    "oom-cpu-pids-isolation", "network-iptables-recovery", "network-nftables-recovery",
    "compatibility-suites", "cri-contract", "oci-runtime", "dependency-policy",
    "desktop-linux-lifecycle", "desktop-macos-x86_64-lifecycle", "desktop-macos-aarch64-lifecycle",
    "desktop-windows-lifecycle", "final-artifact-signatures", "desktop-workspace-journeys",
    "desktop-accessibility", "release-artifact-provenance",
)


def validate(manifest, candidate, host_rows, base):
    errors = []
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        return ["candidate evidence requires schema_version 1"]
    if manifest.get("source_commit") != candidate or not re.fullmatch(r"[0-9a-f]{40}", candidate):
        errors.append("evidence source_commit does not match the exact candidate SHA")
    if manifest.get("source_dirty") is not False:
        errors.append("release evidence must identify a clean source tree")
    checks = manifest.get("checks", {})
    if not isinstance(checks, dict):
        return errors + ["checks must be an object"]
    for name in (*REQUIRED_CHECKS, *("host:" + row for row in host_rows)):
        record = checks.get(name)
        if not isinstance(record, dict):
            errors.append(f"{name}: required candidate evidence is absent")
            continue
        if record.get("status") != "pass" or type(record.get("exit_code")) is not int or record["exit_code"] != 0:
            errors.append(f"{name}: required check did not pass with exit code zero")
        if record.get("source_commit") != candidate or record.get("source_dirty") is not False:
            errors.append(f"{name}: historical, mismatched or dirty source evidence")
        for field in ("command", "host", "toolchain"):
            if not isinstance(record.get(field), str) or not record[field].strip():
                errors.append(f"{name}: missing {field}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("binary_sha256", ""))):
            errors.append(f"{name}: missing binary SHA-256 identity")
        files = record.get("files")
        if not isinstance(files, list) or not files:
            errors.append(f"{name}: no retained evidence files")
            continue
        for artifact in files:
            try:
                relative = Path(artifact["path"])
                path = (base / relative).resolve()
                if relative.is_absolute() or not path.is_relative_to(base.resolve()):
                    raise ValueError("evidence path must remain inside the bundle")
                if not path.is_file() or path.stat().st_size == 0:
                    raise ValueError("evidence file is absent or empty")
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != artifact.get("sha256"):
                    raise ValueError("evidence file SHA-256 mismatch")
            except (OSError, ValueError, TypeError, KeyError) as error:
                errors.append(f"{name}: {error}")
    return errors


def unique_object(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"duplicate evidence key: {key}")
        output[key] = value
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        head = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", "HEAD"], text=True).strip()
        if args.candidate != head:
            raise ValueError("requested candidate differs from checked-out HEAD")
        if subprocess.check_output(["git", "-C", str(args.repo), "status", "--porcelain"], text=True).strip():
            raise ValueError("checked-out source is dirty; final release evidence cannot qualify it")
        matrix = args.repo / "docs/evidence/host-matrix/rows.tsv"
        rows = [line.split("|", 1)[0] for line in matrix.read_text().splitlines() if line.strip() and not line.startswith("#")]
        if not rows:
            raise ValueError("advertised host matrix is empty")
        manifest = json.loads(args.manifest.read_text(), object_pairs_hook=unique_object)
        errors = validate(manifest, args.candidate, rows, args.manifest.resolve().parent)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    if errors:
        print("Candidate release evidence is incomplete:")
        print("\n".join("- " + error for error in errors))
        return 1
    print(f"Candidate evidence verified: {args.candidate}; {len(rows)} hosts and {len(REQUIRED_CHECKS)} required checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
