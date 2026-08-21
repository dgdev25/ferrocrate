#!/usr/bin/env bash
set -euo pipefail

artifact_dir=""
output=""
usage() {
  cat <<'USAGE' >&2
Usage: generate-release-index.sh --artifact-dir PATH [--output PATH]

Validates every archive-bound provenance manifest in PATH and writes a
deterministic ferrocrate-release-index-v1 JSON document suitable for an
external package/release repository.
USAGE
}

while (($#)); do
  case "$1" in
    --artifact-dir) [[ $# -ge 2 ]] || { usage; exit 2; }; artifact_dir="$2"; shift 2 ;;
    --output) [[ $# -ge 2 ]] || { usage; exit 2; }; output="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "$artifact_dir" ]] || { echo "--artifact-dir is required" >&2; exit 2; }
[[ -d "$artifact_dir" ]] || { echo "artifact directory does not exist: $artifact_dir" >&2; exit 1; }
[[ -n "$output" ]] || output="$artifact_dir/index.json"
command -v python3 >/dev/null 2>&1 || { echo "generate-release-index.sh requires python3" >&2; exit 1; }

RELEASE_INDEX_DIR="$artifact_dir" RELEASE_INDEX_OUTPUT="$output" python3 - <<'PY'
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

root = Path(os.environ["RELEASE_INDEX_DIR"])
output = Path(os.environ["RELEASE_INDEX_OUTPUT"])
version_re = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
required = ("version", "channel", "archive", "sha256", "target_os", "target_arch", "target_libc", "git_commit", "rustc")
artifacts = []
seen = set()

def version_key(value):
    match = version_re.fullmatch(value)
    if not match:
        raise SystemExit(f"invalid provenance version: {value!r}")
    prerelease = match.group(4)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)), 1 if prerelease is None else 0, prerelease or "")

manifests = sorted(root.glob("*.provenance.json"), key=lambda path: path.name)
if not manifests:
    raise SystemExit(f"no provenance manifests found in {root}")
for manifest in manifests:
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"invalid provenance manifest {manifest}: {error}")
    if data.get("schema") != "ferrocrate-release-provenance-v1":
        raise SystemExit(f"unsupported provenance schema in {manifest}")
    if any(not isinstance(data.get(key), str) or not data[key] for key in required):
        raise SystemExit(f"provenance manifest is missing required fields: {manifest}")
    version_key(data["version"])
    archive_name = data["archive"]
    if Path(archive_name).name != archive_name or archive_name in ("", ".", ".."):
        raise SystemExit(f"provenance archive is not a basename: {manifest}")
    archive = root / archive_name
    if not archive.is_file():
        raise SystemExit(f"provenance archive is missing: {archive}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != data["sha256"]:
        raise SystemExit(f"provenance digest does not match archive: {archive}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", data["sha256"]):
        raise SystemExit(f"provenance sha256 is invalid: {manifest}")
    if data["target_libc"] not in ("gnu", "musl"):
        raise SystemExit(f"unsupported target_libc in {manifest}: {data['target_libc']!r}")
    if data["target_os"] != "linux" and data["target_libc"] != "gnu":
        raise SystemExit(f"musl target_libc is only valid for Linux: {manifest}")
    identity = (data["version"], data["channel"], data["target_os"], data["target_arch"], data["target_libc"])
    if identity in seen:
        raise SystemExit(f"duplicate release identity: {identity}")
    seen.add(identity)
    artifacts.append({key: data[key] for key in required} | {"provenance": manifest.name})

artifacts.sort(key=lambda item: (version_key(item["version"]), item["channel"], item["target_os"], item["target_arch"], item["target_libc"], item["archive"]))
payload = {"schema": "ferrocrate-release-index-v1", "artifacts": artifacts}
output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as handle:
    temporary = Path(handle.name)
    json.dump(payload, handle, indent=2, sort_keys=False)
    handle.write("\n")
temporary.replace(output)
print(f"release index generated: {output}")
PY
