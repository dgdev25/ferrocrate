#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/package/ferrocrate"
printf 'fixture\n' > "$tmp_dir/package/ferrocrate/ferrocrate"
archive="ferrocrate-v0.0.1-linux-x86_64.tar.gz"
(cd "$tmp_dir" && tar -czf "$archive" package/ferrocrate/ferrocrate)
(cd "$tmp_dir" && sha256sum "$archive" > ferrocrate-v0.0.1-checksums.txt)
digest="$(awk '{print $1}' "$tmp_dir/ferrocrate-v0.0.1-checksums.txt")"
PROVENANCE_PATH="$tmp_dir/$archive.provenance.json" \
  PROVENANCE_ARCHIVE="$archive" \
  PROVENANCE_DIGEST="$digest" \
  python3 - <<'PY'
import json
import os
from pathlib import Path

Path(os.environ["PROVENANCE_PATH"]).write_text(json.dumps({
    "schema": "ferrocrate-release-provenance-v1",
    "version": "v0.0.1",
    "channel": "public",
    "archive": os.environ["PROVENANCE_ARCHIVE"],
    "sha256": os.environ["PROVENANCE_DIGEST"],
    "target_os": "linux",
    "target_arch": "x86_64",
    "git_commit": "0" * 40,
    "rustc": "fixture",
}, sort_keys=True) + "\n")
PY

bash "$repo_root/scripts/verify-release-channel-artifacts.sh" \
  --channel public --version v0.0.1 --artifact-dir "$tmp_dir"

python3 - "$tmp_dir/$archive.provenance.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text())
data["sha256"] = "f" * 64
path.write_text(json.dumps(data))
PY
if bash "$repo_root/scripts/verify-release-channel-artifacts.sh" \
  --channel public --version v0.0.1 --artifact-dir "$tmp_dir"; then
  echo "tampered provenance unexpectedly passed" >&2
  exit 1
fi

echo "release provenance verification fixture passed"
