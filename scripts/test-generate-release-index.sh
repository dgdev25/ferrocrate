#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
utility="$repo_root/scripts/generate-release-index.sh"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/artifacts"

python3 - "$tmp/artifacts" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for version, channel in (("v1.10.0", "public"), ("v1.2.0", "paid")):
    archive = root / f"ferrocrate-{version}-linux-x86_64.tar.gz"
    archive.write_bytes(f"{version}-{channel}".encode())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    payload = {
        "schema": "ferrocrate-release-provenance-v1",
        "version": version,
        "channel": channel,
        "archive": archive.name,
        "sha256": digest,
        "target_os": "linux",
        "target_arch": "x86_64",
        "target_libc": "gnu",
        "git_commit": "abc123",
        "rustc": "rustc test",
    }
    (root / f"{archive.name}.provenance.json").write_text(json.dumps(payload) + "\n")
PY

"$utility" --artifact-dir "$tmp/artifacts" --output "$tmp/index.json"
python3 - "$tmp/index.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["schema"] == "ferrocrate-release-index-v1"
assert [item["version"] for item in data["artifacts"]] == ["v1.2.0", "v1.10.0"]
assert data["artifacts"][0]["channel"] == "paid"
PY

printf 'tampered' >"$tmp/artifacts/ferrocrate-v1.2.0-linux-x86_64.tar.gz"
if "$utility" --artifact-dir "$tmp/artifacts" --output "$tmp/bad.json" >/dev/null 2>&1; then
  echo "tampered artifact unexpectedly indexed" >&2
  exit 1
fi

echo "release index regression checks passed"
