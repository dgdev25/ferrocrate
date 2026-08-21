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
    "target_libc": "gnu",
    "git_commit": "0" * 40,
    "rustc": "fixture",
}, sort_keys=True) + "\n")
PY

bash "$repo_root/scripts/verify-release-channel-artifacts.sh" \
  --channel public --version v0.0.1 --artifact-dir "$tmp_dir"

# The release gate must validate the checksum bytes, not merely the presence
# of an archive and a provenance manifest.
cp "$tmp_dir/$archive" "$tmp_dir/$archive.good"
printf 'tampered\n' >> "$tmp_dir/$archive"
if bash "$repo_root/scripts/verify-release-channel-artifacts.sh" \
  --channel public --version v0.0.1 --artifact-dir "$tmp_dir" >/dev/null 2>&1; then
  echo "tampered archive unexpectedly passed checksum verification" >&2
  exit 1
fi
mv "$tmp_dir/$archive.good" "$tmp_dir/$archive"

# Reject path traversal and extra checksum entries before any archive access.
printf '%s  ../outside.tar.gz\n%s  %s\n' \
  "$digest" "$digest" "$archive" > "$tmp_dir/ferrocrate-v0.0.1-checksums.txt"
if bash "$repo_root/scripts/verify-release-channel-artifacts.sh" \
  --channel public --version v0.0.1 --artifact-dir "$tmp_dir" >/dev/null 2>&1; then
  echo "unsafe checksum manifest unexpectedly passed" >&2
  exit 1
fi
printf '%s  %s\n' "$digest" "$archive" > "$tmp_dir/ferrocrate-v0.0.1-checksums.txt"

# Exercise the signed-channel verifier with an isolated ephemeral key.  This
# proves the release gate, while keeping real publication keys out of tests and
# the repository.  Hosts without GPG still retain the checksum/provenance gate.
if command -v gpg >/dev/null 2>&1; then
  export GNUPGHOME="$tmp_dir/gnupg"
  mkdir -m 700 "$GNUPGHOME"
  cat >"$tmp_dir/keyparams" <<'KEY'
Key-Type: RSA
Key-Length: 2048
Name-Real: Ferrocrate Fixture
Name-Email: fixture@example.invalid
Expire-Date: 0
%no-protection
%commit
KEY
  gpg --batch --generate-key "$tmp_dir/keyparams" >/dev/null 2>&1
  gpg --batch --yes --armor --detach-sign "$tmp_dir/$archive"
  bash "$repo_root/scripts/verify-release-channel-artifacts.sh" \
    --channel public --version v0.0.1 --artifact-dir "$tmp_dir" \
    --require-signatures
fi

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
