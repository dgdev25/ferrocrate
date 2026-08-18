#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

export GNUPGHOME="$tmp_dir/gnupg"
mkdir -m 700 "$GNUPGHOME"
cat >"$tmp_dir/keyparams" <<'KEY'
Key-Type: RSA
Key-Length: 2048
Name-Real: Ferrocrate Signing Fixture
Name-Email: signing-fixture@example.invalid
Expire-Date: 0
%no-protection
%commit
KEY
gpg --batch --generate-key "$tmp_dir/keyparams" >/dev/null 2>&1
key_id="$(gpg --batch --list-secret-keys --with-colons | awk -F: '$1 == "sec" { print $5; exit }')"
[[ -n "$key_id" ]] || { echo "fixture key was not created" >&2; exit 1; }

artifact_dir="$tmp_dir/artifacts"
mkdir -p "$artifact_dir"
printf 'release fixture\n' >"$artifact_dir/ferrocrate-linux-x86_64"
FERROCRATE_GPG_KEY_ID="$key_id" bash "$repo_root/scripts/sign-binaries.sh" "$artifact_dir"
bash "$repo_root/scripts/sign-binaries.sh" "$artifact_dir" --verify-only
[[ -s "$artifact_dir/ferrocrate-linux-x86_64.asc" ]]
[[ -s "$artifact_dir/CHECKSUMS.txt" ]]

printf 'tamper\n' >>"$artifact_dir/ferrocrate-linux-x86_64"
if bash "$repo_root/scripts/sign-binaries.sh" "$artifact_dir" --verify-only; then
  echo "tampered signed artifact unexpectedly verified" >&2
  exit 1
fi

echo "binary signing fixture passed"
