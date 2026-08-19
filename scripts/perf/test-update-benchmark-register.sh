#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/../.." && pwd)"
updater="$repo_root/scripts/perf/update-benchmark-register.py"
register="$repo_root/docs/evidence/performance/benchmark-register.md"
iptables="$repo_root/docs/evidence/performance/2026-08-19-docker-comparison-current-head-bb592039-iptables.md"
nftables="$repo_root/docs/evidence/performance/2026-08-19-docker-comparison-current-head-bb592039-nftables.md"
tmp_root="$(mktemp -d /tmp/ferrocrate-benchmark-register.XXXXXX)"
trap 'rm -rf -- "$tmp_root"' EXIT

cp "$register" "$tmp_root/register.md"
before_hash="$(sha256sum "$tmp_root/register.md" | awk '{print $1}')"
python3 "$updater" "$iptables" "$nftables" --register "$tmp_root/register.md" >"$tmp_root/proposal.md"
after_dry_hash="$(sha256sum "$tmp_root/register.md" | awk '{print $1}')"
[[ "$before_hash" == "$after_dry_hash" ]] || {
  echo "benchmark updater dry-run mutated the register" >&2
  exit 1
}

python3 "$updater" "$iptables" "$nftables" --register "$tmp_root/register.md" --apply
bash "$repo_root/scripts/perf/check-benchmark-register.sh" "$tmp_root/register.md"
grep -q 'Current comparison snapshot' "$tmp_root/register.md"
grep -q '58 unique benchmark IDs' <(bash "$repo_root/scripts/perf/check-benchmark-register.sh" "$tmp_root/register.md")

echo "benchmark register updater regression checks passed"
