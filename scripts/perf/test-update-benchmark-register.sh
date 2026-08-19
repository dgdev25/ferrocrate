#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/../.." && pwd)"
updater="$repo_root/scripts/perf/update-benchmark-register.py"
register="$repo_root/docs/evidence/performance/benchmark-register.md"
latest_head="$(sed -n 's/^Latest benchmark-relevant implementation head: `\([^`]*\)`.*/\1/p' "$register")"
[[ -n "$latest_head" ]] || { echo "benchmark register fixture has no current head" >&2; exit 1; }
iptables_path="$repo_root/docs/evidence/performance/$(date -u +%F)-docker-comparison-current-head-${latest_head}-iptables.md"
nftables_path="$repo_root/docs/evidence/performance/$(date -u +%F)-docker-comparison-current-head-${latest_head}-nftables.md"
[[ -f "$iptables_path" && -f "$nftables_path" ]] || { echo "benchmark register fixture has no current paired reports" >&2; exit 1; }
iptables="$(basename -- "$iptables_path")"
nftables="$(basename -- "$nftables_path")"
tmp_root="$(mktemp -d /tmp/ferrocrate-benchmark-register.XXXXXX)"
trap 'rm -rf -- "$tmp_root"' EXIT

cp "$register" "$tmp_root/register.md"
cp "$iptables_path" "$tmp_root/$iptables"
cp "$nftables_path" "$tmp_root/$nftables"
before_hash="$(sha256sum "$tmp_root/register.md" | awk '{print $1}')"
python3 "$updater" "$tmp_root/$iptables" "$tmp_root/$nftables" --register "$tmp_root/register.md" >"$tmp_root/proposal.md"
after_dry_hash="$(sha256sum "$tmp_root/register.md" | awk '{print $1}')"
[[ "$before_hash" == "$after_dry_hash" ]] || {
  echo "benchmark updater dry-run mutated the register" >&2
  exit 1
}

python3 "$updater" "$tmp_root/$iptables" "$tmp_root/$nftables" --register "$tmp_root/register.md" --apply
bash "$repo_root/scripts/perf/check-benchmark-register.sh" "$tmp_root/register.md"
grep -q 'Current comparison snapshot' "$tmp_root/register.md"
grep -q '58 unique benchmark IDs' <(bash "$repo_root/scripts/perf/check-benchmark-register.sh" "$tmp_root/register.md")

echo "benchmark register updater regression checks passed"
