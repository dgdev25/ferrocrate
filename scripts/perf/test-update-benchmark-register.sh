#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/../.." && pwd)"
updater="$repo_root/scripts/perf/update-benchmark-register.py"
register="$repo_root/docs/evidence/performance/benchmark-register.md"
latest_head="$(sed -n 's/^Latest benchmark-relevant implementation head: `\([^`]*\)`.*/\1/p' "$register")"
[[ -n "$latest_head" ]] || { echo "benchmark register fixture has no current head" >&2; exit 1; }
# Report filenames are dated evidence, not a clock contract.  A report may be
# generated near UTC midnight (or on a host whose clock is deliberately
# offset), so resolve the latest report by implementation head rather than
# requiring its date prefix to equal the runner's current UTC date.
report_dir="$repo_root/docs/evidence/performance"
iptables_path="$(find "$report_dir" -maxdepth 1 -type f -name "*-docker-comparison-current-head-${latest_head}-iptables.md" -print | sort | tail -n 1)"
nftables_path="$(find "$report_dir" -maxdepth 1 -type f -name "*-docker-comparison-current-head-${latest_head}-nftables.md" -print | sort | tail -n 1)"
[[ -f "$iptables_path" && -f "$nftables_path" ]] || { echo "benchmark register fixture has no current paired reports" >&2; exit 1; }
iptables="$(basename -- "$iptables_path")"
nftables="$(basename -- "$nftables_path")"
tmp_root="$(mktemp -d /tmp/ferrocrate-benchmark-register.XXXXXX)"
trap 'rm -rf -- "$tmp_root"' EXIT

cp "$register" "$tmp_root/register.md"
cp "$iptables_path" "$tmp_root/$iptables"
cp "$nftables_path" "$tmp_root/$nftables"
# Exercise stale metadata and B-001 links: a refresh must update both the
# visible snapshot and the register's latest measured-row references.
sed -i \
  -e 's/Latest benchmark-relevant implementation head: `[^`]*`/Latest benchmark-relevant implementation head: `stale-head`/' \
  -e 's/The latest paired refresh was completed at head `[^`]*`/The latest paired refresh was completed at head `stale-head`/' \
  -e 's/milliseconds from commit `[^`]*`/milliseconds from commit `stale-head`/' \
  -e 's#docker-comparison-current-head-[^)]*-iptables.md#docker-comparison-current-head-stale-head-iptables.md#g' \
  -e 's#docker-comparison-current-head-[^)]*-nftables.md#docker-comparison-current-head-stale-head-nftables.md#g' \
  "$tmp_root/register.md"
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
grep -Fq 'Latest benchmark-relevant implementation head: `'"$latest_head"'`' "$tmp_root/register.md"
grep -q "docker-comparison-current-head-${latest_head}-iptables.md" "$tmp_root/register.md"
grep -q "docker-comparison-current-head-${latest_head}-nftables.md" "$tmp_root/register.md"
expected_ids="$(grep -c '^| B-[0-9][0-9][0-9] ' "$tmp_root/register.md")"
grep -q "${expected_ids} unique benchmark IDs" <(bash "$repo_root/scripts/perf/check-benchmark-register.sh" "$tmp_root/register.md")

echo "benchmark register updater regression checks passed"
