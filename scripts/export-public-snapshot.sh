#!/usr/bin/env bash
# Build the public snapshot of this repository as a single-commit orphan
# branch named `public`, from the current `main` tree.
#
#   scripts/export-public-snapshot.sh           # build/refresh the `public` branch
#   scripts/export-public-snapshot.sh --verify  # build into a temp dir and check only
#
# The private repository keeps its full history. The snapshot:
#   1. starts from `git archive main` (so .gitignore'd files never enter),
#   2. drops every path in scripts/public-snapshot-exclude.txt,
#   3. rewrites local machine paths in text files (see SCRUB below),
#   4. fails if any leak pattern, agent-state path, or oversized file remains,
#   5. checks that the workspace still passes `cargo check`.
# See docs/adr/ADR-018-public-release-by-curated-snapshot.md.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
verify_only=0
[[ "${1:-}" != "--verify" ]] || verify_only=1
source_ref="${PUBLIC_SNAPSHOT_SOURCE:-main}"
branch="${PUBLIC_SNAPSHOT_BRANCH:-public}"
max_file_bytes=$((10 * 1024 * 1024))

# Local-path and identity rewrites. Left side is a fixed string; right side
# is the replacement. Order matters: longer prefixes first.
SCRUB=(
  "/path/to/ferrocrate-lab|/srv/lab"
  "/data/dev/ferrocrate-archive|/srv/ferrocrate-archive"
  "/data/dev/ferrocrate-desk|/srv/ferrocrate-desk"
  "/data/dev/ferrocrate-r|/srv/ferrocrate-r"
  "/data/dev/ferrocrate-w|/srv/ferrocrate-w"
  "/data/dev/ferrotest|/srv/ferrotest"
  "/data/dev/ferrocrate|/srv/ferrocrate"
  "/data/dev/|/srv/"
  "/home/USER|/home/user"
  "lyledgdev@gmail.com|maintainers@example.invalid"
  "192.168.0.13|192.0.2.13"
)
# Patterns that must not survive in any text file of the snapshot.
LEAK_PATTERNS='/data/dev|/home/USER|lyledgdev|192\.168\.0\.13|-----BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]{30,}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}'
# Path fragments that must not exist in the snapshot.
FORBIDDEN_PATHS='(^|/)(\.claude|\.claude-flow|\.swarm|\.superpowers|\.harness|\.primer|\.superdesign|memory|lab)(/|$)|(^|/)(agentdb\.rvf|ruvector\.db|\.mcp\.json|COORDINATOR-NOTE\.md|prd2build\.config\.json)$|\.(db|db-wal|db-shm)$'

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tree="$work/tree"
mkdir -p "$tree"

echo "export: archiving $source_ref"
git -C "$repo_root" archive --format=tar "$source_ref" | tar -x -C "$tree"

echo "export: applying exclude list"
while IFS= read -r line; do
  [[ -n "$line" && "$line" != \#* ]] || continue
  rm -rf "${tree:?}/$line"
done < "$repo_root/scripts/public-snapshot-exclude.txt"

echo "export: scrubbing local paths"
# Text files only: binaries are left untouched (and later size-checked).
mapfile -d '' text_files < <(cd "$tree" && grep -rIlZ --exclude-dir=.git -e '' . || true)
sed_script="$work/scrub.sed"
: > "$sed_script"
for pair in "${SCRUB[@]}"; do
  from="${pair%%|*}"; to="${pair#*|}"
  printf 's|%s|%s|g\n' "$from" "$to" >> "$sed_script"
done
if ((${#text_files[@]})); then
  (cd "$tree" && printf '%s\0' "${text_files[@]}" | xargs -0 sed -i -f "$sed_script")
fi

echo "export: verifying"
fail=0
leaks="$(cd "$tree" && grep -rIlE --exclude-dir=.git "$LEAK_PATTERNS" . || true)"
if [[ -n "$leaks" ]]; then
  echo "LEAK: local paths or secrets remain in:" >&2; echo "$leaks" | head -20 >&2; fail=1
fi
forbidden="$(cd "$tree" && find . -path ./.git -prune -o -print | sed 's|^\./||' | grep -E "$FORBIDDEN_PATHS" || true)"
if [[ -n "$forbidden" ]]; then
  echo "LEAK: agent-state or local-only paths remain:" >&2; echo "$forbidden" | head -20 >&2; fail=1
fi
big="$(cd "$tree" && find . -path ./.git -prune -o -type f -size +"$max_file_bytes"c -print || true)"
if [[ -n "$big" ]]; then
  echo "SIZE: files over $((max_file_bytes / 1024 / 1024)) MB:" >&2; echo "$big" >&2; fail=1
fi
for required in LICENSE README.md SECURITY.md CONTRIBUTING.md Cargo.toml deny.toml; do
  [[ -f "$tree/$required" ]] || { echo "MISSING: $required" >&2; fail=1; }
done
(( fail == 0 )) || { echo "export: verification FAILED" >&2; exit 1; }

file_count="$(cd "$tree" && find . -path ./.git -prune -o -type f -print | wc -l)"
echo "export: cargo check in snapshot"
# Skip the npm frontend build: it would install node_modules into the tree.
# Both embeds fall back to a placeholder page when dist/ is absent.
FERROCRATE_SKIP_FRONTEND_BUILD=1 CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}" \
  cargo check --workspace --quiet --manifest-path "$tree/Cargo.toml"

echo "export: snapshot ok ($file_count files)"
(( verify_only == 0 )) || exit 0

echo "export: committing to branch $branch"
src_head="$(git -C "$repo_root" rev-parse --short "$source_ref")"
git -C "$tree" init -q -b "$branch"
# -f: main force-tracks some evidence logs that .gitignore would skip; the
# forbidden-path check above already rejects real local-only files.
git -C "$tree" add -A -f
git -C "$tree" -c user.name="Ferrocrate" -c user.email="maintainers@example.invalid" \
  commit -q -m "Ferrocrate public snapshot (from private $source_ref @ $src_head)"
git -C "$repo_root" fetch -q --force "$tree" "$branch:$branch"
echo "export: branch $branch now at $(git -C "$repo_root" rev-parse --short "$branch")"
