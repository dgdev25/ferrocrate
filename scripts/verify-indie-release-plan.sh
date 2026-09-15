#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"

required_files=(
  LICENSE
  CONTRIBUTING.md
  CODE_OF_CONDUCT.md
  SECURITY.md
  SUPPORT.md
  README.md
  CHANGELOG.md
  docs/FEATURE-MATRIX.md
  docs/performance-baselines.md
  docs/RELEASE.md
  docs/release/SIGNING.md
  docs/architecture/legacy-sled-importers.md
  docs/compatibility/rootless-install.md
  docs/operations/docker-migration.md
  docs/operations/managed-overlays.md
  docs/operations/registry.md
)
for file in "${required_files[@]}"; do
  [[ -f "$file" ]] || { echo "missing public release artifact: $file" >&2; exit 1; }
done

for template in .github/ISSUE_TEMPLATE/bug_report.md .github/ISSUE_TEMPLATE/feature_request.md; do
  [[ -f "$template" ]] || { echo "missing public issue template: $template" >&2; exit 1; }
done

unexpected=0
while IFS= read -r path; do
  case "$path" in
    docs/FEATURE-MATRIX.md|docs/performance-baselines.md|docs/RELEASE.md|docs/release/SIGNING.md|docs/architecture/legacy-sled-importers.md|docs/compatibility/rootless-install.md|docs/operations/docker-migration.md|docs/operations/managed-overlays.md|docs/operations/registry.md)
      ;;
    docs/assets/screenshots/*.png)
      [[ "$path" != docs/assets/screenshots/*/* ]] || { echo "unexpected tracked documentation: $path" >&2; unexpected=1; }
      ;;
    docs/assets/*.svg)
      [[ "$path" != docs/assets/*/* ]] || { echo "unexpected tracked documentation: $path" >&2; unexpected=1; }
      ;;
    *)
      echo "unexpected tracked documentation: $path" >&2
      unexpected=1
      ;;
  esac
done < <(git ls-files docs)
(( unexpected == 0 )) || exit 1

grep -Fq 'Supported' docs/FEATURE-MATRIX.md || { echo "feature matrix lacks supported status" >&2; exit 1; }
grep -Fq 'Experimental' docs/FEATURE-MATRIX.md || { echo "feature matrix lacks experimental status" >&2; exit 1; }
grep -Fq 'Unsupported' docs/FEATURE-MATRIX.md || { echo "feature matrix lacks unsupported status" >&2; exit 1; }

if [[ ! -d .github/workflows ]] || ! find .github/workflows -type f -name '*.yml' -print -quit | grep -q .; then
  echo "missing self-hosted GitHub Actions workflows" >&2
  exit 1
fi
grep -R -Eq 'self-hosted.*ferro-lab' .github/workflows || {
  echo "GitHub Actions workflows must use ferro-lab self-hosted runners" >&2
  exit 1
}

echo "public documentation gate passed: curated allowlist, community files, and self-hosted workflows"
