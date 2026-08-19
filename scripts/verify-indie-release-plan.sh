#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"

plan="docs/INDIE_RELEASE_PLAN.md"
roadmap="docs/ROADMAP.md"
[[ -f "$plan" ]] || { echo "missing indie release plan: $plan" >&2; exit 1; }
[[ -f "$roadmap" ]] || { echo "missing roadmap: $roadmap" >&2; exit 1; }

required_headings=(
  "### 1. Rootless Linux usability"
  "### 2. Reliable rootful Linux baseline"
  "### 3. Docker/OCI compatibility"
  "### 4. CRI and Compose confidence"
  "### 5. Security release gates"
  "### 6. Operational packaging"
  "### 7. Open-source readiness"
  "### 8. Evidence and performance"
)
for heading in "${required_headings[@]}"; do
  grep -Fq "$heading" "$plan" || {
    echo "indie release plan is missing heading: $heading" >&2
    exit 1
  }
done

required_files=(
  LICENSE
  CONTRIBUTING.md
  CODE_OF_CONDUCT.md
  SECURITY.md
  SUPPORT.md
  README.md
  CHANGELOG.md
  docs/INDIE_RELEASE_PLAN.md
  docs/operations/local-release-gate.md
  docs/evidence/performance/benchmark-register.md
)
for file in "${required_files[@]}"; do
  [[ -f "$file" ]] || { echo "missing public release artifact: $file" >&2; exit 1; }
done

for template in .github/ISSUE_TEMPLATE/bug_report.md .github/ISSUE_TEMPLATE/feature_request.md; do
  [[ -f "$template" ]] || {
    echo "missing public issue template: $template" >&2
    exit 1
  }
done

if ! grep -Eiq 'supported|experimental|planned' README.md; then
  echo "README must distinguish supported, experimental, or planned behavior" >&2
  exit 1
fi

# GitHub Actions were intentionally removed; a workflow directory containing
# executable workflow definitions would silently reintroduce an unreviewed CI
# path. Empty parent directories are harmless and do not fail this check.
if [[ -d .github/workflows ]] && find .github/workflows -type f -print -quit | grep -q .; then
  echo "unexpected GitHub workflow files found; use the documented local gate" >&2
  exit 1
fi

gate_count="$(grep -c '^| [^|].* | \(Partial\|Open\|Complete\|Blocked\) |' "$plan" || true)"
if [[ "$gate_count" -ne 8 ]]; then
  echo "expected eight current indie gate status rows, found $gate_count" >&2
  exit 1
fi

if ! grep -Fq 'The current repository-wide roadmap contains ' "$plan"; then
  echo "indie plan is missing its repository-wide roadmap count" >&2
  exit 1
fi

bash scripts/perf/check-benchmark-register.sh
echo "indie release plan gate passed: eight status rows, required public artifacts, no workflows"
