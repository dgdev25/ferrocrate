#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
cd "$repo_root"

plan="docs/PRODUCTION-READINESS-ROADMAP-2026-09-05.md"
roadmap="docs/ROADMAP.md"
[[ -f "$plan" ]] || { echo "missing production readiness roadmap: $plan" >&2; exit 1; }
[[ -f "$roadmap" ]] || { echo "missing roadmap: $roadmap" >&2; exit 1; }

grep -Fq 'This is the active execution roadmap.' "$plan" || {
  echo "production readiness roadmap lacks its authority statement" >&2
  exit 1
}

required_files=(
  LICENSE
  CONTRIBUTING.md
  CODE_OF_CONDUCT.md
  SECURITY.md
  SUPPORT.md
  README.md
  CHANGELOG.md
  docs/PRODUCTION-READINESS-ROADMAP-2026-09-05.md
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

if [[ ! -d .github/workflows ]] || ! find .github/workflows -type f -name '*.yml' -print -quit | grep -q .; then
  echo "missing self-hosted GitHub Actions workflows" >&2
  exit 1
fi
if ! grep -R -Eq 'self-hosted.*ferro-lab' .github/workflows; then
  echo "GitHub Actions workflows must use ferro-lab self-hosted runners" >&2
  exit 1
fi

gate_count="$(grep -cE '^- \[[ x]\] R[0-9]+' "$plan" || true)"
if [[ "$gate_count" -ne 34 ]]; then
  echo "expected 34 production readiness rows, found $gate_count" >&2
  exit 1
fi

if ! grep -Fq '## Phase 6 — Publish honest readiness evidence' "$plan"; then
  echo "production readiness roadmap lacks the release-evidence phase" >&2
  exit 1
fi

bash scripts/perf/check-benchmark-register.sh

# Keep the current Docker API matrix count synchronized with its authoritative
# evidence and the release plan. Historical evidence may retain older counts,
# but the current-head record and plan must agree with the Rust matrix.
matrix="ferro-cli/tests/api_compat_matrix.rs"
[[ -f "$matrix" ]] || { echo "missing Docker API matrix: $matrix" >&2; exit 1; }
declared="$(grep -c '^[[:space:]]*ApiCase {' "$matrix")"
implemented="$(grep -c 'coverage: Coverage::Implemented' "$matrix")"
unsupported="$(grep -c 'coverage: Coverage::Unsupported' "$matrix")"
current_evidence="$(find docs/evidence/verification -maxdepth 1 -type f -name '2026-08-21-docker-tty-container-lifecycle-current-head.md' -print -quit)"
[[ -n "$current_evidence" ]] || {
  echo "missing current Docker API matrix evidence" >&2
  exit 1
}
grep -Fq "The matrix now contains $declared declared cases: $implemented implemented and $unsupported explicitly" "$current_evidence" || {
  echo "Docker API matrix evidence count is stale (expected $declared/$implemented/$unsupported)" >&2
  exit 1
}
grep -Fq "authoritative at $declared declared cases:" "$roadmap" || {
  echo "roadmap Docker API matrix count is stale (expected $declared)" >&2
  exit 1
}
grep -Eq "$declared declared cases(:|,) $implemented implemented, (0|zero) partial, and $unsupported explicit(ly)? unsupported" "$roadmap" || {
  echo "roadmap Docker API matrix count is stale (expected $declared/$implemented/$unsupported)" >&2
  exit 1
}
echo "production readiness documentation gate passed: 34 status rows, required public artifacts, self-hosted workflows"
