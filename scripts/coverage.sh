#!/usr/bin/env bash
set -euo pipefail

DEFAULT_MIN=85
CI_MIN=90
MIN="${FERROCRATE_COVERAGE_MIN:-}"
ENFORCE="${FERROCRATE_COVERAGE_ENFORCE:-1}"
TIMEOUT="${FERROCRATE_COVERAGE_TIMEOUT_SECS:-240}"
OUT="${FERROCRATE_COVERAGE_OUT:-Stdout}"

if [[ -z "${MIN}" ]]; then
  if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
    MIN="${CI_MIN}"
  else
    MIN="${DEFAULT_MIN}"
  fi
fi

if ! [[ "${MIN}" =~ ^[0-9]+$ ]]; then
  echo "coverage: FERROCRATE_COVERAGE_MIN must be an integer percentage, got '${MIN}'" >&2
  exit 2
fi

if ! command -v cargo-tarpaulin >/dev/null 2>&1; then
  if [[ "${ENFORCE}" == "1" || "${ENFORCE}" == "true" ]]; then
    echo "coverage: cargo-tarpaulin required" >&2
    exit 1
  fi
  echo "coverage: cargo-tarpaulin not installed; skipping (FERROCRATE_COVERAGE_ENFORCE=${ENFORCE})"
  exit 0
fi

echo "coverage: enforcing workspace line coverage >= ${MIN}%"
cargo tarpaulin \
  --workspace \
  --timeout "${TIMEOUT}" \
  --out "${OUT}" \
  --fail-under "${MIN}"
