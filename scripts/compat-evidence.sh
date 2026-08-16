#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${ROOT_DIR}/target/compat"
mkdir -p "$OUT_DIR"

REPORT_JSON="${OUT_DIR}/evidence.json"
REPORT_MD="${OUT_DIR}/evidence.md"

run_check() {
  local name="$1"
  shift
  local log_file="${OUT_DIR}/${name}.log"
  if "$@" >"$log_file" 2>&1; then
    echo "pass"
  else
    echo "fail"
  fi
}

echo "[compat] collecting compatibility evidence..."
os_name="$(uname -s)"
docker_api_skip_reason=""
dockerfile_build_skip_reason=""
docker_api_total="unknown"
docker_api_implemented="unknown"
docker_api_partial="unknown"
docker_api_unsupported="unknown"
dockerfile_parity_tests="unknown"

if [[ "$os_name" == "Linux" ]]; then
  docker_api_matrix_status="$(run_check docker_api_matrix cargo test -p ferro-cli --test api_compat_matrix -- --nocapture)"
  docker_api_integration_status="$(run_check docker_api_integration cargo test -p ferro-cli --test docker_compat_integration -- --nocapture)"
else
  docker_api_matrix_status="skipped"
  docker_api_integration_status="skipped"
  docker_api_skip_reason="linux_only_daemon_compat_tests"
fi
seccomp_security_status="$(run_check seccomp_security cargo test -p ferro-core --test security_tests -- --nocapture)"
oci_smoke_status="$(run_check oci_conformance bash scripts/oci-conformance.sh)"
if [[ "$os_name" == "Linux" ]]; then
  dockerfile_build_status="$(run_check dockerfile_build cargo test -p ferro-cli --test dockerfile_parity_integration -- --nocapture)"
else
  dockerfile_build_status="skipped"
  dockerfile_build_skip_reason="linux_only_dockerfile_parity_integration"
fi

if [[ -f "ferro-cli/tests/api_compat_matrix.rs" ]]; then
  docker_api_total="$(rg -n "coverage: Coverage::" ferro-cli/tests/api_compat_matrix.rs | wc -l | tr -d ' ')"
  docker_api_implemented="$(rg -n "Coverage::Implemented" ferro-cli/tests/api_compat_matrix.rs | wc -l | tr -d ' ')"
  docker_api_partial="$(rg -n "Coverage::Partial" ferro-cli/tests/api_compat_matrix.rs | wc -l | tr -d ' ')"
  docker_api_unsupported="$(rg -n "Coverage::Unsupported" ferro-cli/tests/api_compat_matrix.rs | wc -l | tr -d ' ')"
fi

if [[ -f "ferro-cli/tests/dockerfile_parity_integration.rs" ]]; then
  dockerfile_parity_tests="$(rg -n "^#\\[test\\]" ferro-cli/tests/dockerfile_parity_integration.rs | wc -l | tr -d ' ')"
fi
ai_latency_status="$(run_check ai_latency cargo run -p ferro-mind --example ai_latency)"
ai_quality_status="$(run_check ai_quality cargo run -p ferro-mind --example ai_quality)"

ai_latency_ns="unknown"
ai_latency_threshold_ns="${FERROCRATE_AI_LATENCY_MAX_NS:-500000}"
ai_latency_threshold_status="unknown"
if [[ -f "${OUT_DIR}/ai_latency.log" ]]; then
  ai_latency_ns="$(rg -o 'perf\.ai_inference_ns=[0-9]+' "${OUT_DIR}/ai_latency.log" | tail -n1 | cut -d'=' -f2 || true)"
  if [[ -z "${ai_latency_ns}" ]]; then
    ai_latency_ns="unknown"
  elif [[ "${ai_latency_ns}" =~ ^[0-9]+$ ]] && (( ai_latency_ns <= ai_latency_threshold_ns )); then
    ai_latency_threshold_status="pass"
  else
    ai_latency_threshold_status="fail"
  fi
fi

ai_growth_rate_mae_bps="unknown"
ai_growth_rate_mae_max="${FERROCRATE_AI_GROWTH_MAE_MAX_BPS:-80000}"
ai_growth_rate_mae_status="unknown"
ai_oom_detection_rate="unknown"
ai_oom_detection_min="${FERROCRATE_AI_OOM_DETECTION_MIN:-0.20}"
ai_oom_detection_status="unknown"
if [[ -f "${OUT_DIR}/ai_quality.log" ]]; then
  ai_growth_rate_mae_bps="$(rg -o 'perf\.ai_growth_rate_mae_bps=[0-9]+\.[0-9]+' "${OUT_DIR}/ai_quality.log" | tail -n1 | cut -d'=' -f2 || true)"
  ai_oom_detection_rate="$(rg -o 'perf\.ai_oom_detection_rate=[0-9]+\.[0-9]+' "${OUT_DIR}/ai_quality.log" | tail -n1 | cut -d'=' -f2 || true)"
  if [[ -n "${ai_growth_rate_mae_bps}" ]]; then
    if awk "BEGIN {exit !(${ai_growth_rate_mae_bps} <= ${ai_growth_rate_mae_max})}"; then
      ai_growth_rate_mae_status="pass"
    else
      ai_growth_rate_mae_status="fail"
    fi
  fi
  if [[ -n "${ai_oom_detection_rate}" ]]; then
    if awk "BEGIN {exit !(${ai_oom_detection_rate} >= ${ai_oom_detection_min})}"; then
      ai_oom_detection_status="pass"
    else
      ai_oom_detection_status="fail"
    fi
  fi
fi

cat >"$REPORT_JSON" <<JSON
{
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "platform": "${os_name}",
  "checks": {
    "docker_api_matrix": "${docker_api_matrix_status}",
    "docker_api_integration": "${docker_api_integration_status}",
    "seccomp_security_tests": "${seccomp_security_status}",
    "oci_smoke": "${oci_smoke_status}",
    "dockerfile_build_smoke": "${dockerfile_build_status}",
    "ai_latency_example": "${ai_latency_status}",
    "ai_quality_example": "${ai_quality_status}"
  },
  "metrics": {
    "docker_api_cases_total": "${docker_api_total}",
    "docker_api_cases_implemented": "${docker_api_implemented}",
    "docker_api_cases_partial": "${docker_api_partial}",
    "docker_api_cases_unsupported": "${docker_api_unsupported}",
    "ai_inference_ns": "${ai_latency_ns}",
    "ai_latency_max_ns": "${ai_latency_threshold_ns}",
    "ai_latency_threshold_status": "${ai_latency_threshold_status}",
    "ai_growth_rate_mae_bps": "${ai_growth_rate_mae_bps}",
    "ai_growth_rate_mae_max_bps": "${ai_growth_rate_mae_max}",
    "ai_growth_rate_mae_status": "${ai_growth_rate_mae_status}",
    "ai_oom_detection_rate": "${ai_oom_detection_rate}",
    "ai_oom_detection_min": "${ai_oom_detection_min}",
    "ai_oom_detection_status": "${ai_oom_detection_status}"
  },
  "coverage": {
    "dockerfile_parity_tests": "${dockerfile_parity_tests}"
  },
  "skip_reasons": {
    "docker_api": "${docker_api_skip_reason}",
    "dockerfile_build": "${dockerfile_build_skip_reason}"
  }
}
JSON

cat >"$REPORT_MD" <<MD
# Compatibility Evidence

- Generated at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- Platform: ${os_name}
- Docker API matrix: ${docker_api_matrix_status}
- Docker API integration: ${docker_api_integration_status}
- Docker API skip reason: ${docker_api_skip_reason}
- Docker API coverage cases: total=${docker_api_total} implemented=${docker_api_implemented} partial=${docker_api_partial} unsupported=${docker_api_unsupported}
- Seccomp/security tests: ${seccomp_security_status}
- OCI smoke: ${oci_smoke_status}
- Dockerfile build smoke: ${dockerfile_build_status}
- Dockerfile build skip reason: ${dockerfile_build_skip_reason}
- Dockerfile parity tests: ${dockerfile_parity_tests}
- AI latency example: ${ai_latency_status}
- AI inference latency (ns): ${ai_latency_ns}
- AI latency threshold (ns): ${ai_latency_threshold_ns}
- AI latency threshold status: ${ai_latency_threshold_status}
- AI quality example: ${ai_quality_status}
- AI growth-rate MAE (bytes/sec): ${ai_growth_rate_mae_bps}
- AI growth-rate MAE max (bytes/sec): ${ai_growth_rate_mae_max}
- AI growth-rate MAE status: ${ai_growth_rate_mae_status}
- AI OOM detection rate: ${ai_oom_detection_rate}
- AI OOM detection minimum: ${ai_oom_detection_min}
- AI OOM detection status: ${ai_oom_detection_status}
MD

if [[ "$docker_api_matrix_status" == "fail" || \
      "$docker_api_integration_status" == "fail" || \
      "$seccomp_security_status" != "pass" || \
      "$oci_smoke_status" != "pass" || \
      "$dockerfile_build_status" == "fail" || \
      "$ai_latency_status" != "pass" || \
      "$ai_quality_status" != "pass" || \
      "$ai_latency_threshold_status" == "fail" || \
      "$ai_growth_rate_mae_status" == "fail" || \
      "$ai_oom_detection_status" == "fail" ]]; then
  echo "[compat] one or more checks failed. see ${OUT_DIR}/*.log" >&2
  exit 1
fi

echo "[compat] evidence written to ${REPORT_JSON} and ${REPORT_MD}"
