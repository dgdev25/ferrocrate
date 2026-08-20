#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
out="${FERROCRATE_NETWORK_RUN_OUTPUT:-$repo_root/docs/evidence/performance/$(date -u +%F)-docker-network-run-comparison.md}"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
image="${FERROCRATE_COMPARISON_IMAGE:-alpine:3.20}"
rounds="${FERROCRATE_COMPARISON_ROUNDS:-3}"

[[ "$image" =~ ^[A-Za-z0-9._/@:-]+$ ]] || { echo "invalid image reference" >&2; exit 2; }
[[ "$rounds" =~ ^[1-9][0-9]*$ ]] || { echo "rounds must be positive" >&2; exit 2; }
[[ -x "$ferro_bin" ]] || { echo "missing Ferrocrate binary: $ferro_bin" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is unavailable" >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "rootful comparison requires root" >&2; exit 77; }

tmp_root="$(mktemp -d /tmp/ferrocrate-network-run.XXXXXX)"
ferro_runtime="$tmp_root/runtime"
mkdir -p "$ferro_runtime"
trap 'rm -rf "$tmp_root"' EXIT
docker pull "$image" >/dev/null 2>&1 || docker image inspect "$image" >/dev/null
env FERROCRATE_RUNTIME_DIR="$ferro_runtime" HOME="$tmp_root" \
  "$ferro_bin" pull "$image" >/dev/null

median_ms() {
  local command_string="$1" start end i
  local -a samples=()
  for ((i = 0; i < rounds; i++)); do
    start="$(date +%s%N)"
    if ! bash -c "$command_string" >/dev/null 2>&1; then
      echo SKIP
      return
    fi
    end="$(date +%s%N)"
    samples+=("$(((end - start) / 1000000))")
  done
  printf '%s\n' "${samples[@]}" | sort -n | awk '{ a[NR]=$1 } END { print a[int((NR+1)/2)] }'
}

docker_ms="$(median_ms "docker run --rm --network bridge '$image' true")"
ferro_ms="$(median_ms "env FERROCRATE_RUNTIME_DIR='$ferro_runtime' HOME='$tmp_root' '$ferro_bin' run --rm --network bridge --network-backend iptables '$image' true")"

mkdir -p "$(dirname -- "$out")"
{
  echo "# Ferrocrate vs Docker bridge-enabled run benchmark"
  echo
  echo "- Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Host: $(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}") / $(uname -r) / $(uname -m)"
  echo "- Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)"
  echo "- Ferrocrate commit: $(git -C "$repo_root" rev-parse --short HEAD)"
  echo "- Image: \`$image\`; rounds: $rounds; median wall-clock milliseconds."
  echo
  echo "| Feature | Docker median (ms) | Ferrocrate median (ms) | Difference | Relative vs Docker |"
  echo "|---|---:|---:|---:|---:|"
  if [[ "$docker_ms" == SKIP || "$ferro_ms" == SKIP ]]; then
    echo "| container run/exit (bridge) | $docker_ms | $ferro_ms | n/a | n/a |"
  else
    diff=$((ferro_ms - docker_ms))
    relative="$(awk -v d="$docker_ms" -v f="$ferro_ms" 'BEGIN { if (d == 0) print "n/a"; else printf "%+.1f%%", ((f-d)*100)/d }')"
    echo "| container run/exit (bridge) | $docker_ms | $ferro_ms | $diff | $relative |"
  fi
} >"$out"
printf 'comparison report: %s\n' "$out"
