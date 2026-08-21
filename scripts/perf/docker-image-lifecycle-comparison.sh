#!/usr/bin/env bash
set -euo pipefail

# Paired Docker/Ferrocrate image metadata lifecycle benchmark. This is kept
# separate from the fixed ten-feature headline benchmark so the register can
# grow without changing its regression-gate contract.
repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
out="${FERROCRATE_IMAGE_LIFECYCLE_OUTPUT:-$repo_root/docs/evidence/performance/$(date -u +%F)-docker-image-lifecycle-comparison.md}"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
image="${FERROCRATE_COMPARISON_IMAGE:-alpine:3.20}"
rounds="${FERROCRATE_COMPARISON_ROUNDS:-3}"
fixture_timeout="${FERROCRATE_COMPARISON_TIMEOUT_SECONDS:-30}"

[[ "$image" =~ ^[A-Za-z0-9._/@:-]+$ ]] || {
  echo "invalid image reference: $image" >&2
  exit 2
}
[[ "$rounds" =~ ^[1-9][0-9]*$ ]] || {
  echo "rounds must be a positive integer" >&2
  exit 2
}
[[ "$fixture_timeout" =~ ^[1-9][0-9]*$ && "$fixture_timeout" -le 300 ]] || {
  echo "FERROCRATE_COMPARISON_TIMEOUT_SECONDS must be 1..300" >&2
  exit 2
}
[[ -x "$ferro_bin" ]] || {
  echo "Ferrocrate binary is missing or not executable: $ferro_bin" >&2
  exit 1
}
command -v docker >/dev/null || { echo "docker is unavailable" >&2; exit 1; }
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "image lifecycle comparison requires rootful Docker/Ferrocrate access" >&2
  exit 77
fi

tmp_root="$(mktemp -d /tmp/ferrocrate-image-lifecycle.XXXXXX)"
ferro_runtime="$tmp_root/ferro-runtime"
mkdir -p "$ferro_runtime"
cleanup() { rm -rf "$tmp_root"; }
trap cleanup EXIT

docker pull "$image" >/dev/null 2>&1 || docker image inspect "$image" >/dev/null
ferro_env="env FERROCRATE_RUNTIME_DIR=$ferro_runtime HOME=$tmp_root"
eval "$ferro_env \"$ferro_bin\" pull \"$image\"" >/dev/null

declare -a names=()
declare -a docker_values=()
declare -a ferro_values=()
declare -a notes=()

median_ms() {
  local command_string="$1" samples=() start end i
  for ((i = 0; i < rounds; i++)); do
    start="$(date +%s%N)"
    if ! timeout --foreground --signal=TERM --kill-after=5s "$fixture_timeout" \
      bash -c "$command_string" >/dev/null 2>&1; then
      echo SKIP
      return 0
    fi
    end="$(date +%s%N)"
    samples+=("$(( (end - start) / 1000000 ))")
  done
  printf '%s\n' "${samples[@]}" | sort -n | awk '{ a[NR]=$1 } END { print a[int((NR+1)/2)] }'
}

record() {
  names+=("$1")
  docker_values+=("$(median_ms "$2")")
  ferro_values+=("$(median_ms "$3")")
  notes+=("$4")
}

record "image inspect" \
  "docker image inspect '$image'" \
  "$ferro_env '$ferro_bin' image-inspect '$image'" \
  "Same warm local OCI image; metadata readback only."

record "image tag" \
  'tag="ferrocrate-bench:docker-$BASHPID"; docker tag '"$image"' "$tag"; docker image inspect "$tag" >/dev/null; docker rmi "$tag" >/dev/null' \
  "tag=ferrocrate-bench:ferro-\$BASHPID; $ferro_env '$ferro_bin' tag '$image' \"\$tag\" >/dev/null; $ferro_env '$ferro_bin' image-inspect \"\$tag\" >/dev/null; $ferro_env '$ferro_bin' rmi \"\$tag\" >/dev/null" \
  "Tag, inspect, and cleanup of one temporary reference."

record "image remove" \
  'tag="ferrocrate-bench:docker-$BASHPID"; docker tag '"$image"' "$tag"; docker rmi "$tag" >/dev/null' \
  "tag=ferrocrate-bench:ferro-\$BASHPID; $ferro_env '$ferro_bin' tag '$image' \"\$tag\" >/dev/null; $ferro_env '$ferro_bin' rmi \"\$tag\" >/dev/null" \
  "Temporary tag removal while retaining the source image."

mkdir -p "$(dirname -- "$out")"
{
  echo "# Ferrocrate vs Docker image lifecycle benchmark"
  echo
  echo "- Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Host: $(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}") / $(uname -r) / $(uname -m)"
  echo "- Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)"
  echo "- Ferrocrate commit: $(git -C "$repo_root" rev-parse --short HEAD)"
  echo "- Image: \`$image\`; rounds per operation: $rounds; reported value is median wall-clock milliseconds."
  echo "- Per-operation timeout: ${fixture_timeout}s (timed-out operations are reported as SKIP)."
  echo
  echo "This supplements the fixed ten-feature comparison and does not claim universal Docker parity."
  echo
  echo "| Feature | Docker median (ms) | Ferrocrate median (ms) | Difference (Ferrocrate-Docker) | Relative vs Docker | Notes |"
  echo "|---|---:|---:|---:|---:|---|"
  for i in "${!names[@]}"; do
    d="${docker_values[$i]}"; f="${ferro_values[$i]}"
    if [[ "$d" == SKIP || "$f" == SKIP ]]; then
      diff="n/a"; relative="n/a"
    else
      diff=$((f-d))
      relative="$(awk -v docker="$d" -v ferro="$f" 'BEGIN { if (docker == 0) print "n/a"; else printf "%+.1f%%", ((ferro-docker) * 100) / docker }')"
    fi
    echo "| ${names[$i]} | $d | $f | $diff | $relative | ${notes[$i]} |"
  done
} >"$out"

printf 'comparison report: %s\n' "$out"
