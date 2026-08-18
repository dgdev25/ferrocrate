#!/usr/bin/env bash
set -euo pipefail

# Paired Docker/Ferrocrate named-volume create/write/read/remove benchmark.
repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
out="${FERROCRATE_VOLUME_IO_OUTPUT:-$repo_root/docs/evidence/performance/$(date -u +%F)-docker-volume-io-comparison.md}"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
image="${FERROCRATE_COMPARISON_IMAGE:-alpine:3.20}"
rounds="${FERROCRATE_COMPARISON_ROUNDS:-3}"

[[ "$image" =~ ^[A-Za-z0-9._/@:-]+$ ]] || { echo "invalid image reference" >&2; exit 2; }
[[ "$rounds" =~ ^[1-9][0-9]*$ ]] || { echo "rounds must be a positive integer" >&2; exit 2; }
[[ -x "$ferro_bin" ]] || { echo "missing Ferrocrate binary: $ferro_bin" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is unavailable" >&2; exit 1; }
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "volume I/O comparison requires rootful Docker/Ferrocrate access" >&2
  exit 77
fi

tmp_root="$(mktemp -d /tmp/ferrocrate-volume-io.XXXXXX)"
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

median_ms() {
  local command_string="$1" samples=() start end i
  for ((i = 0; i < rounds; i++)); do
    start="$(date +%s%N)"
    if ! bash -c "$command_string" >/dev/null 2>&1; then
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
}

record "volume create/write/read/remove" \
  'name="ferrocrate-bench-docker-$BASHPID"; docker volume create "$name" >/dev/null; docker run --rm -v "$name:/data" '"$image"' sh -c "printf volume-io >/data/value && test -s /data/value"; docker volume rm "$name" >/dev/null' \
  "name=ferrocrate-bench-ferro-\$BASHPID; $ferro_env '$ferro_bin' volume create \"\$name\" >/dev/null; $ferro_env '$ferro_bin' run --rm --volume \"\$name:/data\" '$image' sh -c 'printf volume-io >/data/value && test -s /data/value'; $ferro_env '$ferro_bin' volume rm \"\$name\" >/dev/null"

mkdir -p "$(dirname -- "$out")"
{
  echo "# Ferrocrate vs Docker named-volume I/O benchmark"
  echo
  echo "- Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Host: $(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}") / $(uname -r) / $(uname -m)"
  echo "- Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)"
  echo "- Ferrocrate commit: $(git -C "$repo_root" rev-parse --short HEAD)"
  echo "- Image: \`$image\`; rounds per operation: $rounds; reported value is median wall-clock milliseconds."
  echo
  echo "This supplements the fixed ten-feature comparison and measures a named volume's create, container write/read, and cleanup path."
  echo
  echo "| Feature | Docker median (ms) | Ferrocrate median (ms) | Difference (Ferrocrate-Docker) | Relative vs Docker |"
  echo "|---|---:|---:|---:|---:|"
  for i in "${!names[@]}"; do
    d="${docker_values[$i]}"; f="${ferro_values[$i]}"
    if [[ "$d" == SKIP || "$f" == SKIP ]]; then
      diff="n/a"; relative="n/a"
    else
      diff=$((f-d))
      relative="$(awk -v docker="$d" -v ferro="$f" 'BEGIN { if (docker == 0) print "n/a"; else printf "%+.1f%%", ((ferro-docker) * 100) / docker }')"
    fi
    echo "| ${names[$i]} | $d | $f | $diff | $relative |"
  done
} >"$out"

printf 'comparison report: %s\n' "$out"
