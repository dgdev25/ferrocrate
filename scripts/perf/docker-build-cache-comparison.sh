#!/usr/bin/env bash
set -euo pipefail

# Paired Docker/Ferrocrate build-cache and parallel-build benchmark.  This is
# deliberately separate from the fixed ten-feature headline comparison: the
# two workloads exercise cache/repeated-build and concurrent-build behavior,
# which are tracked as additional benchmark-register rows.

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
out="${FERROCRATE_BUILD_COMPARISON_OUTPUT:-$repo_root/docs/evidence/performance/$(date -u +%F)-docker-build-cache-comparison.md}"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
image="${FERROCRATE_COMPARISON_IMAGE:-alpine:3.20}"
rounds="${FERROCRATE_BUILD_COMPARISON_ROUNDS:-3}"
parallelism="${FERROCRATE_BUILD_COMPARISON_PARALLELISM:-4}"

[[ "$rounds" =~ ^[1-9][0-9]*$ ]] || { echo "invalid rounds: $rounds" >&2; exit 2; }
[[ "$parallelism" =~ ^[1-9][0-9]*$ ]] || { echo "invalid parallelism: $parallelism" >&2; exit 2; }
[[ "$image" =~ ^[A-Za-z0-9._/@:-]+$ ]] || { echo "invalid image: $image" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker is unavailable" >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 ]] || {
  echo "rootful Docker/Ferrocrate comparison requires uid 0; rerun with sudo" >&2
  exit 77
}
[[ -x "$ferro_bin" ]] || { (cd "$repo_root" && cargo build -p ferro-cli --release >/dev/null); }

tmp_root="$(mktemp -d /tmp/ferrocrate-build-comparison.XXXXXX)"
context="$tmp_root/context"
ferro_runtime="$tmp_root/ferro-runtime"
mkdir -p "$context" "$ferro_runtime"
cat >"$context/Dockerfile" <<EOF
FROM $image
ARG BENCHMARK_VARIANT=base
RUN printf 'ferrocrate-build-cache-%s\\n' "\$BENCHMARK_VARIANT" >/benchmark-marker
EOF

cleanup() {
  docker image rm -f ferrocrate-build-cache-docker-base ferrocrate-build-cache-docker-variant \
    ferrocrate-build-cache-ferro-base ferrocrate-build-cache-ferro-variant >/dev/null 2>&1 || true
  rm -rf "$tmp_root"
}
trap cleanup EXIT

docker pull "$image" >/dev/null 2>&1 || docker image inspect "$image" >/dev/null 2>&1 || {
  echo "image $image is unavailable locally and could not be pulled" >&2
  exit 1
}

ferro_env="env HOME=$tmp_root/home FERROCRATE_RUNTIME_DIR=$ferro_runtime"
mkdir -p "$tmp_root/home"
if ! eval "$ferro_env $ferro_bin pull '$image'" >/dev/null 2>&1; then
  echo "Ferrocrate could not prepare base image $image" >&2
  exit 1
fi

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

parallel_ms() {
  local command_prefix="$1" start end i pids=()
  start="$(date +%s%N)"
  for ((i = 1; i <= parallelism; i++)); do
    bash -c "${command_prefix//__INDEX__/$i}" >/dev/null 2>&1 &
    pids+=("$!")
  done
  for p in "${pids[@]}"; do
    wait "$p" || { echo SKIP; return 0; }
  done
  end="$(date +%s%N)"
  echo "$(( (end - start) / 1000000 ))"
}

# Prime both builders once so the repeated-build row measures cache reuse.
docker build -q -t ferrocrate-build-cache-docker-base "$context" >/dev/null
eval "$ferro_env $ferro_bin build --dockerfile '$context/Dockerfile' --tag ferrocrate-build-cache-ferro-base" >/dev/null

docker_cached="$(median_ms "docker build -q -t ferrocrate-build-cache-docker-base '$context'")"
ferro_cached="$(median_ms "$ferro_env $ferro_bin build --dockerfile '$context/Dockerfile' --tag ferrocrate-build-cache-ferro-base")"

# Give each concurrent Ferrocrate worker its own already-populated store. This
# keeps registry preparation outside the timed batch and avoids turning a
# missing per-worker base image into a misleading parallel-build skip.
for ((i = 1; i <= parallelism; i++)); do
  mkdir -p "$tmp_root/home-$i" "$ferro_runtime/$i"
  env HOME="$tmp_root/home-$i" FERROCRATE_RUNTIME_DIR="$ferro_runtime/$i" \
    "$ferro_bin" pull "$image" >/dev/null 2>&1 || {
      echo "Ferrocrate worker $i could not prepare base image $image" >&2
      exit 1
    }
done

docker_parallel="$(parallel_ms "docker build -q -t ferrocrate-build-cache-docker-variant-__INDEX__ '$context'")"
ferro_parallel="$(parallel_ms "env HOME=$tmp_root/home-__INDEX__ FERROCRATE_RUNTIME_DIR=$ferro_runtime/__INDEX__ $ferro_bin build --dockerfile '$context/Dockerfile' --tag ferrocrate-build-cache-ferro-variant-__INDEX__")"

mkdir -p "$(dirname -- "$out")"
{
  echo "# Ferrocrate vs Docker build-cache benchmark"
  echo
  echo "- Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Host: $(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}") / $(uname -r) / $(uname -m)"
  echo "- Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)"
  echo "- Ferrocrate commit: $(git -C "$repo_root" rev-parse --short HEAD)"
  echo "- Image: \`$image\`; rounds per cached row: $rounds; parallelism: $parallelism."
  echo "- Reported values are median wall-clock milliseconds; the parallel row is one wall-clock batch."
  echo
  echo "This is a host-local performance comparison, not a compatibility or production-readiness claim."
  echo
  echo "| Feature | Docker (ms) | Ferrocrate (ms) | Difference (Ferrocrate-Docker) | Relative vs Docker |"
  echo "|---|---:|---:|---:|---:|"
  for row in "Repeated cached build|$docker_cached|$ferro_cached" "Parallel build batch ($parallelism)|$docker_parallel|$ferro_parallel"; do
    IFS='|' read -r name docker_value ferro_value <<<"$row"
    if [[ "$docker_value" == SKIP || "$ferro_value" == SKIP ]]; then
      diff=n/a; relative=n/a
    else
      diff=$((ferro_value - docker_value))
      relative="$(awk -v docker="$docker_value" -v ferro="$ferro_value" 'BEGIN { if (docker == 0) print "n/a"; else printf "%+.1f%%", ((ferro-docker)*100)/docker }')"
    fi
    echo "| $name | $docker_value | $ferro_value | $diff | $relative |"
  done
  echo
  echo "The benchmark uses the same tracked Dockerfile and base image for both implementations."
  echo "Ferrocrate builds use an isolated runtime store; Docker uses its daemon cache."
} >"$out"

printf 'comparison report: %s\n' "$out"
