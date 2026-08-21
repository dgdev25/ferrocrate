#!/usr/bin/env bash
set -euo pipefail

# Paired Docker/Ferrocrate IPv6 network lifecycle benchmark. The command
# validates the persisted IPv6 IPAM entry as well as measuring create/inspect/
# remove, so a fast but incomplete implementation cannot pass silently.

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
out="${FERROCRATE_IPV6_COMPARISON_OUTPUT:-$repo_root/docs/evidence/performance/$(date -u +%F)-docker-ipv6-comparison.md}"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
runtime="$(mktemp -d /tmp/ferrocrate-ipv6-benchmark.XXXXXX)"
rounds="${FERROCRATE_IPV6_COMPARISON_ROUNDS:-3}"
fixture_timeout="${FERROCRATE_COMPARISON_TIMEOUT_SECONDS:-30}"
subnet="fd00:fe:0:1::/64"
gateway="fd00:fe:0:1::1"

cleanup() {
  docker network rm ferro-ipv6-bench >/dev/null 2>&1 || true
  rm -rf "$runtime"
}
trap cleanup EXIT

[[ "$rounds" =~ ^[1-9][0-9]*$ ]] || { echo "invalid rounds: $rounds" >&2; exit 2; }
[[ "$fixture_timeout" =~ ^[1-9][0-9]*$ && "$fixture_timeout" -le 300 ]] || { echo "FERROCRATE_COMPARISON_TIMEOUT_SECONDS must be 1..300" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker is unavailable" >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 ]] || {
  echo "rootful Docker/Ferrocrate comparison requires uid 0; rerun with sudo" >&2
  exit 77
}
[[ -x "$ferro_bin" ]] || { (cd "$repo_root" && cargo build -p ferro-cli --release >/dev/null); }

median_ms() {
  local kind="$1" samples=() start end i name json
  for ((i = 0; i < rounds; i++)); do
    name="ferro-ipv6-bench-$kind-$i"
    start="$(date +%s%N)"
    if [[ "$kind" == docker ]]; then
      timeout --foreground --signal=TERM --kill-after=5s "$fixture_timeout" \
        docker network create --ipv6 --subnet "$subnet" --gateway "$gateway" "$name" >/dev/null
      json="$(timeout --foreground --signal=TERM --kill-after=5s "$fixture_timeout" docker network inspect "$name")"
      timeout --foreground --signal=TERM --kill-after=5s "$fixture_timeout" docker network rm "$name" >/dev/null
    else
      timeout --foreground --signal=TERM --kill-after=5s "$fixture_timeout" \
        env FERROCRATE_RUNTIME_DIR="$runtime/$i" "$ferro_bin" network create \
          --ipv6-subnet "$subnet" --ipv6-gateway "$gateway" "$name" >/dev/null
      json="$(timeout --foreground --signal=TERM --kill-after=5s "$fixture_timeout" \
        env FERROCRATE_RUNTIME_DIR="$runtime/$i" "$ferro_bin" network inspect --format json "$name")"
      timeout --foreground --signal=TERM --kill-after=5s "$fixture_timeout" \
        env FERROCRATE_RUNTIME_DIR="$runtime/$i" "$ferro_bin" network rm "$name" >/dev/null
    fi
    grep -Fq '"EnableIPv6": true' <<<"$json"
    grep -Fq "$subnet" <<<"$json"
    grep -Fq "$gateway" <<<"$json"
    end="$(date +%s%N)"
    samples+=("$(( (end - start) / 1000000 ))")
  done
  printf '%s\n' "${samples[@]}" | sort -n | awk '{ a[NR]=$1 } END { print a[int((NR+1)/2)] }'
}

docker_ms="$(median_ms docker)"
ferro_ms="$(median_ms ferro)"
diff=$((ferro_ms - docker_ms))
relative="$(awk -v docker="$docker_ms" -v ferro="$ferro_ms" 'BEGIN { if (docker == 0) print "n/a"; else printf "%+.1f%%", ((ferro-docker)*100)/docker }')"

mkdir -p "$(dirname -- "$out")"
{
  echo "# Ferrocrate vs Docker IPv6 network benchmark"
  echo
  echo "- Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Host: $(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}") / $(uname -r) / $(uname -m)"
  echo "- Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)"
  echo "- Ferrocrate commit: $(git -C "$repo_root" rev-parse --short HEAD)"
  echo "- Fixture: create, inspect, and remove a bridge network with IPv6 subnet \`$subnet\` and gateway \`$gateway\`."
  echo "- Rounds: $rounds; reported value is the median wall-clock milliseconds."
  echo "- Per-operation timeout: ${fixture_timeout}s."
  echo
  echo "Both implementations had to expose \`EnableIPv6=true\` and the requested IPv6 IPAM values in inspection output."
  echo
  echo "| Feature | Docker median (ms) | Ferrocrate median (ms) | Difference (Ferrocrate-Docker) | Relative vs Docker |"
  echo "|---|---:|---:|---:|---:|"
  echo "| IPv6 network create/inspect/remove | $docker_ms | $ferro_ms | $diff | $relative |"
  echo
  echo "This is a host-local lifecycle comparison; it does not claim IPv6 packet forwarding, DNS64, or cross-host IPv6 support."
} >"$out"

printf 'comparison report: %s\n' "$out"
