#!/usr/bin/env bash
set -euo pipefail

# Bounded local network-rate/DNS smoke comparison.  The fixture deliberately
# uses host networking and a loopback HTTP server so Docker and Ferrocrate see
# the same endpoint; this is not a bridge, published-port, or eBPF test.
repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
out="${FERROCRATE_NETWORK_RATE_OUTPUT:-$repo_root/docs/evidence/performance/$(date -u +%F)-docker-network-rate-comparison.md}"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
image="${FERROCRATE_COMPARISON_IMAGE:-ferrocrate-bench:docker}"
rounds="${FERROCRATE_COMPARISON_ROUNDS:-3}"
requests="${FERROCRATE_NETWORK_RATE_REQUESTS:-8}"
fixture_timeout="${FERROCRATE_COMPARISON_TIMEOUT_SECONDS:-30}"

[[ "$image" =~ ^[A-Za-z0-9._/@:-]+$ ]] || { echo "invalid image" >&2; exit 2; }
[[ "$rounds" =~ ^[1-9][0-9]*$ ]] || { echo "rounds must be positive" >&2; exit 2; }
[[ "$requests" =~ ^[1-9][0-9]*$ && "$requests" -le 100 ]] || { echo "requests must be 1..100" >&2; exit 2; }
[[ "$fixture_timeout" =~ ^[1-9][0-9]*$ && "$fixture_timeout" -le 300 ]] || { echo "timeout must be 1..300" >&2; exit 2; }
[[ -x "$ferro_bin" ]] || { echo "missing Ferrocrate binary: $ferro_bin" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is unavailable" >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "rootful comparison requires root" >&2; exit 77; }

tmp_root="$(mktemp -d /tmp/ferrocrate-network-rate.XXXXXX)"
runtime="$tmp_root/runtime"
server_log="$tmp_root/server.log"
mkdir -p "$runtime"
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  rm -rf "$tmp_root"
}
trap cleanup EXIT

python3 - "$tmp_root" >"$server_log" 2>&1 <<'PY' &
import http.server
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
(root / "health").write_text("ferrocrate-network-rate\n", encoding="ascii")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(root), **kwargs)
    def log_message(self, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(server.server_address[1], flush=True)
server.serve_forever()
PY
server_pid=$!
for _ in $(seq 1 50); do [[ -s "$server_log" ]] && break; sleep 0.02; done
port="$(head -n1 "$server_log")"
[[ "$port" =~ ^[0-9]+$ ]] || { echo "HTTP fixture failed to start" >&2; exit 1; }

docker pull "$image" >/dev/null 2>&1 || docker image inspect "$image" >/dev/null
env FERROCRATE_RUNTIME_DIR="$runtime" HOME="$tmp_root" "$ferro_bin" pull "$image" >/dev/null

median_ms() {
  local command_string="$1" start end i
  local -a samples=()
  for ((i = 0; i < rounds; i++)); do
    start="$(date +%s%N)"
    timeout --foreground --signal=TERM --kill-after=5s "$fixture_timeout" \
      bash -c "$command_string" >/dev/null
    end="$(date +%s%N)"
    samples+=("$(( (end - start) / 1000000 ))")
  done
  printf '%s\n' "${samples[@]}" | sort -n | awk '{ a[NR]=$1 } END { print a[int((NR+1)/2)] }'
}

request_loop="i=0; while [ \"\$i\" -lt $requests ]; do wget -qO- http://127.0.0.1:$port/health >/dev/null; i=\$((i+1)); done"
dns_loop="i=0; while [ \"\$i\" -lt $requests ]; do getent hosts localhost >/dev/null; i=\$((i+1)); done"
docker_http="docker run --rm --network host '$image' sh -ec '$request_loop'"
ferro_http="env FERROCRATE_RUNTIME_DIR='$runtime' HOME='$tmp_root' '$ferro_bin' run --rm --network host '$image' sh -ec '$request_loop'"
docker_dns="docker run --rm --network host '$image' sh -ec '$dns_loop'"
ferro_dns="env FERROCRATE_RUNTIME_DIR='$runtime' HOME='$tmp_root' '$ferro_bin' run --rm --network host '$image' sh -ec '$dns_loop'"

docker_http_ms="$(median_ms "$docker_http")"
ferro_http_ms="$(median_ms "$ferro_http")"
docker_dns_ms="$(median_ms "$docker_dns")"
ferro_dns_ms="$(median_ms "$ferro_dns")"

relative() {
  awk -v f="$1" -v d="$2" 'BEGIN { if (d == 0) print "+0.0%"; else printf "%+.1f%%", ((f-d)/d)*100 }'
}
mkdir -p "$(dirname -- "$out")"
cat >"$out" <<EOF
# Ferrocrate vs Docker local network-rate/DNS benchmark

- Date (UTC): $(date -u +%FT%TZ)
- Host: $(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}") / $(uname -r) / $(uname -m)
- Docker: $(docker version --format '{{.Server.Version}}')
- Ferrocrate commit: $(git -C "$repo_root" rev-parse --short HEAD)
- Image: \`$image\`; rounds: $rounds; requests per operation: $requests.
- Network mode: host; HTTP endpoint is a local loopback fixture.
- Per-operation timeout: ${fixture_timeout}s.

| Feature | Docker median (ms) | Ferrocrate median (ms) | Difference | Relative vs Docker |
|---|---:|---:|---:|---:|
| $requests sequential local HTTP connections | $docker_http_ms | $ferro_http_ms | $((ferro_http_ms - docker_http_ms)) | $(relative "$ferro_http_ms" "$docker_http_ms") |
| $requests local resolver lookups (\`getent hosts localhost\`) | $docker_dns_ms | $ferro_dns_ms | $((ferro_dns_ms - docker_dns_ms)) | $(relative "$ferro_dns_ms" "$docker_dns_ms") |

This is a bounded host-network smoke measurement of connection setup and local
resolver overhead. It does not qualify bridge throughput, PPS under load,
published ports, firewall policy, or live eBPF behavior.
EOF
echo "comparison report: $out"
