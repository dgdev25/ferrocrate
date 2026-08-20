#!/usr/bin/env bash
set -euo pipefail

# Compare a small outbound HTTP request from the same OCI image through the
# Docker-compatible runtimes.  Host networking is intentional: it gives both
# clients the same local HTTP endpoint and isolates request/connection setup
# from published-port and bridge-firewall qualification.

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/../.." && pwd)}"
out="${FERROCRATE_OUTBOUND_HTTP_OUTPUT:-$repo_root/docs/evidence/performance/$(date -u +%F)-docker-outbound-http-comparison.md}"
ferro_bin="${FERROCRATE_BIN:-$repo_root/target/release/ferro-cli}"
image="${FERROCRATE_COMPARISON_IMAGE:-alpine:3.20}"
rounds="${FERROCRATE_COMPARISON_ROUNDS:-5}"

[[ "$image" =~ ^[A-Za-z0-9._/@:-]+$ ]] || { echo "invalid image" >&2; exit 2; }
[[ "$rounds" =~ ^[1-9][0-9]*$ ]] || { echo "rounds must be positive" >&2; exit 2; }
[[ -x "$ferro_bin" ]] || { echo "Ferrocrate binary is unavailable: $ferro_bin" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is unavailable" >&2; exit 1; }
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "rootful Docker/Ferrocrate comparison requires uid 0; rerun with sudo" >&2
  exit 77
fi

tmp_root="$(mktemp -d /tmp/ferrocrate-outbound-http.XXXXXX)"
runtime="$tmp_root/runtime"
socket="$tmp_root/ferro.sock"
server_log="$tmp_root/server.log"
mkdir -p "$runtime"
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi
  rm -rf "$tmp_root"
}
trap cleanup EXIT

python3 - "$tmp_root" >"$server_log" 2>&1 <<'PY' &
import http.server
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
(root / "health").write_text("ferrocrate-outbound-ok\n", encoding="ascii")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(root), **kwargs)

    def log_message(self, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.RequestHandlerClass.directory = str(root)
print(server.server_address[1], flush=True)
server.serve_forever()
PY
server_pid=$!
for _ in $(seq 1 50); do [[ -s "$server_log" ]] && break; sleep 0.02; done
port="$(head -n1 "$server_log")"
[[ "$port" =~ ^[0-9]+$ ]] || { echo "HTTP fixture failed to start" >&2; exit 1; }

median_ms() {
  local command_string="$1" start end i
  local -a samples=()
  for ((i = 0; i < rounds; i++)); do
    start="$(date +%s%N)"
    bash -c "$command_string" >/dev/null
    end="$(date +%s%N)"
    samples+=("$(( (end - start) / 1000000 ))")
  done
  printf '%s\n' "${samples[@]}" | sort -n | awk '{ a[NR]=$1 } END { print a[int((NR+1)/2)] }'
}

docker_cmd="docker run --rm --network host $image wget -qO- http://127.0.0.1:$port/health"
ferro_cmd="env FERROCRATE_RUNTIME_DIR=$runtime HOME=$tmp_root $ferro_bin run --rm --network host $image wget -qO- http://127.0.0.1:$port/health"
docker_value="$(median_ms "$docker_cmd")"
ferro_value="$(median_ms "$ferro_cmd")"
delta=$((ferro_value - docker_value))
relative="$(awk -v f="$ferro_value" -v d="$docker_value" 'BEGIN { if (d == 0) print "+0.0%"; else printf "%+.1f%%", ((f-d)/d)*100 }')"

mkdir -p "$(dirname -- "$out")"
cat >"$out" <<EOF
# Ferrocrate vs Docker outbound HTTP benchmark

- Date (UTC): $(date -u +%FT%TZ)
- Host: $(uname -srvmo)
- Docker: $(docker version --format '{{.Server.Version}}')
- Ferrocrate commit: $(git -C "$repo_root" rev-parse --short HEAD)
- Image: \`$image\`; rounds: $rounds; reported value is the median wall-clock milliseconds.
- Network mode: host (same local HTTP fixture for both runtimes)

| Feature | Docker median (ms) | Ferrocrate median (ms) | Difference | Relative vs Docker |
|---|---:|---:|---:|---:|
| Outbound HTTP request | $docker_value | $ferro_value | $delta | $relative |

This measures local outbound request/connection setup through host networking.
It does not qualify bridge networking, published ports, firewall policy, DNS, or
the unresolved live eBPF published-port path.
EOF
echo "comparison report: $out"
