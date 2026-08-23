#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness="$repo_root/scripts/docker-client-conformance.sh"

if [[ ! -x "$harness" ]]; then
  echo "missing executable conformance harness: $harness" >&2
  exit 1
fi

work_root="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-conformance-contract.XXXXXX")"
trap 'rm -rf -- "$work_root"' EXIT
fake_bin="$work_root/bin"
fake_state="$work_root/state"
mkdir -p "$fake_bin" "$fake_state"

cat >"$fake_bin/ferro-cli" <<'FAKE_FERRO'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"$FAKE_STATE/ferro.calls"
if [[ "${1:-}" == "--version" ]]; then
  if [[ "${FAKE_FERRO_VERSION_HANG:-0}" == 1 ]]; then
    sleep 30
  fi
  echo "ferrocrate 0.1.0-contract"
  exit 0
fi
if [[ "${1:-}" != "daemon" ]]; then
  echo "unexpected fake FerroCrate command: $*" >&2
  exit 64
fi

socket=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--socket" ]]; then
    socket="${2:-}"
    break
  fi
  shift
done
[[ -n "$socket" ]] || { echo "fake daemon did not receive --socket" >&2; exit 64; }

exec python3 - "$socket" <<'PY'
import os
import signal
import socket
import sys
import time

path = sys.argv[1]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)

def stop(_signum, _frame):
    server.close()
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
while True:
    time.sleep(0.1)
PY
FAKE_FERRO

cat >"$fake_bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -euo pipefail

id="${FERROCRATE_CONFORMANCE_RECORD_ID:-unrecorded}"
printf '%s\t%s\n' "$id" "$*" >>"$FAKE_STATE/docker.calls"

output=""
previous=""
for argument in "$@"; do
  if [[ "$previous" == "-o" || "$previous" == "--output" ]]; then
    output="$argument"
  fi
  previous="$argument"
done
if [[ -n "$output" ]]; then
  : >"$output"
fi

case "$id" in
  cli-version)
    echo "Client: Docker Engine - Community"
    echo " Version: 99.1.0-contract"
    echo "Server:"
    echo " Engine:"
    echo "  Version: 0.1.0-contract"
    ;;
  compose-version)
    echo "Docker Compose version v99.2.0-contract"
    ;;
  container-create|attach-container-create)
    echo "0123456789abcdef"
    ;;
  container-wait|attach-container-wait)
    echo "0"
    ;;
  container-attach)
    echo "contract attach output"
    exit 124
    ;;
  registry-search)
    echo "contract registry failure" >&2
    exit 37
    ;;
  registry-login)
    while IFS= read -r _line; do :; done
    echo "Login Succeeded"
    ;;
  *)
    echo "contract output for $id"
    ;;
esac
FAKE_DOCKER
chmod +x "$fake_bin/ferro-cli" "$fake_bin/docker"
spaced_ferro_dir="$work_root/ferro bin"
spaced_ferro="$spaced_ferro_dir/ferro cli"
mkdir -p "$spaced_ferro_dir"
cp "$fake_bin/ferro-cli" "$spaced_ferro"

expected_ids="$work_root/expected.ids"
cat >"$expected_ids" <<'EXPECTED'
cli-version
compose-version
engine-info
image-build
image-inspect
container-create
container-start
container-inspect
container-list
container-port
container-copy-in
container-diff
container-update
container-export
container-stop
container-wait
container-logs
container-remove
image-save
image-remove
image-load
image-list
attach-container-create
attach-container-start
container-attach
attach-container-wait
attach-container-remove
registry-search
registry-login
registry-logout
compose-up
compose-ps
compose-logs
compose-down
system-prune
EXPECTED

scoreboard="$work_root/parity-scoreboard.md"
execution_log="$work_root/docker-client-conformance.log"
set +e
PATH="$fake_bin:$PATH" \
  FAKE_STATE="$fake_state" \
  FERROCRATE_BIN="$spaced_ferro" \
  DOCKER_BUILDKIT=0 \
  FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS=2 \
  FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS=2 \
  "$harness" --output "$scoreboard" --log "$execution_log"
status=$?
set -e

if [[ "$status" != 1 ]]; then
  echo "expected completed conformance with command failures to exit 1, got $status" >&2
  exit 1
fi
[[ -s "$scoreboard" ]] || { echo "scoreboard was not generated" >&2; exit 1; }
[[ -s "$execution_log" ]] || { echo "execution log was not generated" >&2; exit 1; }

log_ids="$work_root/log.ids"
call_ids="$work_root/call.ids"
awk -F '\t' 'NR > 1 { print $2 }' "$execution_log" >"$log_ids"
awk -F '\t' '$1 != "unrecorded" { print $1 }' "$fake_state/docker.calls" >"$call_ids"
diff -u "$expected_ids" "$log_ids"
diff -u "$expected_ids" "$call_ids"

assert_recorded_command_starts_with() {
  local id="$1" expected="$2" actual
  actual="$(awk -F '\t' -v wanted="$id" '$1 == wanted { print $2; exit }' "$fake_state/docker.calls")"
  if [[ "$actual" != "$expected"* ]]; then
    echo "$id executed '$actual'; expected command beginning '$expected'" >&2
    exit 1
  fi
}

# Literal coverage for every P1 "Missing commands" entry and the required
# Compose lifecycle. IDs alone are insufficient: a mislabeled invocation must
# fail this contract.
assert_recorded_command_starts_with cli-version "version"
assert_recorded_command_starts_with engine-info "info"
assert_recorded_command_starts_with container-create "create "
assert_recorded_command_starts_with container-port "port "
assert_recorded_command_starts_with container-copy-in "cp "
assert_recorded_command_starts_with container-diff "diff "
assert_recorded_command_starts_with container-update "update "
assert_recorded_command_starts_with container-export "container export "
assert_recorded_command_starts_with image-save "save "
assert_recorded_command_starts_with image-load "load "
assert_recorded_command_starts_with container-attach "attach "
assert_recorded_command_starts_with registry-search "search "
assert_recorded_command_starts_with registry-login "login "
assert_recorded_command_starts_with registry-logout "logout "
assert_recorded_command_starts_with system-prune "system prune "

assert_compose_tail() {
  local id="$1" expected="$2" actual after_file tail
  actual="$(awk -F '\t' -v wanted="$id" '$1 == wanted { print $2; exit }' "$fake_state/docker.calls")"
  after_file="${actual#* --file }"
  tail="${after_file#* }"
  if [[ "$tail" != "$expected" ]]; then
    echo "$id executed Compose tail '$tail'; expected '$expected'" >&2
    exit 1
  fi
}

assert_compose_tail compose-up "up --detach"
assert_compose_tail compose-ps "ps --all"
assert_compose_tail compose-logs "logs --no-color"
assert_compose_tail compose-down "down --timeout 10"

expected_count="$(wc -l <"$expected_ids" | tr -d ' ')"
log_count="$(awk 'END { print NR - 1 }' "$execution_log")"
row_count="$(awk '/^\| [0-9]+ \|/ { count++ } END { print count + 0 }' "$scoreboard")"
[[ "$log_count" == "$expected_count" ]] || {
  echo "execution log contains $log_count rows; expected $expected_count" >&2
  exit 1
}
[[ "$row_count" == "$expected_count" ]] || {
  echo "scoreboard contains $row_count result rows; expected $expected_count" >&2
  exit 1
}

awk -F '\t' '$2 == "registry-search" { found = ($5 == 37 && $6 == "FAIL") } END { exit !found }' \
  "$execution_log"
awk -F '\t' '$2 == "container-attach" { found = ($5 == 124 && $6 == "ERROR") } END { exit !found }' \
  "$execution_log"
awk -F '\t' '$2 == "compose-down" { found = ($5 == 0 && $6 == "PASS") } END { exit !found }' \
  "$execution_log"
grep -Eq '^\| [0-9]+ \| registry-search \|.*\| 37 \| FAIL \|$' "$scoreboard"
grep -Eq '^\| [0-9]+ \| container-attach \|.*\| 124 \| ERROR \|$' "$scoreboard"
grep -Fq '| PASS | 33 |' "$scoreboard"
grep -Fq '| FAIL | 1 |' "$scoreboard"
grep -Fq '| ERROR | 1 |' "$scoreboard"
grep -Fq 'DOCKER_BUILDKIT=0' "$scoreboard"
grep -Fq 'tests/fixtures/real-app/compose.yml' "$scoreboard"
grep -Fq 'Docker-compatible server: 0.1.0-contract' "$scoreboard"
grep -Fq 'FerroCrate: ferrocrate 0.1.0-contract' "$scoreboard" || {
  echo "configured FERROCRATE_BIN path with spaces was not used for version metadata" >&2
  exit 1
}

extract_log_results() {
  awk -F '\t' 'NR > 1 { print $1 "\t" $2 "\t" $5 "\t" $6 }' "$1"
}

extract_markdown_results() {
  awk -F '|' '
    /^\| [0-9]+ \|/ {
      for (field = 2; field <= 7; field++) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $field)
      }
      print $2 "\t" $3 "\t" $6 "\t" $7
    }
  ' "$1"
}

# Every rendered exit/status pair must match the captured TSV record, not just
# the two deliberately failing spot checks above.
log_results="$work_root/log-results.tsv"
markdown_results="$work_root/markdown-results.tsv"
extract_log_results "$execution_log" >"$log_results"
extract_markdown_results "$scoreboard" >"$markdown_results"
diff -u "$log_results" "$markdown_results"

# Mutation check: prove the all-row comparator rejects one corrupted row.
corrupt_scoreboard="$work_root/corrupt-scoreboard.md"
awk '/^\| 35 \|/ { sub(/\| PASS \|$/, "| FAIL |") } { print }' \
  "$scoreboard" >"$corrupt_scoreboard"
extract_markdown_results "$corrupt_scoreboard" >"$work_root/corrupt-results.tsv"
if diff -u "$log_results" "$work_root/corrupt-results.tsv" >/dev/null; then
  echo "all-row scoreboard comparison accepted a corrupted status" >&2
  exit 1
fi

# Identical client outcomes on the same host must reproduce the committed
# Markdown byte-for-byte; runtime names and temporary paths are not evidence.
first_scoreboard="$work_root/first-scoreboard.md"
cp "$scoreboard" "$first_scoreboard"
set +e
PATH="$fake_bin:$PATH" \
  FAKE_STATE="$fake_state" \
  FERROCRATE_BIN="$spaced_ferro" \
  DOCKER_BUILDKIT=0 \
  FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS=2 \
  FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS=2 \
  "$harness" --output "$scoreboard" --log "$execution_log" >/dev/null
repeat_status=$?
set -e
[[ "$repeat_status" == 1 ]] || {
  echo "expected repeated conformance with command failures to exit 1, got $repeat_status" >&2
  exit 1
}
cmp "$first_scoreboard" "$scoreboard"

# Version metadata uses the same configured bound as client commands. A hung
# version probe must degrade to "unavailable", not block scoreboard output.
hang_scoreboard="$work_root/hang-scoreboard.md"
hang_log="$work_root/hang.log"
set +e
timeout --foreground --kill-after=1s 18s env \
  PATH="$fake_bin:$PATH" \
  FAKE_STATE="$fake_state" \
  FAKE_FERRO_VERSION_HANG=1 \
  FERROCRATE_BIN="$spaced_ferro" \
  DOCKER_BUILDKIT=0 \
  FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS=2 \
  FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS=2 \
  "$harness" --output "$hang_scoreboard" --log "$hang_log" >/dev/null
hang_status=$?
set -e
[[ "$hang_status" == 1 ]] || {
  echo "expected bounded hung-version run to finish with command-failure exit 1, got $hang_status" >&2
  exit 1
}
grep -Fq 'FerroCrate: unavailable' "$hang_scoreboard"

# Existing directories are invalid file targets and must be rejected before
# any daemon/client setup or atomic publication attempt.
output_directory="$work_root/output-directory"
log_directory="$work_root/log-directory"
mkdir -p "$output_directory" "$log_directory"
set +e
DOCKER_BUILDKIT=1 FERROCRATE_BIN="$spaced_ferro" \
  "$harness" --output "$output_directory" --log "$work_root/directory-output.log" \
  >"$work_root/output-directory.stdout" 2>"$work_root/output-directory.stderr"
output_directory_status=$?
DOCKER_BUILDKIT=1 FERROCRATE_BIN="$spaced_ferro" \
  "$harness" --output "$work_root/directory-log.md" --log "$log_directory" \
  >"$work_root/log-directory.stdout" 2>"$work_root/log-directory.stderr"
log_directory_status=$?
set -e
[[ "$output_directory_status" == 2 ]]
[[ "$log_directory_status" == 2 ]]
grep -Fq 'HARNESS ERROR: --output must not be an existing directory' "$work_root/output-directory.stderr"
grep -Fq 'HARNESS ERROR: --log must not be an existing directory' "$work_root/log-directory.stderr"
[[ -z "$(find "$output_directory" -mindepth 1 -print -quit)" ]]
[[ -z "$(find "$log_directory" -mindepth 1 -print -quit)" ]]

# A harness/setup error is exit 2, not a command FAIL/ERROR row, and atomic
# generation must preserve evidence that existed before the failed setup.
setup_scoreboard="$work_root/setup-scoreboard.md"
setup_log="$work_root/setup.log"
printf 'prior scoreboard\n' >"$setup_scoreboard"
printf 'prior log\n' >"$setup_log"
set +e
PATH="$fake_bin:$PATH" \
  FAKE_STATE="$fake_state" \
  FERROCRATE_BIN="$work_root/missing-ferro-cli" \
  DOCKER_BUILDKIT=0 \
  "$harness" --output "$setup_scoreboard" --log "$setup_log" \
  >"$work_root/setup.stdout" 2>"$work_root/setup.stderr"
setup_status=$?
set -e
[[ "$setup_status" == 2 ]] || {
  echo "expected setup error exit 2, got $setup_status" >&2
  exit 1
}
grep -Fq 'HARNESS ERROR:' "$work_root/setup.stderr"
[[ "$(cat "$setup_scoreboard")" == "prior scoreboard" ]]
[[ "$(cat "$setup_log")" == "prior log" ]]

bash -n "$harness"
echo "docker client conformance contract tests passed"
