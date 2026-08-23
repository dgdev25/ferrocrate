#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness="$repo_root/scripts/docker-client-conformance.sh"

if [[ ! -x "$harness" ]]; then
  echo "missing executable conformance harness: $harness" >&2
  exit 1
fi

work_root="$(mktemp -d "${TMPDIR:-/tmp}/ferrocrate-conformance-contract.XXXXXX")"
fake_bin="$work_root/bin"
fake_state="$work_root/state"
mkdir -p "$fake_bin" "$fake_state"

cleanup_contract_test() {
  local pid_file pid
  for pid_file in "$fake_state"/*.pid; do
    [[ -f "$pid_file" ]] || continue
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    kill -KILL "$pid" 2>/dev/null || true
  done
  [[ -z "${unrelated_pid:-}" ]] || kill -KILL "$unrelated_pid" 2>/dev/null || true
  rm -rf -- "$work_root"
}
trap cleanup_contract_test EXIT

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
printf '%s\n' "$socket" >"$FAKE_STATE/daemon.socket"

if [[ "${FAKE_REPLACE_CONFIGURED_FERRO:-0}" == 1 ]]; then
  mv -f -- "$FAKE_REPLACEMENT_FERRO" "$FAKE_CONFIGURED_FERRO"
fi

if [[ "${FAKE_SPAWN_DAEMON_DESCENDANT:-0}" == 1 ]]; then
  setsid env -u FERROCRATE_CONFORMANCE_PROCESS_TOKEN \
    -u FERROCRATE_CONFORMANCE_WRAPPER_TOKEN \
    python3 - "$FAKE_STATE/daemon-descendant.pid" <<'PY' &
import os
import signal
import sys
import time

with open(sys.argv[1], "w", encoding="utf-8") as pid_file:
    pid_file.write(f"{os.getpid()}\n")
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
PY
  for _ in $(seq 1 100); do
    [[ -s "$FAKE_STATE/daemon-descendant.pid" ]] && break
    sleep 0.01
  done
fi

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
printf '%s\t%s\t%s\t%s\t%s\n' \
  "$id" "${DOCKER_HOST:-unset}" "${DOCKER_CONFIG:-unset}" \
  "${DOCKER_BUILDKIT:-unset}" "$*" >>"$FAKE_STATE/docker.calls"

if [[ "$id" == compose-logs && "${FAKE_SPAWN_COMPOSE_DESCENDANT:-0}" == 1 ]]; then
  setsid env -u FERROCRATE_CONFORMANCE_PROCESS_TOKEN \
    -u FERROCRATE_CONFORMANCE_WRAPPER_TOKEN \
    python3 - "$FAKE_STATE/compose-descendant.pid" <<'PY' &
import os
import signal
import sys
import time

with open(sys.argv[1], "w", encoding="utf-8") as pid_file:
    pid_file.write(f"{os.getpid()}\n")
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
PY
  for _ in $(seq 1 100); do
    [[ -s "$FAKE_STATE/compose-descendant.pid" ]] && break
    sleep 0.01
  done
  # Keep the plugin parent present long enough for the ownership tracker to
  # observe the marker-stripping fork before it is reparented.
  sleep 0.5
fi

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

cat >"$fake_bin/mv" <<'FAKE_MV'
#!/usr/bin/env bash
set -euo pipefail

destination="${!#}"
if [[ -n "${FAKE_MV_FAIL_DESTINATION:-}" && "$destination" == "$FAKE_MV_FAIL_DESTINATION" &&
      ! -e "${FAKE_MV_FAILURE_MARKER:?}" ]]; then
  : >"$FAKE_MV_FAILURE_MARKER"
  exit 73
fi
if [[ -n "${FAKE_MV_TERM_DESTINATION:-}" && "$destination" == "$FAKE_MV_TERM_DESTINATION" &&
      ! -e "${FAKE_MV_TERM_MARKER:?}" ]]; then
  : >"$FAKE_MV_TERM_MARKER"
  kill -TERM "$PPID"
  sleep 0.1
  exit 74
fi
exec /usr/bin/mv "$@"
FAKE_MV
chmod +x "$fake_bin/mv"

setsid python3 - "$fake_state/unrelated.pid" <<'PY' &
import os
import signal
import sys
import time

with open(sys.argv[1], "w", encoding="utf-8") as pid_file:
    pid_file.write(f"{os.getpid()}\n")
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
PY
unrelated_pid=$!
for _ in $(seq 1 100); do
  [[ -s "$fake_state/unrelated.pid" ]] && break
  sleep 0.01
done

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
  FAKE_SPAWN_DAEMON_DESCENDANT=1 \
  FAKE_SPAWN_COMPOSE_DESCENDANT=1 \
  FERROCRATE_BIN="$spaced_ferro" \
  DOCKER_HOST="unix://$work_root/caller.sock" \
  DOCKER_CONFIG="$work_root/caller-docker-config" \
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
  actual="$(awk -F '\t' -v wanted="$id" '$1 == wanted { print $5; exit }' "$fake_state/docker.calls")"
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
  actual="$(awk -F '\t' -v wanted="$id" '$1 == wanted { print $5; exit }' "$fake_state/docker.calls")"
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

daemon_socket="$(cat "$fake_state/daemon.socket")"
expected_host="unix://$daemon_socket"
expected_config="${daemon_socket%/runtime/docker.sock}/docker-config"
awk -F '\t' -v host="$expected_host" -v config="$expected_config" '
  $2 != host || $3 != config || $4 != "0" { exit 1 }
' "$fake_state/docker.calls" || {
  echo "a Docker/Compose invocation escaped the isolated endpoint/config/classic-builder contract" >&2
  exit 1
}
awk -F '\t' '$1 == "system-prune" { found = ($2 ~ /^unix:\/\/.*\/runtime\/docker\.sock$/ && $3 ~ /\/docker-config$/ && $4 == "0") } END { exit !found }' \
  "$fake_state/docker.calls"

assert_process_gone() {
  local label="$1" pid_file="$2" pid
  [[ -s "$pid_file" ]] || { echo "$label did not record its PID" >&2; exit 1; }
  pid="$(cat "$pid_file")"
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.01
  done
  echo "$label survived conformance cleanup (pid=$pid)" >&2
  exit 1
}

assert_process_gone "escaped daemon workload" "$fake_state/daemon-descendant.pid"
assert_process_gone "escaped Compose plugin descendant" "$fake_state/compose-descendant.pid"
kill -0 "$unrelated_pid" 2>/dev/null || {
  echo "conformance cleanup touched an unrelated process" >&2
  exit 1
}

source_commit="$(git -C "$repo_root" rev-parse HEAD)"
binary_sha256="$(sha256sum "$spaced_ferro" | awk '{ print $1 }')"
grep -Fq "FerroCrate source commit: \`$source_commit\`" "$scoreboard"
grep -Fq "FerroCrate binary SHA-256: \`$binary_sha256\`" "$scoreboard"

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

# Output names that are lexically different but resolve to the same directory
# entry must be rejected before setup. Otherwise the second publication move
# can silently replace the first member of the evidence pair.
alias_parent="$work_root/alias-parent"
mkdir -p "$alias_parent"
set +e
DOCKER_BUILDKIT=0 FERROCRATE_BIN="$spaced_ferro" \
  "$harness" --output "$alias_parent/score.md" --log "$alias_parent/./score.md" \
  >"$work_root/alias.stdout" 2>"$work_root/alias.stderr"
alias_status=$?
set -e
[[ "$alias_status" == 2 ]]
grep -Fq 'HARNESS ERROR: --output and --log must be different paths' "$work_root/alias.stderr"

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

# The published hash/version must describe the exact executable snapshot that
# launched the daemon, even if the configured path is atomically replaced
# while that daemon is running.
provenance_ferro="$work_root/provenance-ferro"
provenance_replacement="$work_root/provenance-ferro.replacement"
cp "$fake_bin/ferro-cli" "$provenance_ferro"
cat >"$provenance_replacement" <<'REPLACEMENT_FERRO'
#!/usr/bin/env bash
if [[ "${1:-}" == --version ]]; then
  echo "ferrocrate 9.9.9-replacement"
  exit 0
fi
exit 64
REPLACEMENT_FERRO
chmod +x "$provenance_ferro" "$provenance_replacement"
provenance_hash="$(sha256sum "$provenance_ferro" | awk '{ print $1 }')"
provenance_scoreboard="$work_root/provenance-scoreboard.md"
provenance_log="$work_root/provenance.log"
set +e
PATH="$fake_bin:$PATH" \
  FAKE_STATE="$fake_state" \
  FAKE_REPLACE_CONFIGURED_FERRO=1 \
  FAKE_CONFIGURED_FERRO="$provenance_ferro" \
  FAKE_REPLACEMENT_FERRO="$provenance_replacement" \
  FERROCRATE_BIN="$provenance_ferro" \
  DOCKER_BUILDKIT=0 \
  FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS=2 \
  FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS=2 \
  "$harness" --output "$provenance_scoreboard" --log "$provenance_log" >/dev/null
provenance_status=$?
set -e
[[ "$provenance_status" == 1 ]]
grep -Fq "FerroCrate: ferrocrate 0.1.0-contract" "$provenance_scoreboard"
grep -Fq "FerroCrate binary SHA-256: \`$provenance_hash\`" "$provenance_scoreboard"

# Publishing the raw log and rendered scoreboard is one transaction. A failure
# replacing the second member must restore both prior artifacts.
pair_scoreboard="$work_root/pair-scoreboard.md"
pair_log="$work_root/pair.log"
prior_scoreboard_target="$work_root/prior-scoreboard-target"
ln -s "$prior_scoreboard_target" "$pair_scoreboard"
printf 'prior paired log\n' >"$pair_log"
set +e
PATH="$fake_bin:$PATH" \
  FAKE_STATE="$fake_state" \
  FAKE_MV_FAIL_DESTINATION="$pair_log" \
  FAKE_MV_FAILURE_MARKER="$work_root/mv-failed-once" \
  FERROCRATE_BIN="$spaced_ferro" \
  DOCKER_BUILDKIT=0 \
  FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS=2 \
  FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS=2 \
  "$harness" --output "$pair_scoreboard" --log "$pair_log" \
  >"$work_root/pair.stdout" 2>"$work_root/pair.stderr"
pair_status=$?
set -e
[[ "$pair_status" == 2 ]] || {
  echo "expected paired publication failure exit 2, got $pair_status" >&2
  exit 1
}
[[ -L "$pair_scoreboard" && "$(readlink "$pair_scoreboard")" == "$prior_scoreboard_target" ]]
[[ "$(cat "$pair_log")" == "prior paired log" ]]

# A termination between the two installation moves must also roll back both
# members. Command-failure rollback alone is insufficient for a supervised run.
term_pair_scoreboard="$work_root/term-pair-scoreboard.md"
term_pair_log="$work_root/term-pair.log"
printf 'prior terminated scoreboard\n' >"$term_pair_scoreboard"
printf 'prior terminated log\n' >"$term_pair_log"
set +e
PATH="$fake_bin:$PATH" \
  FAKE_STATE="$fake_state" \
  FAKE_MV_TERM_DESTINATION="$term_pair_log" \
  FAKE_MV_TERM_MARKER="$work_root/mv-terminated-once" \
  FERROCRATE_BIN="$spaced_ferro" \
  DOCKER_BUILDKIT=0 \
  FERROCRATE_CONFORMANCE_TIMEOUT_SECONDS=2 \
  FERROCRATE_CONFORMANCE_DAEMON_TIMEOUT_SECONDS=2 \
  "$harness" --output "$term_pair_scoreboard" --log "$term_pair_log" \
  >"$work_root/term-pair.stdout" 2>"$work_root/term-pair.stderr"
term_pair_status=$?
set -e
[[ "$term_pair_status" == 143 ]] || {
  echo "expected terminated publication exit 143, got $term_pair_status" >&2
  exit 1
}
[[ "$(cat "$term_pair_scoreboard")" == "prior terminated scoreboard" ]]
[[ "$(cat "$term_pair_log")" == "prior terminated log" ]]

# The repository's default scoreboard must retain its genuine raw record in a
# tracked, non-ignored location so a clean checkout preserves the evidence chain.
durable_log="$repo_root/docs/evidence/docker-client-conformance/2026-08-23-parity-scoreboard.tsv"
git -C "$repo_root" check-ignore -q "$durable_log" && {
  echo "durable conformance log is ignored: $durable_log" >&2
  exit 1
}
git -C "$repo_root" ls-files --error-unmatch \
  "${durable_log#"$repo_root/"}" >/dev/null
grep -Fq 'docs/evidence/docker-client-conformance/2026-08-23-parity-scoreboard.tsv' \
  "$repo_root/docs/compatibility/parity-scoreboard.md"
grep -Eq 'FerroCrate source commit: `?[0-9a-f]{40}`?' \
  "$repo_root/docs/compatibility/parity-scoreboard.md"
grep -Eq 'FerroCrate binary SHA-256: `?[0-9a-f]{64}`?' \
  "$repo_root/docs/compatibility/parity-scoreboard.md"

bash -n "$harness"
echo "docker client conformance contract tests passed"
