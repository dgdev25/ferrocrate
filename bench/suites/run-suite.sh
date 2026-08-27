#!/bin/bash
# usage: bench/suites/run-suite.sh <cli-e2e|compose-e2e|critest> [--engine ferrocrate|docker] [--refresh]
#
# Runs a suite that Docker's own projects maintain against Ferrocrate's
# Docker-compatible socket, and converts its output into bench result records.
# Source A of docs/testing/TEST-PROGRAM-PLAN.md: the widest coverage per unit of
# effort, because every failure is already a precise reproduction someone else wrote.
#
# Docker is the oracle: run with --engine docker to record what the suite does
# against the real daemon, so a failure on both engines is classified app-or-env
# rather than product.
set -uo pipefail
BENCH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="${1:?cli-e2e | compose-e2e | critest | oci-runtime | moby-integration | buildkit-dockerfile}"; shift || true
ENGINE=ferrocrate; REFRESH=0
while [ $# -gt 0 ]; do case "$1" in --engine) ENGINE="$2"; shift 2;; --refresh) REFRESH=1; shift;; *) shift;; esac; done

# Docker exposes no CRI endpoint, so it cannot act as the oracle for critest.
if [ "$SUITE" = critest ] && [ "$ENGINE" = docker ]; then
  echo "critest has no Docker oracle: Docker exposes no CRI endpoint" >&2; exit 2
fi

SRC="${SUITE_SRC:-/data/dev/bench-suites}"; mkdir -p "$SRC"
export PATH="$HOME/.local/go-install/go/bin:$PATH"
DATE="$(date -u +%Y-%m-%d)"; RUN="$(date -u +%Y-%m-%dT%H:%MZ)"
HEAD="$(git -C "$BENCH/.." rev-parse --short HEAD)"
OUT="$BENCH/results/$DATE/suite-$SUITE-$ENGINE.jsonl"; mkdir -p "$(dirname "$OUT")"; : > "$OUT"
SOCK=/run/user/1000/ferrocrate.sock
FERRO="${FERROCRATE_BIN:-$BENCH/../target/release/ferro-cli}"
WORK="$(mktemp -d /tmp/suite-$SUITE.XXXXXX)"

case "$SUITE" in
  cli-e2e)     REPO=https://github.com/docker/cli;     DIR="$SRC/cli";     PIN="${SUITE_PIN:-master}";;
  compose-e2e) REPO=https://github.com/docker/compose; DIR="$SRC/compose"; PIN="${SUITE_PIN:-main}";;
  critest)     REPO=https://github.com/kubernetes-sigs/cri-tools; DIR="$SRC/cri-tools"; PIN="${SUITE_PIN:-master}";;
  oci-runtime) REPO=https://github.com/opencontainers/runtime-tools; DIR="$SRC/runtime-tools"; PIN="${SUITE_PIN:-main}";;
  moby-integration) REPO=https://github.com/moby/moby; DIR="$SRC/moby"; PIN="${SUITE_PIN:-master}";;
  buildkit-dockerfile) REPO=https://github.com/moby/buildkit; DIR="$SRC/buildkit"; PIN="${SUITE_PIN:-master}";;
  *) echo "unknown suite: $SUITE" >&2; exit 2;;
esac

# --- source ---
if [ ! -d "$DIR/.git" ]; then
  echo "cloning $REPO"; git clone -q --depth 50 "$REPO" "$DIR" || { echo "clone failed" >&2; exit 2; }
fi
[ "$REFRESH" = 1 ] && git -C "$DIR" fetch -q origin && git -C "$DIR" checkout -q "$PIN" 2>/dev/null

# docker/cli ships its module as vendor.mod, so a plain `go test ./e2e/...`
# reports "directory prefix e2e does not contain main module" and the run
# records zero tests, which reads as a clean pass. Link the expected names.
if [ "$SUITE" = cli-e2e ] && [ -f "$DIR/vendor.mod" ] && [ ! -e "$DIR/go.mod" ]; then
  ln -sf vendor.mod "$DIR/go.mod"; ln -sf vendor.sum "$DIR/go.sum"
fi

echo "== $SUITE @ $(git -C "$DIR" rev-parse --short HEAD) on $ENGINE"

# --- engine under test ---
# critest speaks CRI, not the Docker API, so it needs the ferro-cri server on its
# own socket. Every other suite goes through the Docker-compatible socket.
CRI_PATH="${FERROCRATE_CRI_SOCKET:-/run/user/1000/ferrocrate-cri.sock}"
if [ "$ENGINE" = ferrocrate ]; then
  command -v "$FERRO" >/dev/null 2>&1 || [ -x "$FERRO" ] || { echo "no ferro-cli at $FERRO" >&2; exit 2; }
  if [ "$SUITE" = critest ]; then
    CRI_BIN="${FERROCRATE_CRI_BIN:-$BENCH/../target/release/ferro-cri}"
    [ -x "$CRI_BIN" ] || { echo "no ferro-cri at $CRI_BIN; build it first" >&2; exit 2; }
    pkill -f "^$CRI_BIN" 2>/dev/null; rm -f "$CRI_PATH"
    FERROCRATE_CRI_SOCKET="$CRI_PATH" "$CRI_BIN" > "$WORK/daemon.log" 2>&1 &
    DAEMON=$!
    for _ in $(seq 1 100); do [ -S "$CRI_PATH" ] && break; sleep 0.1; done
    [ -S "$CRI_PATH" ] || { echo "ferro-cri did not create $CRI_PATH; see $WORK/daemon.log" >&2; exit 2; }
    trap 'kill $DAEMON 2>/dev/null; rm -f "$CRI_PATH"' EXIT
  else
    pkill -f "^$FERRO daemon" 2>/dev/null; rm -f "$SOCK"
    "$FERRO" daemon --docker-compat --socket "$SOCK" > "$WORK/daemon.log" 2>&1 &
    DAEMON=$!
    for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
    export DOCKER_HOST="unix://$SOCK"
    # docker/cli's e2e suite reads TEST_DOCKER_HOST, not DOCKER_HOST, and exits
    # before it runs anything when that is unset.
    export TEST_DOCKER_HOST="unix://$SOCK"
    trap 'kill $DAEMON 2>/dev/null; rm -f "$SOCK"' EXIT
  fi
else
  unset DOCKER_HOST
  # The oracle run drives the real daemon.
  export TEST_DOCKER_HOST="${DOCKER_ORACLE_HOST:-unix:///var/run/docker.sock}"
fi

# --- skip-list: tests that assert Docker-only behaviour the feature matrix declares
# out of scope. Reviewed, never grown to hide a product failure. ---
SKIPFILE="$BENCH/suites/$SUITE/skip.txt"
skip_re="$( [ -f "$SKIPFILE" ] && grep -vE '^\s*(#|$)' "$SKIPFILE" | paste -sd'|' || true )"

record() { # name status ms tail
  local tail; tail="$(printf '%s' "${4:-}" | tail -c 400 | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read())[1:-1])')"
  printf '{"source":"%s","suite":"%s","engine":"%s","step":"%s","status":"%s","exit":%d,"ms":%d,"stderr_tail":"%s","run":"%s","head":"%s"}\n' \
    "$SUITE" "$SUITE" "$ENGINE" "$1" "$2" "${5:-0}" "${3:-0}" "$tail" "$RUN" "$HEAD" >> "$OUT"
}

# --- run and convert ---
case "$SUITE" in
  cli-e2e|compose-e2e|moby-integration|buildkit-dockerfile)
    case "$SUITE" in
      cli-e2e)             PKG=./e2e/...;;
      compose-e2e)         PKG=./pkg/e2e/...;;
      # Moby's integration suite is large and restarts the daemon in places; those
      # cases go in skip.txt rather than being worked around. Nightly only.
      moby-integration)    PKG=./integration/...;;
      # BuildKit's Dockerfile frontend tests reach us through the Buildx docker driver.
      buildkit-dockerfile) PKG=./frontend/dockerfile/...;;
    esac
    echo "go test $PKG (this takes a while)"
    # -mod=vendor is required by docker/cli, which vendors, and fatal for
    # docker/compose, which does not: it fails with inconsistent vendoring and
    # collects zero tests. Decide per repository.
    MODFLAG=""; [ -d "$DIR/vendor" ] && MODFLAG="-mod=vendor"
    ( cd "$DIR" && go test -count=1 $MODFLAG -timeout 45m -json $PKG 2>"$WORK/go.err" ) > "$WORK/go.json" || true
    if [ ! -s "$WORK/go.json" ]; then
      echo "$SUITE/$ENGINE: go test produced no output; first error follows" >&2
      head -5 "$WORK/go.err" >&2
    fi
    python3 - "$WORK/go.json" "$OUT" "$SUITE" "$ENGINE" "$RUN" "$HEAD" "${skip_re:-__none__}" <<'PY'
import json, re, sys
src, out, suite, engine, run, head, skip = sys.argv[1:8]
skip_re = re.compile(skip) if skip != "__none__" else None
tests, fails = {}, {}
for line in open(src, errors="replace"):
    line = line.strip()
    if not line.startswith("{"): continue
    try: ev = json.loads(line)
    except ValueError: continue
    name = ev.get("Test")
    if not name: continue
    action = ev.get("Action")
    if action in ("pass", "fail", "skip"): tests[name] = action
    elif action == "output": fails.setdefault(name, []).append(ev.get("Output", ""))
with open(out, "a") as fh:
    for name, action in sorted(tests.items()):
        status = {"pass": "pass", "fail": "fail", "skip": "skip"}[action]
        if skip_re and skip_re.search(name): status = "skip"
        tail = "".join(fails.get(name, []))[-400:] if status == "fail" else ""
        fh.write(json.dumps({"source": suite, "suite": suite, "engine": engine, "step": name,
                             "status": status, "exit": 0 if status != "fail" else 1, "ms": 0,
                             "stderr_tail": tail, "run": run, "head": head},
                            separators=(",", ":")) + "\n")
print(f"{suite}/{engine}: {sum(1 for a in tests.values() if a=='pass')} pass, "
      f"{sum(1 for a in tests.values() if a=='fail')} fail, {sum(1 for a in tests.values() if a=='skip')} skip")
if not tests:
    print(f"{suite}/{engine}: collected no tests at all; the suite did not run", file=sys.stderr)
    raise SystemExit(2)
PY
    ;;
  oci-runtime)
    # runtime-tools validates the container the runtime actually produced against
    # the OCI runtime spec: it builds a bundle, runs it through the runtime under
    # test, and inspects the result from inside.
    echo "building runtime-tools validators"
    ( cd "$DIR" && make runtimetest validation-executables ) > "$WORK/build.log" 2>&1 || { echo "runtime-tools build failed; see $WORK/build.log" >&2; exit 2; }
    # runtime-tools invokes an OCI runtime binary directly: create, start,
    # state, delete against a bundle. Ferrocrate has no such binary today, so
    # pointing this at ferro-cli would record false failures rather than real
    # ones. Set OCI_RUNTIME explicitly to run the suite against one.
    RUNTIME="${OCI_RUNTIME:-}"
    if [ -z "$RUNTIME" ]; then
      echo "oci-runtime: skipped — no OCI runtime binary. Set OCI_RUNTIME to run it." >&2
      record "oci-runtime-suite" skip 0 "no OCI runtime binary; Ferrocrate exposes no create/start/state/delete interface" 0
      echo "-> $OUT (skipped)"; exit 0
    fi
    passed=0; failed=0
    for v in "$DIR"/validation/*.t; do
      name="$(basename "$v" .t)"
      if RUNTIME="$RUNTIME" timeout 120 "$v" > "$WORK/$name.out" 2>&1; then
        record "$name" pass 0 "" 0; passed=$((passed+1))
      else
        record "$name" fail 0 "$(tail -c 400 "$WORK/$name.out")" 1; failed=$((failed+1))
      fi
    done
    echo "oci-runtime/$ENGINE: $passed passed, $failed failed"
    ;;
  critest)
    if ! command -v critest >/dev/null 2>&1; then
      echo "building critest"; ( cd "$DIR" && make critest ) >"$WORK/build.log" 2>&1 || { echo "critest build failed; see $WORK/build.log" >&2; exit 2; }
      # cri-tools puts the binary under build/bin/<os>/<arch>, not build/bin.
      CRITEST_BIN="$(find "$DIR/build" -type f -name critest -perm -u+x 2>/dev/null | head -1)"
      [ -n "$CRITEST_BIN" ] || { echo "critest built but no binary found under $DIR/build" >&2; exit 2; }
      export PATH="$(dirname "$CRITEST_BIN"):$PATH"
    fi
    command -v critest >/dev/null 2>&1 || { echo "critest is not runnable" >&2; exit 2; }
    CRI_SOCK="unix://$CRI_PATH"
    echo "critest --runtime-endpoint $CRI_SOCK"
    critest --runtime-endpoint "$CRI_SOCK" --ginkgo.noColor > "$WORK/critest.out" 2>&1 || true
    grep -oE "^(•|S|F).*|^ *[0-9]+ (Passed|Failed|Pending|Skipped)" "$WORK/critest.out" | tail -5
    total_pass=$(grep -oE "[0-9]+ Passed" "$WORK/critest.out" | head -1 | grep -oE "[0-9]+" || echo 0)
    total_fail=$(grep -oE "[0-9]+ Failed" "$WORK/critest.out" | head -1 | grep -oE "[0-9]+" || echo 0)
    # No summary at all means critest never ran. Recording that as a pass is how
    # a suite that never started reads as a clean result.
    if ! grep -qE "[0-9]+ (Passed|Failed)" "$WORK/critest.out"; then
      record "critest-summary" fail 0 "critest produced no summary; it did not run. $(tail -c 300 "$WORK/critest.out")" 2
      echo "critest/$ENGINE: did not run; see $WORK/critest.out" >&2
      echo "-> $OUT"; exit 2
    fi
    record "critest-summary" "$([ "${total_fail:-1}" = 0 ] && echo pass || echo fail)" 0 "$(tail -c 400 "$WORK/critest.out")" "${total_fail:-1}"
    echo "critest/$ENGINE: $total_pass passed, $total_fail failed (detail in $WORK/critest.out)"
    ;;
esac

echo "-> $OUT  ($(grep -c '"status":"pass"' "$OUT") pass, $(grep -c '"status":"fail"' "$OUT") fail, $(grep -c '"status":"skip"' "$OUT") skip)"
