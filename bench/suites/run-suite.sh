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

# Several agents share this host. Without an isolated store they terminate each
# other's containers and builds, and without an isolated socket one daemon
# deletes another's socket ("replaced by another inode"). Both look like product
# defects but are collisions.
export FERROCRATE_HOME="${FERROCRATE_HOME:-/path/to/ferrocrate-lab/runtimes/suites}"
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
SOCK="${FERROCRATE_SOCK:-/run/user/1000/ferrocrate-suites.sock}"
FERRO="${FERROCRATE_BIN:-}"
if [ -z "$FERRO" ]; then
  for c in "$BENCH/../target/release/ferro-cli" "$BENCH/../release-artifacts/ferro-cli"; do
    [ -x "$c" ] && FERRO="$c" && break
  done
fi
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

# compose's e2e framework runs the compose CLI as a docker cli-plugin, and
# without bin/build/docker-compose every test that shells out fails on both
# engines — the oracle run then records those as app failures and the diff
# against Ferrocrate shows nothing. Build the binary once with the e2e tag.
if [ "$SUITE" = compose-e2e ] && [ ! -x "$DIR/bin/build/docker-compose" ]; then
  echo "building compose e2e binary"
  ( cd "$DIR" && make build ) > "$WORK/compose-build.log" 2>&1 || { echo "compose build failed; see $WORK/compose-build.log" >&2; exit 2; }
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
    # Launch through a differently named symlink: other agents on this host run
    # `pkill -f '^/.*/ferro-cli daemon'` before testing a rebuilt CLI and that
    # pattern would kill this suite's daemon mid-run. argv[0] must not end in
    # "ferro-cli daemon".
    # This build has no FERROCRATE_HOME: the store root is $HOME/.ferrocrate
    # (verified with strings on the binary), so isolation needs a private HOME.
    # Persistent across runs so image pulls are not repeated against the
    # rate-limited Docker Hub quota; isolated from every other agent's store.
    ln -sf "$FERRO" "$WORK/ferro-suite-engine"
    mkdir -p "$FERROCRATE_HOME/home"
    HOME="$FERROCRATE_HOME/home" "$WORK/ferro-suite-engine" daemon --docker-compat --socket "$SOCK" > "$WORK/daemon.log" 2>&1 &
    DAEMON=$!
    for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
    export DOCKER_HOST="unix://$SOCK"
    # docker/cli's e2e suite reads TEST_DOCKER_HOST, not DOCKER_HOST, and exits
    # before it runs anything when that is unset.
    export TEST_DOCKER_HOST="unix://$SOCK"
    # compose's e2e framework builds the child env from scratch (BaseEnvironment
    # in pkg/e2e/framework.go) and drops DOCKER_HOST; the only host selection it
    # forwards is DOCKER_CONTEXT. Without a context the compose suite silently
    # runs against /var/run/docker.sock on both engines and the diff is empty.
    export DOCKER_CONTEXT="ferro-suite-$$"
    docker context create "$DOCKER_CONTEXT" --docker "host=unix://$SOCK" >/dev/null 2>&1 \
      || { echo "docker context create failed" >&2; exit 2; }
    trap 'kill $DAEMON 2>/dev/null; rm -f "$SOCK"; docker context rm -f "$DOCKER_CONTEXT" >/dev/null 2>&1' EXIT
  fi
else
  unset DOCKER_HOST
  # The oracle run drives the real daemon.
  export TEST_DOCKER_HOST="${DOCKER_ORACLE_HOST:-unix:///var/run/docker.sock}"
  unset DOCKER_CONTEXT
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
  # Suites that spin up a local OCI registry as a process (buildkit's mirror,
  # moby's plugin tests) need a `registry` binary this host has no package
  # for. Extract it once from the registry:2 image through the oracle daemon;
  # every later run reuses the copy.
  ensure_registry_bin() {
    REG="$BENCH/suites/buildkit-dockerfile/bin/registry"
    if [ ! -x "$REG" ]; then
      echo "extracting registry binary from registry:2 (local test registry needs it)"
      mkdir -p "$(dirname "$REG")"
      cid="$(docker create registry:2)" \
        && docker cp "$cid":/bin/registry "$REG" >/dev/null \
        && docker rm "$cid" >/dev/null \
        || { echo "registry extraction failed" >&2; exit 2; }
      chmod +x "$REG"
    fi
  }
  cli-e2e|compose-e2e|moby-integration|buildkit-dockerfile)
    case "$SUITE" in
      cli-e2e)             PKG=./e2e/...;;
      compose-e2e)         PKG=./pkg/e2e/...;;
      # Moby's integration suite is large and restarts the daemon in places; those
      # cases go in skip.txt rather than being worked around. Nightly only.
      moby-integration)    PKG=./integration/...
        # TestMain in every integration package pulls "frozen" fixture images
        # before any test runs, and panics in ~0.1s when it cannot find the
        # list. The loader reads $DOCKERFILE (joined onto the package's parent
        # dir, so a relative name resolves nowhere) and scans it for the
        # RUN download-frozen-image-v2.sh block. Point it at the root
        # Dockerfile, the only one carrying that block.
        export DOCKERFILE="$DIR/Dockerfile"
        # Plugin tests exec a local `registry` binary (no distro package for
        # it); reuse the copy the buildkit suite extracts from registry:2.
        ensure_registry_bin
        export PATH="$(dirname "$REG"):$PATH"
        # Tests that start extra daemons create their data dirs under
        # DOCKER_INTEGRATION_DAEMON_DEST; without it they abort in setup.
        # They spawn the real dockerd, which needs root this host does not
        # give, so they fail on both engines and the oracle diff files them
        # as environment, not product.
        export DOCKER_INTEGRATION_DAEMON_DEST="$WORK/daemon-dest"
        mkdir -p "$DOCKER_INTEGRATION_DAEMON_DEST";;
      # BuildKit's Dockerfile frontend tests reach us through the Buildx docker driver.
      buildkit-dockerfile) PKG=./frontend/dockerfile/...;;
    esac
    # A pinned HEAD whose go.mod has moved ahead of its vendor/ tree makes
    # -mod=vendor abort with "inconsistent vendoring" before any test runs,
    # which the summary reads as zero tests. Probe once and fall back to
    # -mod=mod so the suite runs instead of silently recording nothing.
    MODFLAG="-mod=vendor"
    if ! ( cd "$DIR" && go list -mod=vendor $PKG >/dev/null 2>&1 ); then
      echo "vendor tree out of sync with go.mod; using -mod=mod"
      MODFLAG="-mod=mod"
    fi
    echo "go test $PKG (this takes a while)"
    # BuildKit's harness reaches the engine only through its dockerd worker:
    # TEST_DOCKERD=1 registers it, Moby.New starts a "dockerd" per sandbox and
    # proxies BuildKit gRPC through that daemon's /grpc endpoint (the route the
    # docker-driver uses, and the one Ferrocrate implements). Two obstacles on
    # this host, both solved here instead of in the suite:
    #  1. Moby.New calls requireRoot() and we have no sudo. `unshare -Ur` gives
    #     the test process a user namespace with uid 0, which passes the check.
    #  2. Inside that namespace supplementary groups are gone, so the test
    #     cannot reach the root:docker oracle socket. A user namespace maps the
    #     real uid 1000, so a forwarder owned by uid 1000 IS reachable: the
    #     wrapper runs a "gate" listener outside the namespace and a `dockerd`
    #     shim inside PATH that listens where the harness expects and pipes
    #     every connection to the gate. To the harness it looks like a dockerd
    #     that speaks the Docker API and BuildKit on one socket.
    PRE=()
    if [ "$SUITE" = buildkit-dockerfile ]; then
      ensure_registry_bin
      case "$ENGINE" in
        docker) TARGET="unix:///var/run/docker.sock";;
        *)      TARGET="unix://$SOCK";;
      esac
      GATE="$WORK/gate.sock"
      python3 - "$GATE" "$TARGET" > "$WORK/gate.log" 2>&1 <<'PYEOF' &
import os, socket, sys, threading
gate, target = sys.argv[1], sys.argv[2][len("unix://"):]
try: os.unlink(gate)
except FileNotFoundError: pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(gate); srv.listen(128)
def pump(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            b.sendall(d)
    except OSError: pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass
def handle(c):
    try: u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); u.connect(target)
    except OSError: c.close(); return
    threading.Thread(target=pump, args=(c, u), daemon=True).start()
    pump(u, c)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PYEOF
      GATEPID=$!
      for _ in $(seq 1 50); do [ -S "$GATE" ] && break; sleep 0.1; done
      [ -S "$GATE" ] || { echo "gate did not come up; see $WORK/gate.log" >&2; kill $GATEPID; exit 2; }
      mkdir -p "$WORK/bin"
      cat > "$WORK/bin/dockerd" <<'PYEOF'
#!/usr/bin/env python3
# dockerd replacement for buildkit's integration harness: listens where the
# harness's --host flag says and pipes every connection to BK_GATE. The
# harness pings the socket, talks the Docker API, and hijacks /grpc for
# BuildKit; the engine behind the gate serves all three.
import os, socket, sys, threading
sock, gate, i = None, os.environ["BK_GATE"], 0
args = sys.argv[1:]
while i < len(args):
    if args[i] == "--host" and i + 1 < len(args):
        h = args[i + 1]
        sock = h[len("unix://"):] if h.startswith("unix://") else h
    i += 1
if not sock: sys.exit(1)
try: os.unlink(sock)
except FileNotFoundError: pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock); srv.listen(128)
def pump(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            b.sendall(d)
    except OSError: pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass
def handle(c):
    try: u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); u.connect(gate)
    except OSError: c.close(); return
    threading.Thread(target=pump, args=(c, u), daemon=True).start()
    pump(u, c)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PYEOF
      chmod +x "$WORK/bin/dockerd"
      export BK_GATE="$GATE"
      # Persistent mirror storage: the harness copies every test image from
      # docker.io into a throwaway registry once per run. Docker Hub allows
      # this shared IP 100 manifest requests per rolling hour, so a fresh
      # mirror per leg would spend the quota twice and mid-suite 429s abort
      # the run (panic in lazyMirrorRunnerFunc). BUILDKIT_REGISTRY_MIRROR_DIR
      # keeps the registry's blobs across runs and legs; the copier's
      # "already exists" check then skips the pull entirely.
      export BUILDKIT_REGISTRY_MIRROR_DIR="$BENCH/suites/buildkit-dockerfile/mirror"
      PRE=(unshare -Ur env TEST_DOCKERD=1 PATH="$WORK/bin:$(dirname "$REG"):$PATH")
    fi
    # go test runs t.Parallel tests GOMAXPROCS-wide (32 here). Compose's e2e
    # tests each create a bridge network, and that many concurrent networks
    # exhausts the daemon's default address pools ("all predefined address
    # pools have been fully subnetted") — an env failure that swamps the
    # oracle. Cap parallel tests; 4 leaves headroom in the pool.
    PAR="${GO_TEST_PARALLEL:-4}"
    ( cd "$DIR" && "${PRE[@]}" go test -count=1 "$MODFLAG" -timeout 45m -parallel "$PAR" -json $PKG 2>"$WORK/go.err" ) > "$WORK/go.json" || true
    [ -n "${GATEPID:-}" ] && kill "$GATEPID" 2>/dev/null
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
        # compose's failure cleanup (framework.go:147) lists the whole config
        # dir after the real error and pushes it out of any fixed tail. Drop
        # those lines, keep the last 800 chars of what is left.
        out = "".join(fails.get(name, []))
        out = "".join(l for l in out.splitlines(keepends=True)
                      if "framework.go:147" not in l)
        tail = out[-800:] if status == "fail" else ""
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
      export PATH="$DIR/build/bin:$PATH"
    fi
    CRI_SOCK="unix://$CRI_PATH"
    echo "critest --runtime-endpoint $CRI_SOCK"
    critest --runtime-endpoint "$CRI_SOCK" --ginkgo.noColor > "$WORK/critest.out" 2>&1 || true
    grep -oE "^(•|S|F).*|^ *[0-9]+ (Passed|Failed|Pending|Skipped)" "$WORK/critest.out" | tail -5
    total_pass=$(grep -oE "[0-9]+ Passed" "$WORK/critest.out" | head -1 | grep -oE "[0-9]+" || echo 0)
    total_fail=$(grep -oE "[0-9]+ Failed" "$WORK/critest.out" | head -1 | grep -oE "[0-9]+" || echo 0)
    record "critest-summary" "$([ "${total_fail:-1}" = 0 ] && echo pass || echo fail)" 0 "$(tail -c 400 "$WORK/critest.out")" "${total_fail:-1}"
    echo "critest/$ENGINE: $total_pass passed, $total_fail failed (detail in $WORK/critest.out)"
    ;;
esac

echo "-> $OUT  ($(grep -c '"status":"pass"' "$OUT") pass, $(grep -c '"status":"fail"' "$OUT") fail, $(grep -c '"status":"skip"' "$OUT") skip)"
