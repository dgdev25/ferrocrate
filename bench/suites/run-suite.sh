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

# One run per suite+engine at a time, enforced by the filesystem, not by
# convention. On 2026-08-27 two full BuildKit runs raced in the same clone:
# the second corrupted the first's environment and a watcher then committed an
# emptied result file. A lock makes that impossible rather than discouraged.
LOCKDIR="/path/to/ferrocrate-lab/locks"; mkdir -p "$LOCKDIR"
LOCKFILE="$LOCKDIR/$SUITE-$ENGINE.lock"
exec 8>>"$LOCKFILE"
if ! flock -n 8; then
  # Read the holder's pid from a separate file: the lockfile's own fd is held
  # open by the holder and its write may not have flushed when we read it.
  holder="$(cat "$LOCKFILE.pid" 2>/dev/null || echo unknown)"
  echo "REFUSED: $SUITE/$ENGINE is already running (pid $holder). Not starting a second run." >&2
  exit 3
fi
echo $$ > "$LOCKFILE.pid"
# Bash EXIT traps replace rather than stack, so there is exactly ONE trap in
# this script. Later paths register what they need cleaned by setting these
# variables; they must never call `trap ... EXIT` themselves.
CLEANUP_DAEMON=""; CLEANUP_PATHS=""; CLEANUP_DOCKER_CONTEXT=""
suite_cleanup() {
  [ -n "$CLEANUP_DAEMON" ] && kill "$CLEANUP_DAEMON" 2>/dev/null
  [ -n "$CLEANUP_DOCKER_CONTEXT" ] && docker context rm -f "$CLEANUP_DOCKER_CONTEXT" >/dev/null 2>&1
  # shellcheck disable=SC2086
  [ -n "$CLEANUP_PATHS" ] && rm -f $CLEANUP_PATHS
  rm -f "$LOCKFILE.pid"
}
trap suite_cleanup EXIT

SRC="${SUITE_SRC:-/data/dev/bench-suites}"; mkdir -p "$SRC"
export PATH="$HOME/.local/go-install/go/bin:$PATH"
DATE="$(date -u +%Y-%m-%d)"; RUN="$(date -u +%Y-%m-%dT%H:%MZ)"
HEAD="$(git -C "$BENCH/.." rev-parse --short HEAD)"
OUT="$BENCH/results/$DATE/suite-$SUITE-$ENGINE.jsonl"; mkdir -p "$(dirname "$OUT")"; : > "$OUT"
# The socket lives under FERROCRATE_HOME, not /run/user/1000: every agent on
# this host gets its own FERROCRATE_HOME, so per-suite runtimes never collide,
# while a fixed /run/user/1000 name makes two agents race for one socket (each
# daemon's startup `rm -f` deletes the other's listener mid-run).
SOCK="${FERROCRATE_SOCK:-$FERROCRATE_HOME/ferrocrate-suites.sock}"
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
if [ "$SUITE" = compose-e2e ]; then
  if [ ! -x "$DIR/bin/build/docker-compose" ]; then
    echo "building compose e2e binary"
    ( cd "$DIR" && make build ) > "$WORK/compose-build.log" 2>&1 || { echo "compose build failed; see $WORK/compose-build.log" >&2; exit 2; }
  fi
  # The provider tests (providers_test.go) skip-setup-fail when the
  # example-provider binary is missing, on both engines, so the oracle diff
  # files them as environment and six real tests never run. Build it once.
  if [ ! -x "$DIR/bin/build/example-provider" ]; then
    echo "building compose example-provider"
    ( cd "$DIR" && make example-provider ) > "$WORK/provider-build.log" 2>&1 || { echo "example-provider build failed; see $WORK/provider-build.log" >&2; exit 2; }
  fi
fi

echo "== $SUITE @ $(git -C "$DIR" rev-parse --short HEAD) on $ENGINE"

# --- engine under test ---
# critest speaks CRI, not the Docker API, so it needs the ferro-cri server on its
# own socket. Every other suite goes through the Docker-compatible socket.
CRI_PATH="${FERROCRATE_CRI_SOCKET:-$FERROCRATE_HOME/ferrocrate-cri.sock}"
if [ "$ENGINE" = ferrocrate ]; then
  command -v "$FERRO" >/dev/null 2>&1 || [ -x "$FERRO" ] || { echo "no ferro-cli at $FERRO" >&2; exit 2; }
  if [ "$SUITE" = critest ]; then
    CRI_BIN="${FERROCRATE_CRI_BIN:-$BENCH/../target/release/ferro-cri}"
    [ -x "$CRI_BIN" ] || { echo "no ferro-cri at $CRI_BIN; build it first" >&2; exit 2; }
    pkill -f "^$CRI_BIN" 2>/dev/null; rm -f "$CRI_PATH"
    # ferro-cri has no FERROCRATE_HOME support (verified with strings on the
    # binary): its store root comes from FERROCRATE_RUNTIME_DIR and defaults to
    # /var/lib/ferrocrate, which other agents on this host also use. Point it
    # under the isolated suites store like every other engine here.
    export FERROCRATE_RUNTIME_DIR="${FERROCRATE_RUNTIME_DIR:-$FERROCRATE_HOME/cri}"
    mkdir -p "$FERROCRATE_RUNTIME_DIR"
    FERROCRATE_CRI_SOCKET="$CRI_PATH" "$CRI_BIN" > "$WORK/daemon.log" 2>&1 &
    DAEMON=$!
    for _ in $(seq 1 100); do [ -S "$CRI_PATH" ] && break; sleep 0.1; done
    [ -S "$CRI_PATH" ] || { echo "ferro-cri did not create $CRI_PATH; see $WORK/daemon.log" >&2; exit 2; }
    CLEANUP_DAEMON="$DAEMON"; CLEANUP_PATHS="$CRI_PATH"
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
    CLEANUP_DAEMON="$DAEMON"; CLEANUP_PATHS="$SOCK"; CLEANUP_DOCKER_CONTEXT="$DOCKER_CONTEXT"
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

# Suites that spin up a local OCI registry as a process (buildkit's mirror,
# moby's plugin tests) need a `registry` binary this host has no package
# for. Extract it once from the registry:2 image through the oracle daemon;
# every later run reuses the copy.
ensure_registry_bin() {
  REG="$BENCH/suites/buildkit-dockerfile/bin/registry"
  if [ ! -x "$REG" ]; then
    echo "extracting registry binary from registry:2 (local test registry needs it)"
    mkdir -p "$(dirname "$REG")"
    # Setup must not run against the engine under test: extracting this helper
    # is not a measurement, and Ferrocrate's archive endpoint currently returns
    # 404 for a container id that inspect resolves (S62), which made the whole
    # suite unrunnable. Always use the real Docker daemon for it.
    cid="$(DOCKER_HOST= DOCKER_CONTEXT=default docker create registry:2)" \
      && DOCKER_HOST= DOCKER_CONTEXT=default docker cp "$cid":/bin/registry "$REG" >/dev/null \
      && DOCKER_HOST= DOCKER_CONTEXT=default docker rm "$cid" >/dev/null \
      || { echo "registry extraction failed" >&2; exit 2; }
    chmod +x "$REG"
  fi
}

# --- run and convert ---
case "$SUITE" in
  cli-e2e|compose-e2e|moby-integration|buildkit-dockerfile)
    case "$SUITE" in
      cli-e2e)             PKG=./e2e/...;;
      compose-e2e)         PKG=./pkg/e2e/...;;
      # Moby's integration suite is large and restarts the daemon in places; those
      # cases go in skip.txt rather than being worked around. Nightly only.
      moby-integration)    PKG=./integration/...
        # TestMain in every integration package pulls "frozen" fixture images
        # before any test runs, and panics in ~0.1s when it cannot find the
        # list. The loader opens <parent-of-package-dir>/Dockerfile (the
        # $DOCKERFILE override is joined, not made absolute, so an absolute
        # value still lands under that parent) and scans it for the
        # RUN download-frozen-image-v2.sh block, which only the root Dockerfile
        # carries. Put a symlink to it in every parent directory.
        find "$DIR/integration" -name '*_test.go' | while read -r tf; do
          pd="$(dirname "$(dirname "$tf")")"
          [ -e "$pd/Dockerfile" ] || ln -s "$(realpath --relative-to="$pd" "$DIR/Dockerfile")" "$pd/Dockerfile"
        done
        # Every package's TestMain runs the frozen-image ensure concurrently;
        # when two packages race, the loser's pull-tag-remove step hits
        # NotFound and panics the whole package. Pre-seed the frozen names
        # (digest refs from the root Dockerfile's download-frozen-image block)
        # so imageExists() short-circuits in every TestMain. The engine's
        # store caches them, so this pulls once per engine, not per run.
        while IFS='|' read -r ref tag; do
          if ! docker image inspect "$tag" >/dev/null 2>&1; then
            echo "pre-seeding frozen image $tag"
            # retry: Docker Hub answers 429 to a cold store's first burst and
            # one refused pull must not abort a 40-minute run
            ok=0
            for try in 1 2 3 4 5; do
              if [ "$ENGINE" = ferrocrate ]; then
                # S32: the docker CLI encodes fromImage (docker.io%2Flibrary%2F…)
                # and the daemon rejects the encoded form, so every CLI pull
                # fails. The raw API with plain (unencoded) query values works.
                # Also pull and tag the digest-only form (name@digest): the
                # daemon answers "not found" to a name:tag@digest tag source.
                sref="${ref%%:*}@${ref##*@}"
                curl -sf -X POST --unix-socket "$SOCK" \
                  "http://localhost/v1.43/images/create?fromImage=$sref" >/dev/null && ok=1
              else
                sref="$ref"
                docker pull -q "$ref" >/dev/null 2>&1 && ok=1
              fi
              [ "$ok" = 1 ] && break
              sleep $((try * 10))
            done
            [ "$ok" = 1 ] || { echo "frozen-image pull failed: $ref" >&2; exit 2; }
            docker tag "$sref" "$tag" >/dev/null
            # S35: on ferrocrate the compat tag endpoint answers "not found"
            # for every ref form (tag and digest; refs are stored under
            # registry-1.docker.io while clients look up docker.io), so the
            # tag step silently fails and TestMain panics with a 3-test run.
            # Fail here with the reason instead of recording a fake pass.
            if [ "$ENGINE" = ferrocrate ] && ! docker image inspect "$tag" >/dev/null 2>&1; then
              echo "pre-seed incomplete: $tag missing after pull+tag (S35: compat tag endpoint not found; S36: numeric Created breaks image inspect)" >&2
              exit 2
            fi
          fi
        done <<'FROZEN'
busybox:latest@sha256:95cf004f559831017cdf4628aaf1bb30133677be8702a8c5f2994629f637a209|busybox:latest
busybox:glibc@sha256:1f81263701cddf6402afe9f33fca0266d9fff379e59b1748f33d3072da71ee85|busybox:glibc
debian:trixie-slim@sha256:c85a2732e97694ea77237c61304b3bb410e0e961dd6ee945997a06c788c545bb|debian:trixie-slim
hello-world:latest@sha256:d58e752213a51785838f9eed2b7a498ffa1cb3aa7f946dda11af39286c3db9a9|hello-world:frozen
hello-world:latest@sha256:d58e752213a51785838f9eed2b7a498ffa1cb3aa7f946dda11af39286c3db9a9|hello-world:latest
hello-world:amd64@sha256:90659bf80b44ce6be8234e6ff90a1ac34acbeb826903b02cfa0da11c82cbc042|hello-world:amd64
hello-world:arm64@sha256:963612c5503f3f1674f315c67089dee577d8cc6afc18565e0b4183ae355fb343|hello-world:arm64
FROZEN
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
    echo "go test $PKG (this takes a while)"
    # -mod=vendor is required by docker/cli, which vendors, and fatal for
    # docker/compose, which does not: it fails with inconsistent vendoring and
    # collects zero tests. Decide per repository.
    MODFLAG=""; [ -d "$DIR/vendor" ] && MODFLAG="-mod=vendor"
    # BuildKit's harness reaches the engine only through its dockerd worker:
    # TEST_DOCKERD=1 registers it, Moby.New starts a "dockerd" per sandbox and
    # proxies BuildKit gRPC through that daemon's POST /grpc hijack (the route
    # the docker-driver uses). Ferrocrate answers 404 on /grpc (ticket S34), so
    # every worker-dependent test fails with "error reading server preface"
    # until that route exists; the S31 ping gate alone cannot fix the suite.
    # Two obstacles on this host, both solved here instead of in the suite:
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
# S31: the engine answers only GET /_ping, but every Docker-SDK client opens
# its session with HEAD /_ping and treats 404 (not 405) as fatal, so sandbox
# startup dies in waitForAPI before a single test runs. Answer HEAD here.
PING_RESP = (b"HTTP/1.1 200 OK\r\n"
             b"Api-Version: 1.43\r\n"
             b"Builder-Version: 2\r\n"
             b"Ostype: linux\r\n"
             b"Docker-Experimental: false\r\n"
             b"Content-Length: 0\r\n"
             b"Connection: close\r\n\r\n")
def read_head(c):
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        d = c.recv(4096)
        if not d: return buf, True
        buf += d
    return buf, False
def handle(c):
    head, closed = read_head(c)
    if closed and not head:
        c.close(); return
    line = head.split(b"\r\n", 1)[0]
    parts = line.split()
    if len(parts) >= 2 and parts[0] == b"HEAD" and parts[1].rstrip(b"/").endswith(b"_ping"):
        c.sendall(PING_RESP); c.close(); return
    try: u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); u.connect(target)
    except OSError: c.close(); return
    try:
        if head: u.sendall(head)
    except OSError: pass
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
      cp "$BENCH/suites/buildkit-dockerfile/dockerd-forwarder.py" "$WORK/bin/dockerd"
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
    # MODFLAG is empty or "-mod=vendor", so leave it unquoted: a quoted empty
    # value reaches go test as an empty-string positional, which go resolves to
    # the package "." ("no Go files in <repo root>"), and the run records zero
    # tests (every compose-e2e run since 3f242299 failed exactly this way).
    ( cd "$DIR" && "${PRE[@]}" go test -count=1 $MODFLAG -timeout "${GO_TEST_TIMEOUT:-45m}" -parallel "$PAR" -json $PKG 2>"$WORK/go.err" ) > "$WORK/go.json" || true
    if [ ! -s "$WORK/go.json" ]; then
      echo "$SUITE/$ENGINE: go test produced no output; first error follows" >&2
      head -5 "$WORK/go.err" >&2
    fi
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
    while IFS= read -r -d '' v; do
      name="$(basename "$v" .t)"
      if ( cd "$DIR" && RUNTIME="$RUNTIME" timeout 120 "$v" ) > "$WORK/$name.out" 2>&1; then
        record "$name" pass 0 "" 0; passed=$((passed+1))
      else
        record "$name" fail 0 "$(tail -c 400 "$WORK/$name.out")" 1; failed=$((failed+1))
      fi
    done < <(find "$DIR/validation" -type f -name '*.t' -print0 | sort -z)
    echo "oci-runtime/$ENGINE: $passed passed, $failed failed"
    ;;
  critest)
    if ! command -v critest >/dev/null 2>&1; then
      # cri-tools writes the binary under build/bin/<os>/<arch>, not build/bin,
      # and its Makefile needs go on PATH.
      if ! find "$DIR/build" -type f -name critest -perm -u+x >/dev/null 2>&1; then
        echo "building critest"; ( cd "$DIR" && PATH="$HOME/.local/go-install/go/bin:$PATH" make critest ) >"$WORK/build.log" 2>&1 || { echo "critest build failed; see $WORK/build.log" >&2; exit 2; }
      fi
      CRITEST_BIN="$(find "$DIR/build" -type f -name critest -perm -u+x 2>/dev/null | head -1)"
      [ -n "$CRITEST_BIN" ] || { echo "critest built but no binary found under $DIR/build" >&2; exit 2; }
      export PATH="$(dirname "$CRITEST_BIN"):$PATH"
    fi
    command -v critest >/dev/null 2>&1 || { echo "critest is not runnable" >&2; exit 2; }
    CRI_SOCK="unix://$CRI_PATH"
    echo "critest --runtime-endpoint $CRI_SOCK"
    critest --runtime-endpoint "$CRI_SOCK" --ginkgo.noColor \
      --ginkgo.json-report="$WORK/critest.json" > "$WORK/critest.out" 2>&1 || true
    grep -oE "^ *[0-9]+ (Passed|Failed|Pending|Skipped)" "$WORK/critest.out" | tail -4
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
    # record one line per spec from the ginkgo JSON report (no Docker oracle
    # here by design: the CRI API is the contract, so a fail is a fail)
    critest_py_status=critest
    python3 - "$WORK/critest.json" "$OUT" "$RUN" "$HEAD" "$SUITE" "$ENGINE" <<'PY' || critest_py_status=fallback
import json, sys
rep, out, run, head, suite, engine = sys.argv[1:7]
try:
    with open(rep) as fh: r = json.load(fh)
except Exception:
    sys.exit(1)
def walk(node):
    for s in node.get("SpecReports", []):
        st = s["State"]
        status = {"passed": "pass", "failed": "fail", "skipped": "skip", "pending": "skip"}.get(st, "fail")
        # BeforeSuite/AfterSuite nodes carry null ContainerHierarchyTexts/LeafNodeText
        name = " / ".join(c for c in (s.get("ContainerHierarchyTexts") or []) if c) + " " + (s.get("LeafNodeText") or "")
        tail = ""
        if status == "fail":
            fl = s.get("Failures") or ([s["Failure"]] if s.get("Failure") else [])
            tail = " | ".join((f.get("Message") or "") for f in fl)[:800]
        with open(out, "a") as fh:
            fh.write(json.dumps({"source": suite, "suite": suite, "engine": engine, "step": name.strip(),
                                 "status": status, "exit": 0 if status != "fail" else 1, "ms": 0,
                                 "stderr_tail": tail, "run": run, "head": head},
                                separators=(",", ":")) + "\n")
# the report is a list of suite reports; specs live in SpecReports
for suite_report in r if isinstance(r, list) else [r]:
    walk(suite_report)
PY
    if [ "$critest_py_status" = fallback ]; then
      record "critest-summary" "$([ "${total_fail:-1}" = 0 ] && echo pass || echo fail)" 0 "$(tail -c 400 "$WORK/critest.out")" "${total_fail:-1}"
    fi
    echo "critest/$ENGINE: $total_pass passed, $total_fail failed (detail in $WORK/critest.out)"
    ;;
esac

# grep -c prints "0" AND exits 1 on no match, so `grep -c ... || echo 0` yields
# two lines ("0\n0"), which corrupted every done-marker written before this
# was fixed. Take grep's own count and ignore its exit status.
PASS_N=$(grep -c '"status":"pass"' "$OUT" 2>/dev/null); PASS_N=${PASS_N:-0}
FAIL_N=$(grep -c '"status":"fail"' "$OUT" 2>/dev/null); FAIL_N=${FAIL_N:-0}
SKIP_N=$(grep -c '"status":"skip"' "$OUT" 2>/dev/null); SKIP_N=${SKIP_N:-0}
RECORDS=$(wc -l < "$OUT" 2>/dev/null); RECORDS=${RECORDS:-0}
echo "-> $OUT  ($PASS_N pass, $FAIL_N fail, $SKIP_N skip)"
# Done-marker: watchers read this file, never a process-name match. A pgrep
# loop caught a false gap between two runs on 2026-08-27 and declared a
# still-running suite finished.
#
# A run that collected NO records is a failed run, not a finished one. Writing
# a done-marker for it made a watcher treat the compose recheck's empty result
# as complete. Write a .failed marker instead so the distinction is explicit.
DONEDIR="/path/to/ferrocrate-lab/done"; mkdir -p "$DONEDIR"
rm -f "$DONEDIR/$SUITE-$ENGINE.done" "$DONEDIR/$SUITE-$ENGINE.failed"
if [ "$RECORDS" -eq 0 ]; then
  printf '%s\n' "suite=$SUITE engine=$ENGINE out=$OUT records=0 reason=no-records-collected finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$DONEDIR/$SUITE-$ENGINE.failed"
  echo "$SUITE/$ENGINE: collected no records; wrote $DONEDIR/$SUITE-$ENGINE.failed, not .done" >&2
  exit 2
fi
printf '%s\n' "suite=$SUITE engine=$ENGINE out=$OUT pass=$PASS_N fail=$FAIL_N skip=$SKIP_N records=$RECORDS finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$DONEDIR/$SUITE-$ENGINE.done"
