#!/bin/bash
# usage: bench/run-app.sh <app> <ferrocrate|docker|both> [--skip-clone]
# Clones or refreshes the app at its pin, containerises greenfield apps from a
# stack template, runs the matrix, and writes bench/results/<date>/<app>-<engine>.jsonl
set -uo pipefail
BENCH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$BENCH/.." && pwd)"
APP="${1:?app name}"; ENGINES="${2:-both}"; SKIP_CLONE="${3:-}"
MANIFEST="$BENCH/apps/$APP/manifest.yaml"; [ -f "$MANIFEST" ] || { echo "no manifest: $MANIFEST" >&2; exit 2; }
CLONES="${BENCH_CLONES:-/data/dev/bench-apps}"; mkdir -p "$CLONES"
DATE="$(date -u +%Y-%m-%d)"; RUN="$(date -u +%Y-%m-%dT%H:%MZ)"; HEAD="$(git -C "$ROOT" rev-parse --short HEAD)"
OUTDIR="$BENCH/results/$DATE"; mkdir -p "$OUTDIR"

# --- manifest (flat YAML: key: value; lists as [a, b]) ---
m() { sed -n -E "s/^$1:[[:space:]]*(.*)$/\1/p" "$MANIFEST" | head -1 | sed -E 's/^"(.*)"$/\1/'; }
REPO="$(m repo)"; PIN="$(m pin)"; SUBDIR="$(m subdir)"; CLASS="$(m class)"; STACK="$(m stack)"
START="$(m start)"; CPORT="$(m port)"; HEALTH="$(m health)"; HEALTH="${HEALTH:-/}"
DATA_PATHS="$(m data_paths | tr -d '[]' | tr ',' ' ')"; SKIP="$(m skip | tr -d '[]' | tr ',' ' ')"
BASE_IMAGE="$(m base_image)"; ENV_LIST="$(m env | tr -d '{}' | tr ',' ' ')"
DOCKERFILE="$(m dockerfile)"; BUILD_FILE_ARG=""; [ -n "$DOCKERFILE" ] && BUILD_FILE_ARG="-f $DOCKERFILE"
PORT="${BENCH_PORT:-$(( 32000 + $(printf '%s' "$APP" | cksum | cut -d' ' -f1) % 2000 ))}"

# --- source ---
if [[ "$REPO" == /* ]]; then SRC="$REPO"; else
  SRC="$CLONES/$APP"
  if [ -z "$SKIP_CLONE" ]; then
    if [ -d "$SRC/.git" ]; then git -C "$SRC" fetch -q origin && git -C "$SRC" checkout -q "$PIN" 2>/dev/null || git -C "$SRC" checkout -q "origin/$PIN";
    else git clone -q --depth 50 "$REPO" "$SRC" && git -C "$SRC" checkout -q "$PIN" 2>/dev/null || true; fi
  fi
fi
CTX="$SRC${SUBDIR:+/$SUBDIR}"; [ -d "$CTX" ] || { echo "context missing: $CTX" >&2; exit 2; }

# --- containerise greenfield apps from the stack template ---
if [ "$CLASS" = greenfield ]; then
  T="$BENCH/templates/$STACK"; [ -d "$T" ] || { echo "no template for stack $STACK" >&2; exit 2; }
  [ -f "$CTX/Dockerfile" ] || sed -e "s|@START@|$START|g" -e "s|@PORT@|$CPORT|g" -e "s|@BASE@|$BASE_IMAGE|g" "$T/Dockerfile.tmpl" > "$CTX/Dockerfile"
  [ -f "$CTX/.dockerignore" ] || cp "$T/dockerignore" "$CTX/.dockerignore" 2>/dev/null || true
  if [ ! -f "$CTX/compose.yaml" ] && [ ! -f "$CTX/docker-compose.yml" ]; then
    { echo "services:"; echo "  app:"; echo "    build: ."; echo "    ports: [\"$PORT:$CPORT\"]";
      [ -n "$DATA_PATHS" ] && { echo "    volumes:"; for d in $DATA_PATHS; do echo "      - bench_${APP}_$(basename $d):/app/$d"; done; }
      [ -n "$DATA_PATHS" ] && { echo "volumes:"; for d in $DATA_PATHS; do echo "  bench_${APP}_$(basename $d):"; done; }; } > "$CTX/compose.yaml"
  fi
fi
HAS_COMPOSE=0; { [ -f "$CTX/compose.yaml" ] || [ -f "$CTX/docker-compose.yml" ]; } && HAS_COMPOSE=1
# The compose file publishes its own host port; read the first "host:container" mapping unless the manifest sets compose_port.
COMPOSE_PORT="$(m compose_port)"
if [ -z "$COMPOSE_PORT" ] && [ "$HAS_COMPOSE" = 1 ]; then
  cf="$CTX/compose.yaml"; [ -f "$cf" ] || cf="$CTX/docker-compose.yml"
  COMPOSE_PORT="$(grep -oE '"?[0-9]{2,5}:[0-9]{2,5}"?' "$cf" | head -1 | tr -d '"' | cut -d: -f1)"
fi
COMPOSE_PORT="${COMPOSE_PORT:-$PORT}"
VOLS=""; FIRST_VOL=""; for d in $DATA_PATHS; do v="bench_${APP}_$(basename $d):/app/$d"; VOLS="$VOLS -v $v"; [ -z "$FIRST_VOL" ] && FIRST_VOL="$v"; done
ENVS=""; for kv in $ENV_LIST; do ENVS="$ENVS -e ${kv/: /=}"; done
IMG="bench/$APP:latest"

# --- engines ---
run_engine() {
  ENGINE="$1"; WORK="$(mktemp -d /tmp/bench-$APP-$ENGINE.XXXXXX)"; OUT="$OUTDIR/$APP-$ENGINE.jsonl"; : > "$OUT"
  case "$ENGINE" in
    docker)     CLI="docker"; COMPOSE="docker compose";;
    ferrocrate) CLI="$BENCH/ferro-adapter.sh"; COMPOSE="$BENCH/ferro-adapter.sh compose";;
  esac
  export CLI COMPOSE ENGINE APP IMG PORT CPORT HEALTH VOLS ENVS FIRST_VOL CTX WORK HAS_COMPOSE SKIP BASE_IMAGE BUILD_FILE_ARG COMPOSE_PORT
  step() { local name="$1"; shift; local st ex t0 t1 tail
    if [[ " $SKIP " == *" $name "* ]]; then printf '{"app":"%s","engine":"%s","step":"%s","status":"skip","exit":0,"ms":0,"stderr_tail":"manifest skip","run":"%s","head":"%s"}\n' "$APP" "$ENGINE" "$name" "$RUN" "$HEAD" >> "$OUT"; echo "SKIP $name"; return; fi
    t0=$(( ${EPOCHREALTIME/./} / 1000 )); timeout "${STEP_TIMEOUT:-600}" "$@" > "$WORK/$name.out" 2> "$WORK/$name.err"; ex=$?; t1=$(( ${EPOCHREALTIME/./} / 1000 ))
    st=pass; [ $ex -ne 0 ] && st=fail
    tail="$(tail -c 400 "$WORK/$name.err" | tr -d '\000' | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read())[1:-1])')"
    printf '{"app":"%s","engine":"%s","step":"%s","status":"%s","exit":%d,"ms":%d,"stderr_tail":"%s","run":"%s","head":"%s"}\n' "$APP" "$ENGINE" "$name" "$st" "$ex" "$((t1-t0))" "$tail" "$RUN" "$HEAD" >> "$OUT"
    echo "$(echo $st | tr a-z A-Z) $name ($ex, $((t1-t0)) ms)"; }
  xfail() { local name="$1"; shift; if timeout 60 "$@" >/dev/null 2>"$WORK/$name.err"; then
      printf '{"app":"%s","engine":"%s","step":"%s","status":"fail","exit":0,"ms":0,"stderr_tail":"expected an error","run":"%s","head":"%s"}\n' "$APP" "$ENGINE" "$name" "$RUN" "$HEAD" >> "$OUT"; echo "FAIL $name (no error)"
    else printf '{"app":"%s","engine":"%s","step":"%s","status":"pass","exit":1,"ms":0,"stderr_tail":"","run":"%s","head":"%s"}\n' "$APP" "$ENGINE" "$name" "$RUN" "$HEAD" >> "$OUT"; echo "PASS $name (errored)"; fi; }
  # clean state
  $CLI rm -f "bench-$APP" "bench-$APP-r" "bench-$APP-a" "bench-$APP-b" "bench-$APP-net" >/dev/null 2>&1
  $CLI network rm "bench-$APP-net" >/dev/null 2>&1; [ -n "$FIRST_VOL" ] && $CLI volume rm "${FIRST_VOL%%:*}" >/dev/null 2>&1
  echo "== $APP on $ENGINE (port $PORT, ctx $CTX)"
  source "$BENCH/matrix.sh"; matrix_run
  $CLI rm -f "bench-$APP" "bench-$APP-r" >/dev/null 2>&1
  echo "== $APP/$ENGINE: pass=$(grep -c '"status":"pass"' "$OUT") fail=$(grep -c '"status":"fail"' "$OUT") skip=$(grep -c '"status":"skip"' "$OUT") -> $OUT"
  rm -rf "$WORK"
}
case "$ENGINES" in both) run_engine docker; run_engine ferrocrate;; *) run_engine "$ENGINES";; esac
