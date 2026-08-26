#!/bin/bash
# The command matrix. Sourced by run-app.sh; engine-agnostic.
#
# Contract:
#   $CLI        engine command prefix ("ferro-cli" style or "docker")
#   $ENGINE     ferrocrate | docker
#   $APP        manifest name;  $IMG image tag;  $PORT host port;  $CPORT container port
#   $HEALTH     health path;    $VOLS "-v name:/path ..." string;   $CTX build context dir
#   $HAS_COMPOSE 1 when the app has a compose file (provided or generated)
#   $SKIP       space-separated step names to skip (from the manifest)
#   step NAME CMD...   records one JSONL line: {app,engine,step,status,exit,ms,stderr_tail}
#   xfail NAME CMD...  passes only when the command fails
#
# Docker verbs are used throughout; the engine adapter (run-app.sh) maps them
# for the native Ferrocrate CLI until S9 lands.

matrix_run() {
  local url="http://127.0.0.1:${PORT}${HEALTH}"
  local name="bench-${APP}"

  # Engine
  step version        $CLI version
  step info           $CLI info
  step doctor         bash -c "$CLI doctor; true"

  # Image
  step pull-base      $CLI pull "$BASE_IMAGE"
  step build          bash -c "cd '$CTX' && $CLI build $BUILD_FILE_ARG -t '$IMG' ."
  step images         $CLI images
  step image-inspect  $CLI image inspect "$IMG"
  step history        $CLI history "$IMG"
  step tag            $CLI tag "$IMG" "${IMG%:*}:bench-tag"
  step save           bash -c "$CLI save -o '$WORK/image.tar' '$IMG' && test -s '$WORK/image.tar'"
  step rmi-tag        $CLI rmi "${IMG%:*}:bench-tag"
  step load           $CLI load -i "$WORK/image.tar"

  # Lifecycle
  step run-detached   $CLI run -d --name "$name" -p "${PORT}:${CPORT}" $VOLS $ENVS "$IMG"
  step health         bash -c "for i in \$(seq 1 30); do curl -sf -o /dev/null '$url' && exit 0; sleep 1; done; curl -s -o /dev/null -w 'HTTP %{http_code}\n' '$url'; exit 1"
  step ps             $CLI ps -a
  step logs           $CLI logs "$name"
  step inspect        $CLI inspect "$name"
  step top            $CLI top "$name"
  step stats          $CLI stats --no-stream "$name"
  step exec           $CLI exec "$name" sh -c 'echo exec-ok'
  step cp-out         $CLI cp "$name:/etc/hostname" "$WORK/hostname.copy"
  step cp-in          bash -c "echo bench > '$WORK/in.txt' && $CLI cp '$WORK/in.txt' '$name:/tmp/in.txt' && $CLI exec '$name' cat /tmp/in.txt"
  step diff           $CLI diff "$name"
  step pause          $CLI pause "$name"
  step unpause        $CLI unpause "$name"
  step restart        bash -c "$CLI restart '$name' && for i in \$(seq 1 30); do curl -sf -o /dev/null '$url' && exit 0; sleep 1; done; exit 1"
  step stop           $CLI stop "$name"
  step start          bash -c "$CLI start '$name' && for i in \$(seq 1 30); do curl -sf -o /dev/null '$url' && exit 0; sleep 1; done; exit 1"
  step rename         $CLI rename "$name" "${name}-r"
  step commit         $CLI commit "${name}-r" "${IMG%:*}:committed"
  step export         bash -c "$CLI export -o '$WORK/rootfs.tar' '${name}-r' && test -s '$WORK/rootfs.tar'"
  step kill           $CLI kill "${name}-r"
  step wait           timeout 30 $CLI wait "${name}-r"
  step rm             $CLI rm "${name}-r"
  step rmi-committed  $CLI rmi "${IMG%:*}:committed"

  # Data: the first named volume must survive a container replacement
  if [ -n "$FIRST_VOL" ]; then
    step data-write   $CLI run --rm -v "$FIRST_VOL" "$BASE_IMAGE" sh -c "echo persisted > ${FIRST_VOL#*:}/bench.txt"
    step data-read    $CLI run --rm -v "$FIRST_VOL" "$BASE_IMAGE" cat "${FIRST_VOL#*:}/bench.txt"
    step volume-ls    $CLI volume ls
    step volume-inspect $CLI volume inspect "${FIRST_VOL%%:*}"
    step volume-rm    $CLI volume rm "${FIRST_VOL%%:*}"
  fi

  # Network
  step network-ls     $CLI network ls
  step network-create $CLI network create "bench-${APP}-net"
  step network-run    bash -c "$CLI run -d --name '${name}-net' --network 'bench-${APP}-net' '$IMG' && sleep 2 && $CLI rm -f '${name}-net'"
  step network-rm     $CLI network rm "bench-${APP}-net"

  # Compose
  if [ "$HAS_COMPOSE" = 1 ]; then
    step compose-up     bash -c "cd '$CTX' && $COMPOSE up -d --build"
    step compose-health bash -c "for i in \$(seq 1 120); do curl -sf -o /dev/null 'http://127.0.0.1:${COMPOSE_PORT}${HEALTH}' && exit 0; sleep 1; done; curl -s -o /dev/null -w 'HTTP %{http_code} on port ${COMPOSE_PORT}\n' 'http://127.0.0.1:${COMPOSE_PORT}${HEALTH}'; exit 1"
    step compose-ps     bash -c "cd '$CTX' && $COMPOSE ps"
    step compose-logs   bash -c "cd '$CTX' && $COMPOSE logs --tail 20"
    step compose-down   bash -c "cd '$CTX' && $COMPOSE down -v"
  fi

  # Errors: the message must name the cause
  xfail err-bad-image   $CLI run --rm bench-no-such-image-xyz:1
  xfail err-no-container $CLI exec bench-no-such-container ls
  step  err-port-in-use bash -c "$CLI run -d --name '${name}-a' -p '${PORT}:${CPORT}' '$IMG' && ! $CLI run -d --name '${name}-b' -p '${PORT}:${CPORT}' '$IMG' 2>'$WORK/port.err'; r=\$?; $CLI rm -f '${name}-a' '${name}-b' >/dev/null 2>&1; grep -qiE 'port|address|in use' '$WORK/port.err' && exit \$r; echo 'no port wording'; exit 1"

  # Extras
  step events         bash -c "timeout 5 $CLI events; true"
  step system-df      $CLI system df
  step container-prune $CLI container prune -f
  step image-prune    $CLI image prune -f
  step search         $CLI search alpine
}
