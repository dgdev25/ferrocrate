#!/usr/bin/env bash
# FerroCrate launcher. --preview serves the UI for visual checks; default starts
# the real desktop bridge using the repository's existing dev launcher.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"
FRONTEND_PORT="47600"
mode=web
rebuild=0
for arg in "$@"; do
  case "$arg" in
    --preview) mode=preview ;;
    --existing-bridge) mode=existing ;;
    --prod) mode=prod ;;
    --rebuild) rebuild=1 ;;
    --stop)
      if [[ -f logs/start.pid ]]; then
        pid="$(cat logs/start.pid)"
        if [[ "$pid" =~ ^[0-9]+$ ]] && [[ -r "/proc/$pid/cmdline" ]] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$root/start.sh"; then
          kill -TERM "$pid"
        fi
      fi
      exit 0 ;;
    --reset-ports) sed -i 's/^FRONTEND_PORT="[0-9]*"/FRONTEND_PORT=""/' "$root/start.sh"; exit 0 ;;
    --help) echo 'Usage: ./start.sh [--preview|--prod|--existing-bridge] [--rebuild|--stop|--reset-ports]'; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done
for tool in node npm curl python3; do command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 2; }; done
if [[ -z "$FRONTEND_PORT" ]]; then
  FRONTEND_PORT="$(python3 - <<'PY'
import socket
for port in range(47600, 47700):
    with socket.socket() as sock:
        try:
            sock.bind(('127.0.0.1', port))
        except OSError:
            continue
        print(port)
        break
else:
    raise SystemExit('No available frontend port')
PY
)"
  sed -i "s/^FRONTEND_PORT=\"\"/FRONTEND_PORT=\"$FRONTEND_PORT\"/" "$root/start.sh"
fi
mkdir -p logs
ui="$root/apps/ferro-desktop-ui"
if [[ ! -d "$ui/node_modules" || "$ui/package-lock.json" -nt "$ui/node_modules/.package-lock.json" ]]; then npm ci --prefix "$ui"; fi
if [[ "$mode" == prod || "$rebuild" == 1 ]]; then npm run --prefix "$ui" build; fi
child=""
cleanup() {
  if [[ -n "$child" ]]; then kill -TERM -- "-$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
  rm -f logs/start.pid
}
trap cleanup EXIT
trap 'exit 130' INT TERM
command -v setsid >/dev/null || { echo 'setsid is required for owned process cleanup' >&2; exit 2; }
echo $$ > logs/start.pid
case "$mode" in
  preview) setsid npm run --prefix "$ui" dev -- --host 127.0.0.1 --port "$FRONTEND_PORT" > logs/frontend.log 2>&1 & ;;
  prod) setsid npm run --prefix "$ui" preview -- --host 127.0.0.1 --port "$FRONTEND_PORT" --strictPort > logs/frontend.log 2>&1 & ;;
  existing)
    [[ -x "$ui/src-tauri/target/debug/ferro-desktop-ui" ]] || { echo 'Existing bridge missing; run default launcher to build' >&2; exit 2; }
    export FERROCRATE_RUNTIME_DIR="${FERROCRATE_RUNTIME_DIR:-$root/target/closeout-ui-runtime}"
    mkdir -p "$FERROCRATE_RUNTIME_DIR"
    export PATH="$root/target/debug:$root/target/release:$PATH"
    if [[ -f "$HOME/.ferrocrate/dev/entitlement.pub" ]]; then
      export FERROCRATE_ENTITLEMENT_FILE="$HOME/.ferrocrate/dev/entitlement.lic"
      export FERROCRATE_ENTITLEMENT_PUBKEY="$(cat "$HOME/.ferrocrate/dev/entitlement.pub")"
    fi
    setsid "$ui/src-tauri/target/debug/ferro-desktop-ui" --web --listen "127.0.0.1:$FRONTEND_PORT" > logs/frontend.log 2>&1 & ;;
  web) setsid bash scripts/dev-desktop.sh --web --listen "127.0.0.1:$FRONTEND_PORT" > logs/frontend.log 2>&1 & ;;
esac
child=$!
ready=0
for ((attempt=0; attempt<60; attempt++)); do
  kill -0 "$child" 2>/dev/null || { echo 'Launcher exited; see logs/frontend.log' >&2; exit 1; }
  if curl -fsS --max-time 2 "http://127.0.0.1:$FRONTEND_PORT/" >/dev/null; then ready=1; break; fi
  sleep .5
done
[[ "$ready" == 1 ]] || { echo 'HTTP startup timed out; see logs/frontend.log' >&2; exit 1; }
printf '+-------------------------------------------------------+\n'
printf '| FerroCrate %-42s |\n' "$mode"
printf '| UI: %-49s |\n' "http://localhost:$FRONTEND_PORT"
printf '| Logs: logs/frontend.log; stop: ./start.sh --stop       |\n'
printf '+-------------------------------------------------------+\n'
if [[ "$mode" == existing ]]; then
  echo '[info] Existing backend with current frontend; final candidate validation requires a fresh backend build.'
elif [[ "$mode" != web ]]; then
  echo '[info] Visual preview: backend-dependent actions need the real desktop bridge.'
fi
wait "$child"
