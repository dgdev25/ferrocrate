#!/bin/bash
# Maps Docker verbs onto the native Ferrocrate CLI so the matrix can use one
# vocabulary. Each mapping is a known gap (ticket S9 / S1); delete a case here
# when the CLI accepts the Docker form natively.
F="${FERROCRATE_BIN:-/data/dev/ferrocrate/target/release/ferro-cli}"
case "$1" in
  ps)        shift; exec "$F" containers "$@" ;;
  image)     shift; case "$1" in
               inspect) shift; exec "$F" image-inspect "$@" ;;
               prune)   shift; exec "$F" image-prune --force ;;
               ls|list) shift; exec "$F" images "$@" ;;
               rm)      shift; exec "$F" rmi "$@" ;;
               *) exec "$F" image "$@" ;; esac ;;
  container) shift; case "$1" in
               prune)   shift; exec "$F" container-prune --force ;;
               ls|list) shift; exec "$F" containers "$@" ;;
               *) exec "$F" "$@" ;; esac ;;
  system)    shift; case "$1" in df) exec "$F" system-df ;; *) exec "$F" system "$@" ;; esac ;;
  build)     shift; args=(); ctx=""; while [ $# -gt 0 ]; do case "$1" in -t|--tag) args+=("$1" "$2"); shift 2 ;; -f|--file) args+=(--dockerfile "$2"); shift 2 ;; -*) args+=("$1"); shift ;; *) ctx="$1"; shift ;; esac; done
             [ -n "$ctx" ] && cd "$ctx"; [[ " ${args[*]} " == *" --dockerfile "* ]] || args+=(--dockerfile Dockerfile); exec "$F" build "${args[@]}" ;;
  export)    shift; if [ "$1" = -o ]; then out="$2"; shift 2; exec "$F" export "$@" > "$out"; fi; exec "$F" export "$@" ;;
  rm)        shift; force=0; names=(); for a in "$@"; do case "$a" in -f|--force) force=1 ;; *) names+=("$a") ;; esac; done
             if [ $force = 1 ]; then for n in "${names[@]}"; do "$F" kill "$n" >/dev/null 2>&1; done; fi; exec "$F" rm "${names[@]}" ;;
  *)         exec "$F" "$@" ;;
esac
