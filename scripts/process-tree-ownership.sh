#!/usr/bin/env bash
# Linux process-tree ownership helpers for bounded shell harnesses.
#
# A process group is not a sufficient ownership boundary: Compose and workload
# helpers may call setsid(2), and environment markers can be deliberately or
# accidentally removed.  These helpers continuously record descendant
# identities as PID + /proc start time, so cleanup can reap escaped descendants
# without matching or signalling unrelated processes.

ferrocrate_process_identity() {
  local pid="$1" stat_line stat_tail
  local -a stat_fields=()
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  { IFS= read -r stat_line <"/proc/$pid/stat"; } 2>/dev/null || return 1
  stat_tail="${stat_line##*) }"
  read -r -a stat_fields <<<"$stat_tail"
  ((${#stat_fields[@]} >= 20)) || return 1
  [[ "${stat_fields[0]}" != Z ]] || return 1
  printf '%s\t%s\n' "${stat_fields[1]}" "${stat_fields[19]}"
}

ferrocrate_process_matches() {
  local pid="$1" expected_start="$2" identity
  identity="$(ferrocrate_process_identity "$pid")" || return 1
  [[ "${identity#*$'\t'}" == "$expected_start" ]]
}

ferrocrate_track_process_tree() {
  local root_pid="$1" registry="$2" identity pid parent_pid start_time changed
  local snapshot_line
  local -A known=() parents=()

  # Background function subshells can inherit the caller's EXIT trap. A tracker
  # must never recursively run its harness cleanup while it is being stopped.
  trap - EXIT
  trap 'exit 0' TERM INT
  for _ in $(seq 1 100); do
    identity="$(ferrocrate_process_identity "$root_pid")" && break
    sleep 0.002
  done
  [[ -n "${identity:-}" ]] || return 0
  known["$root_pid"]="${identity#*$'\t'}"
  printf '%s\t%s\n' "$root_pid" "${known[$root_pid]}" >>"$registry"

  while :; do
    parents=()
    while read -r pid parent_pid; do
      [[ "$pid" =~ ^[1-9][0-9]*$ && "$parent_pid" =~ ^[0-9]+$ ]] || continue
      parents["$pid"]="$parent_pid"
    done < <(ps -eo pid=,ppid= 2>/dev/null)

    # Retire stale identities before using a PID as an ownership parent. This
    # prevents PID reuse from pulling an unrelated process tree into the set.
    for pid in "${!known[@]}"; do
      ferrocrate_process_matches "$pid" "${known[$pid]}" || unset 'known[$pid]'
    done

    changed=1
    while [[ "$changed" == 1 ]]; do
      changed=0
      for pid in "${!parents[@]}"; do
        [[ -z "${known[$pid]+present}" ]] || continue
        parent_pid="${parents[$pid]}"
        [[ -n "${known[$parent_pid]+present}" ]] || continue
        identity="$(ferrocrate_process_identity "$pid")" || continue
        start_time="${identity#*$'\t'}"
        known["$pid"]="$start_time"
        printf '%s\t%s\n' "$pid" "$start_time" >>"$registry"
        changed=1
      done
    done
    sleep 0.02
  done
}

ferrocrate_start_process_tracker() {
  local root_pid="$1" registry="$2" result_variable="$3" started_tracker_pid
  : >"$registry" || return 1
  ferrocrate_track_process_tree "$root_pid" "$registry" &
  started_tracker_pid=$!
  for _ in $(seq 1 100); do
    [[ -s "$registry" ]] && {
      printf -v "$result_variable" '%s' "$started_tracker_pid"
      return 0
    }
    kill -0 "$started_tracker_pid" 2>/dev/null || break
    sleep 0.002
  done
  kill -TERM "$started_tracker_pid" 2>/dev/null || true
  wait "$started_tracker_pid" 2>/dev/null || true
  return 1
}

ferrocrate_signal_process_registry() {
  local registry="$1" signal="$2" pid start_time
  [[ -r "$registry" ]] || return 0
  while IFS=$'\t' read -r pid start_time; do
    [[ -n "$pid" && -n "$start_time" ]] || continue
    ferrocrate_process_matches "$pid" "$start_time" || continue
    kill "-$signal" "$pid" 2>/dev/null || true
  done <"$registry"
}

ferrocrate_registry_has_live_processes() {
  local registry="$1" pid start_time
  [[ -r "$registry" ]] || return 1
  while IFS=$'\t' read -r pid start_time; do
    [[ -n "$pid" && -n "$start_time" ]] || continue
    ferrocrate_process_matches "$pid" "$start_time" && return 0
  done <"$registry"
  return 1
}

ferrocrate_terminate_process_tree() {
  local tracker_pid="$1" registry="$2" tracker_identity="" tracker_start=""

  # Keep the tracker running while TERM is delivered so descendants forked by
  # shutdown hooks are added to the owned identity set.
  for _ in $(seq 1 50); do
    ferrocrate_registry_has_live_processes "$registry" || break
    ferrocrate_signal_process_registry "$registry" TERM
    sleep 0.02
  done

  # Freeze every survivor before the last tracker snapshots. Once stopped,
  # owned processes cannot fork between the final scan and KILL.
  if ferrocrate_registry_has_live_processes "$registry"; then
    for _ in $(seq 1 3); do
      ferrocrate_signal_process_registry "$registry" STOP
      sleep 0.03
    done
  fi

  if [[ "$tracker_pid" =~ ^[1-9][0-9]*$ ]]; then
    tracker_identity="$(ferrocrate_process_identity "$tracker_pid")" || true
    tracker_start="${tracker_identity#*$'\t'}"
    kill -TERM "$tracker_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      ferrocrate_process_matches "$tracker_pid" "$tracker_start" || break
      sleep 0.01
    done
    if [[ -n "$tracker_start" ]] && ferrocrate_process_matches "$tracker_pid" "$tracker_start"; then
      kill -KILL "$tracker_pid" 2>/dev/null || true
    fi
    wait "$tracker_pid" 2>/dev/null || true
  fi
  ferrocrate_signal_process_registry "$registry" KILL
  return 0
}
