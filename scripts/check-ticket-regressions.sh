#!/bin/bash
# A ticket status must never move backward relative to its own history: closed
# or resolved must not become open or reopened. This happened three times on
# 2026-08-27 because a merge picks one side's file wholesale, and nothing
# checked whether that side was stale.
#
# Usage: scripts/check-ticket-regressions.sh [ref]   (default: HEAD)
set -uo pipefail
REF="${1:-HEAD}"
CLOSED_RE='status: *(closed|resolved|fixed)'
OPEN_RE='status: *(open|reopened|partial fix)'
fail=0
for f in bench/tickets/S*.md; do
  name="$(basename "$f")"
  current="$(git show "$REF:$f" 2>/dev/null | grep -m1 -oE 'status: *[a-z A-Z()-]+' || true)"
  echo "$current" | grep -qE "$OPEN_RE" || continue
  # Has any ancestor of $REF that touched this file recorded a closed status?
  if git log "$REF" --oneline -- "$f" 2>/dev/null | while read -r commit _; do
       git show "$commit:$f" 2>/dev/null | grep -m1 -oE 'status: *[a-z A-Z()-]+'
     done | grep -qE "$CLOSED_RE"; then
    echo "REGRESSION: $name is '$current' at $REF but was closed at an earlier commit on this line of history" >&2
    fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "no ticket status regressions"
exit "$fail"
