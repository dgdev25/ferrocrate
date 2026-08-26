# Tickets

One file per product defect: `S<n>.md` for the seed set, `T<yyyymmdd>-<n>.md`
for bench-found ones. Fields: app, step, command, Docker output, Ferrocrate
output, first seen, class, status (open | fixed-pending-retest | closed), and
the retest result line when closed. Only `bench/scoreboard.py` output and
these files feed the fix loop.
