# Triage rules

One class per failed step. `scoreboard.py` assigns the first three automatically; a person or model confirms before a ticket is opened.

| Class | Rule | Action |
|---|---|---|
| product | Docker passes, Ferrocrate fails or differs | ticket |
| app-or-env | both engines fail | inspect: app broken at pin -> skip with note; host problem -> fix host, re-run |
| boundary | step is in the manifest `skip` list and matches a row in docs/FEATURE-MATRIX.md | none; if no matrix row exists it is product |
| flake | passes on an immediate re-run | count; three in a week for the same step -> ticket |
| unpaired | no Docker result for the step | run Docker again |

Re-run a single app and engine with `bench/run-app.sh <app> ferrocrate --skip-clone`.
