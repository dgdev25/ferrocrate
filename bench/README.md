# bench — real-app test bench

Runs the same command matrix against real applications on Docker and on
Ferrocrate and reports parity.

```bash
bench/run-app.sh battleships both     # one app, both engines
bench/run-all.sh                      # every manifest, then the scoreboard
python3 bench/scoreboard.py           # bench/results/SCOREBOARD.md
```

- `apps/<app>/manifest.yaml` — what to clone, how to build, what healthy means
- `templates/<stack>/` — Dockerfile generators for apps without container files
- `matrix.sh` — the steps; `ferro-adapter.sh` — Docker verbs on the native CLI
- `tickets/` — one file per product defect; `triage.md` — the classes
- `GLM.md` and `prompts/` — how the loop runs unattended on GLM
Clones go to `$BENCH_CLONES` (default `/data/dev/bench-apps`).
