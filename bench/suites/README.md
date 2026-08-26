# Borrowed suites

Source A of `docs/testing/TEST-PROGRAM-PLAN.md`: run the test suites Docker's own
projects maintain against Ferrocrate's Docker-compatible socket. The widest
coverage per unit of effort, because every failure is a precise reproduction
somebody else already wrote.

```bash
bench/suites/run-suite.sh cli-e2e                  # against Ferrocrate
bench/suites/run-suite.sh cli-e2e --engine docker  # the oracle
bench/suites/run-suite.sh compose-e2e --refresh    # update the checkout first
bench/suites/run-suite.sh critest
```

Results land in `bench/results/<date>/suite-<name>-<engine>.jsonl` in the same
record shape as the app bench, so `scoreboard.py` reads them without changes.

`<suite>/skip.txt` holds tests that assert Docker-only behaviour this project
declares out of scope. **Every entry must correspond to a row in
`docs/FEATURE-MATRIX.md`.** A skip list is a statement about scope, never a way
to hide a failure; review it on every run.

Sources are cloned to `$SUITE_SRC` (default `/data/dev/bench-suites`) and pinned
by `SUITE_PIN`. Go is required and is expected at `~/.local/go-install/go/bin`.
