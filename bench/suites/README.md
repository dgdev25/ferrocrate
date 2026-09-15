# Borrowed suites

Runs test suites maintained by Docker projects against Ferrocrate's
Docker-compatible socket. Every failure is a precise upstream reproduction.

```bash
bench/suites/run-suite.sh cli-e2e                  # against Ferrocrate
bench/suites/run-suite.sh cli-e2e --engine docker  # the oracle
bench/suites/run-suite.sh compose-e2e --refresh    # update the checkout first
bench/suites/run-suite.sh critest
```

Results land in `bench/results/<date>/suite-<name>-<engine>.jsonl`.
`bench/scoreboard.py` handles application benchmarks; borrowed suites use
`bench/suite-scoreboard.py`. Result files are overwritten by another run of
the same suite/engine on that date: archive selected files and their hashes
before rerunning.

`<suite>/skip.txt` holds tests that assert Docker-only behaviour this project
declares out of scope. **Every entry must correspond to a row in
`docs/FEATURE-MATRIX.md`.** A skip list is a statement about scope, never a way
to hide a failure; review it on every run.

Sources are cloned to `$SUITE_SRC` (default `/data/dev/bench-suites`) and pinned
by `SUITE_PIN`. Go is required and is expected at `~/.local/go-install/go/bin`.

## Select suite evidence explicitly

The suite scoreboard no longer accepts clone roots or chooses files by mtime.
Create a selection JSON listing **every suite required by the candidate support
matrix**, with the exact result file, its recorded run and head, and the upstream
suite commit. Paths resolve relative to the selection file. For example:

```json
{
  "candidate_head": "FULL_FERROCRATE_COMMIT",
  "suites": {
    "cli-e2e": {
      "suite_head": "FULL_DOCKER_CLI_SUITE_COMMIT",
      "ferrocrate": {
        "path": "results/cli-ferrocrate.jsonl",
        "run": "RECORDED_FERRO_RUN",
        "head": "FULL_FERROCRATE_COMMIT"
      },
      "docker": {
        "path": "results/cli-docker.jsonl",
        "run": "RECORDED_DOCKER_RUN",
        "head": "RECORDED_DOCKER_HARNESS_COMMIT"
      },
      "expected_steps": [{"package": "PACKAGE", "step": "TestRequired"}]
    },
    "critest": {
      "suite_head": "FULL_CRI_TOOLS_SUITE_COMMIT",
      "ferrocrate": {
        "path": "results/cri-ferrocrate.jsonl",
        "run": "RECORDED_CRI_RUN",
        "head": "FULL_FERROCRATE_COMMIT"
      }
    },
    "oci-runtime": {"suite_head": "FULL_RUNTIME_TOOLS_SUITE_COMMIT"}
  }
}
```

Add `sha256` to each selected engine entry to reject replaced result files.
The report always emits the digest of the bytes it actually inspected. The
optional `expected_steps` inventory exposes cases absent on **both** engines;
without it, absent case counts cover only cases observed on Docker. An omitted
result file (as illustrated for OCI) remains an explicit evidence gap. Do not
remove required suites or change support scope to make the report pass.

```bash
python3 bench/suite-scoreboard.py --selection candidate-suites.json
python3 bench/suite-scoreboard.py --selection candidate-suites.json --json > suite-report.json
python3 bench/suite-scoreboard.py --selection candidate-suites.json --check
python3 -m unittest discover -s bench -p 'test_suite_*.py'
```

Rendering a report exits zero even when it contains failures. `--check` exits
one unless the selected suite scope qualifies; malformed selection files exit
two. This is a compatibility evidence gate, not the entire release gate.
The recorded `head` identifies the harness checkout; release qualification must
also attach binary hashes/build provenance and host identity using the release
candidate evidence contract.

Every future runner record carries the full harness `head` and upstream
`suite_head`; Go records preserve package plus test name and mark parent rows
as aggregates. The parser retains failures even if they match `skip.txt`, using
`scope_skip_match` only as a triage annotation. Only an explicit `unsupported`
record with a `reason` and `scope_ref` counts as an unsupported capability.
Ordinary skips remain skips and prevent qualification. Missing terminal Go
events, malformed output, or an empty report produce harness errors.

Observed leaf passes, product failures, shared failures, unpaired failures,
harness errors, unsupported cases, skips and absent cases have separate counts.
Shared failures are **not automatically attributed to the harness**. The
no-oracle column counts leaf cases without a verified passing Docker result
and overlaps observed statuses. Aggregates and suite hooks appear separately,
so they cannot inflate leaf totals. CRI uses its specification contract:
its failures count directly without requiring a Docker endpoint. CRI still
requires matching candidate/upstream provenance and nonempty leaf evidence.

Historical files lack `suite_head`; selecting their paths is useful for raw
triage but cannot qualify them or establish a matching Docker oracle. Do not
invent missing revisions. For R18 reruns, capture the candidate binary identity,
pin the same upstream commit on both engines, preserve the full case inventory,
run each selected suite, and archive both result files before the next run.
For R19, collect a current CRI JSON spec report and an actual OCI result set
for the claimed interface; a summary-only CRI file or skipped OCI marker is
insufficient. Historical passes and failures remain historical observations.
