# Performance baseline evidence

`scripts/perf/run-baseline.sh` collects the repository's startup, pull, build,
idle daemon, idle no-daemon, per-container RSS, binary size, AI latency, Docker
API, OCI, and rootless prerequisite measurements into
`target/perf-baseline/`. `manifest.tsv` records each benchmark result and the
individual logs retain the emitted `perf.*` metrics and configured SLOs.

Collection defaults to `FERROCRATE_PERF_ALLOW_SKIP=1` and
`FERROCRATE_PERF_ENFORCE=0` so a host row can record missing privileged
prerequisites without hiding the result. Release qualification uses:

```bash
FERROCRATE_PERF_REQUIRE_ALL=1 \
  bash scripts/perf/verify-baseline.sh
```

That mode rejects skipped benchmarks and missing rootless helpers. A baseline
is evidence for one host/kernel row; it is not a cross-distribution or
cross-platform performance claim. Threshold values remain the SLO values
printed by each benchmark and must be reviewed when hardware or workload
profiles change.
