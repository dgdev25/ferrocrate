# Docker/Compose migration report

`ferrocrate migrate compose-report --file compose.yaml --output report.json`
parses and validates a Compose file, resolves the same environment
interpolation used by Compose execution, computes dependency-order batches, and
writes a sanitized migration plan. It is deliberately report-only: it does not
pull images, create containers, alter networks, or remove Docker state.

The report includes service image/build sources, port/volume counts, declared
networks, restart/profile metadata, dependency order, and a `manual_review`
list. Host/service network modes, deploy constraints, and services without an
image or build source are explicitly flagged. Review the report, back up the
source workload, and perform execution as a separately authorized change.

The report schema is versioned as `ferrocrate/migration-report/v1` so future
execution tooling can reject incompatible plans instead of silently guessing.
Network and volume names are sorted, and identical input produces byte-stable
output suitable for review diffs and signed change records.
