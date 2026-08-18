# Ferrocrate support

Ferrocrate is currently a Linux-first project. Support claims follow the
dated qualification records in [`docs/evidence/`](docs/evidence/) and the
consolidated [`docs/ROADMAP.md`](docs/ROADMAP.md); a feature described as
best-effort or host-dependent is not a production-support guarantee.

## Before opening an issue

Please include:

- Ferrocrate version or commit, distribution, kernel, architecture, and
  rootful/rootless mode.
- `ferrocrate doctor --json` output, with credentials and signing material
  removed.
- The relevant command, bounded logs, inspect/events output, and any explicit
  error or capability diagnostic.
- For networking or recovery issues, the backend, runtime directory scope,
  and the matching dated evidence record if one exists.

Do not attach private keys, registry credentials, unrestricted packet captures,
or generated runtime state. See the [support policy](docs/operations/support-policy.md)
for qualification levels, incident requirements, and compatibility/deprecation
rules.

## Security reports

Do not disclose vulnerabilities in a public issue. Follow
[`SECURITY.md`](SECURITY.md) for the private reporting and response process.

## Requests and bugs

- Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) for
  reproducible defects.
- Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md)
  for proposed behavior or compatibility work.
- For contribution questions, read [`CONTRIBUTING.md`](CONTRIBUTING.md).

