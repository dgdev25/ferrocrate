# FerroCrate release process

Use the tag-triggered GitHub Actions workflow on self-hosted `ferro-lab`
runners to qualify a release candidate. The workflow requires both candidate
validation and candidate qualification before it can publish.

Do not publish a release while any required row in the production readiness
roadmap is failed, blocked, or not run.

## Candidate procedure

1. Select the exact commit and version.
2. Run the required candidate gate on the qualified host:

   ```bash
   bash scripts/local-release-gate.sh --version vX.Y.Z
   ```

3. Build platform artifacts through the release workflow. It applies the
   platform signing steps and creates `SHA256SUMS` and `latest.json`.
4. Verify each signed installer and updater payload on its advertised platform.
5. Review the evidence bundle against the candidate support matrix.
6. A maintainer approves the GitHub publication after all required rows pass.

Local commands prepare artifacts only. They do not prove native signing,
install, update, rollback, runtime fault handling, or desktop interaction.

## Required signing material

The release workflow needs the protected signing credentials described in
[`SIGNING.md`](release/SIGNING.md). Do not replace a missing trusted Apple or
Windows identity with a self-signed certificate.

## Legacy helper

`scripts/build-and-release.sh` is a legacy local helper. It creates local
artifacts and a local Git tag. It does not push a tag or create a GitHub
release. Do not use it as the production release procedure.

## Evidence and support

- [Candidate support matrix](operations/candidate-support-2026-09-05.md)
- [Local release-gate contract](operations/local-release-gate.md)
- [Production readiness roadmap](PRODUCTION-READINESS-ROADMAP-2026-09-05.md)
- [Release artifact contract](release-artifacts.md)
