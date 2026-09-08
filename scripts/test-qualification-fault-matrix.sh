#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname -- "$0")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/caller-target" "$fixture/elsewhere"
printf 'keep caller data\n' >"$fixture/caller-target/sentinel"
cat >"$fixture/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" == "$EXPECTED_REPO" ]] || { echo "wrong working directory"; exit 9; }
case "${CARGO_FIXTURE_MODE:-pass}" in
  pass) printf 'running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n' ;;
  empty) printf 'running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out\n' ;;
  failed) echo 'fixture failure'; exit 1 ;;
esac
STUB
chmod +x "$fixture/bin/cargo"
export PATH="$fixture/bin:$PATH" EXPECTED_REPO="$repo_root"

run_fixture() {
  (cd "$fixture/elsewhere" &&
    FERROCRATE_QUAL_ROOT=0 FERROCRATE_REPO_ROOT="$repo_root" \
    FERROCRATE_QUAL_TARGET_DIR="$fixture/caller-target" \
    FERROCRATE_QUAL_OUTPUT_DIR="$fixture/$1" FERROCRATE_QUAL_KEEP_TARGET=0 \
    CARGO_FIXTURE_MODE="$2" bash "$repo_root/scripts/qualification-fault-matrix.sh")
}

run_fixture pass pass >"$fixture/pass.log" 2>&1 || {
  cat "$fixture/pass.log" >&2
  echo 'qualification runner must enter the selected repository before invoking cargo' >&2
  exit 1
}
[[ -f "$fixture/caller-target/sentinel" ]] || {
  echo 'qualification runner deleted caller-owned target directory' >&2; exit 1;
}
[[ -s "$fixture/pass/manifest.tsv" && -s "$fixture/pass/provenance.txt" ]] || {
  echo 'qualification runner did not retain manifest and provenance' >&2; exit 1;
}
[[ "$(wc -l <"$fixture/pass/manifest.tsv")" == 7 ]] || {
  echo 'qualification runner did not record all selected rows' >&2; exit 1;
}
if run_fixture empty empty >"$fixture/empty.log" 2>&1; then
  echo 'qualification runner accepted zero selected tests as passing evidence' >&2; exit 1
fi
grep -q $'\tharness-error\t' "$fixture/empty/manifest.tsv"
if run_fixture failed failed >"$fixture/failed.log" 2>&1; then
  echo 'qualification runner accepted a failing cargo command' >&2; exit 1
fi
grep -q $'\tfail\t' "$fixture/failed/manifest.tsv"
[[ -f "$fixture/caller-target/sentinel" ]] || {
  echo 'failure cleanup deleted caller-owned target directory' >&2; exit 1;
}
echo 'qualification-fault-matrix fixtures passed (cwd, target ownership, provenance, zero tests, failure)'
