#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"
output="$(mktemp)"
fixtures="$(mktemp -d)"
trap 'rm -rf "$output" "$fixtures"' EXIT

if ! bash "$repo_root/scripts/shell-out-audit.sh" >"$output" 2>&1; then
  cat "$output" >&2
  exit 1
fi

grep -q '^shell-out audit: pass$' "$output"
! grep -q 'Command::new' "$output"

# Regression fixtures: the shell-string rule must reject non-literal command
# strings after interpreter flags (-c, -lc, -Command) and must accept literal
# or ALL-CAPS const scripts, including inside #[cfg(test)] regions.
cat >"$fixtures/bad_interpolated.rs" <<'FIXTURE'
fn a() {
    let script = format!("echo {}", user);
    let _ = Command::new("sh").arg("-c").arg(&script).status();
}
FIXTURE
cat >"$fixtures/bad_powershell.rs" <<'FIXTURE'
fn b() {
    let _ = Command::new("powershell.exe").args(["-NoProfile", "-Command", &script]).status();
}
FIXTURE
cat >"$fixtures/bad_dynamic.rs" <<'FIXTURE'
fn c() {
    let _ = sh.args(["-c", script.as_str(), "x"]);
}
FIXTURE

for bad in "$fixtures"/bad_*.rs; do
  only="$(mktemp -d)"
  mv "$bad" "$only/$(basename -- "$bad")"
  if FERROCRATE_SHELLOUT_STRING_SCAN_ROOTS="$only" \
      bash "$repo_root/scripts/shell-out-audit.sh" >/dev/null 2>&1; then
    echo "shell-string gate failed to reject $(basename -- "$bad")" >&2
    exit 1
  fi
  rm -rf "$only"
done

cat >"$fixtures/good_scripts.rs" <<'FIXTURE'
const SCRIPT: &str = "exit 0";
fn d() {
    let _ = Command::new("powershell.exe").args(["-NoProfile", "-Command", SCRIPT]).status();
    let _ = sh.args(["-c", "kill -STOP $$; exec \"$@\"", "n"]).status();
    let _ = sh.arg("-lc").arg("uname -r").status();
}
#[cfg(test)]
mod tests {
    fn e() {
        let command = format!("trap {}", m);
        let _ = sh.args(["-c", &command]);
    }
}
FIXTURE

if ! FERROCRATE_SHELLOUT_STRING_SCAN_ROOTS="$fixtures" \
    bash "$repo_root/scripts/shell-out-audit.sh" >/dev/null 2>&1; then
  echo "shell-string gate rejected vetted fixed-script patterns" >&2
  exit 1
fi

printf '%s\n' 'shell-out audit regression test: pass'
