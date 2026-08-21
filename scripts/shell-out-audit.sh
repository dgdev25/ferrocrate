#!/usr/bin/env bash
set -euo pipefail

repo_root="${FERROCRATE_REPO_ROOT:-$(cd "$(dirname -- "$0")/.." && pwd)}"

# Production process-spawn scan. Two rules:
#
# 1. ferro-net/ferro-netd network mutation must flow through
#    ferro-net::executor; executor.rs is the one intentional implementation of
#    that boundary. Test fixtures and build scripts are not runtime mutation
#    paths and are deliberately outside this scan.
#
# 2. No shell-string spawn with non-literal command text. Any interpreter
#    command-string flag (-c, -lc, -Command) must be followed by a Rust string
#    literal or an ALL-CAPS const/static identifier. A `const`/`static` &str
#    cannot embed runtime interpolation, so both forms are injection-safe by
#    construction. `#[cfg(test)]` regions are skipped; they are fixtures, not
#    process boundaries.
scan_roots=("${FERROCRATE_SHELLOUT_SCAN_ROOTS:-}")
if ((${#scan_roots[@]} == 0)); then
  scan_roots=(
    "$repo_root/ferro-net/src"
    "$repo_root/ferro-netd/src"
  )
fi
violations=()

while IFS= read -r match; do
  [[ -z "$match" ]] && continue
  file="${match%%:*}"
  case "$file" in
    */ferro-net/src/executor.rs) ;;
    *) violations+=("$match") ;;
  esac
done < <(
  grep -rnE --include='*.rs' \
    'Command::new|std::process::Command|(^|[[:space:]])(sh|bash)[[:space:]]+-c' \
    "$repo_root/ferro-net/src" "$repo_root/ferro-netd/src" || true
)

string_scan_roots=("${FERROCRATE_SHELLOUT_STRING_SCAN_ROOTS:-}")
if ((${#string_scan_roots[@]} == 0)); then
  string_scan_roots=(
    "$repo_root/ferro-core/src"
    "$repo_root/ferro-cli/src"
    "$repo_root/ferro-desktop/src"
    "$repo_root/ferro-mgr/src"
    "$repo_root/ferro-net/src"
    "$repo_root/ferro-netd/src"
    "$repo_root/ferro-cri/src"
    "$repo_root/ferro-mind/src"
    "$repo_root/ferro-compose/src"
  )
fi
existing_roots=()
for root in "${string_scan_roots[@]}"; do
  [[ -d "$root" ]] && existing_roots+=("$root")
done

if ((${#existing_roots[@]} != 0)); then
  while IFS= read -r match; do
    [[ -z "$match" ]] && continue
    violations+=("$match")
  done < <(
    find "${existing_roots[@]}" -name '*.rs' -print0 2>/dev/null |
      xargs -0 -r perl -e '
        use strict; use warnings;
        for my $file (@ARGV) {
            open my $fh, "<", $file or die "open $file: $!";
            local $/; my $src_all = <$fh>; close $fh;
            # Skip #[cfg(test)] fixture regions at the tail of the file.
            my $cut = index($src_all, "#[cfg(test)]");
            my $src = $cut >= 0 ? substr($src_all, 0, $cut) : $src_all;
            while ($src =~ /("(?:-l?c|-Command)")(\s*,\s*|\s*\)\s*\.arg\(\s*)(.{0,40})/gs) {
                my ($flag, $next) = ($1, $3);
                my $at = $-[0];
                my $line_start = rindex($src, "\n", $at) + 1;
                my $prefix = substr($src, $line_start, $at - $line_start);
                next if $prefix =~ m{^\s*//};
                my $head = substr($src, 0, $at);
                my $lineno = 1 + ($head =~ tr/\n//);
                if ($next !~ /^("|[A-Z_][A-Z0-9_]*\b)/) {
                    printf "%s:%d: non-literal command string after interpreter flag %s (next: %.20s)\n",
                        $file, $lineno, $flag, $next;
                }
            }
        }
      '
  )
fi

if ((${#violations[@]} != 0)); then
  printf '%s\n' 'shell-out audit: fail' >&2
  printf '%s\n' "${violations[@]}" >&2
  exit 1
fi

printf '%s\n' 'shell-out audit: pass'
