#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p ferro-core --lib lan_mirror::tests
cargo test -p ferro-cli --bin ferro-cli parses_config_set

grep -Fq '_ferrocrate-registry._tcp.local.' ferro-core/src/lan_mirror.rs
grep -Fq 'X-Ferrocrate-Mirror-Secret' ferro-core/src/image_fetch.rs
grep -Fq 'HTTP/1.1 405 Method Not Allowed' ferro-cli/src/main.rs
grep -Fq 'peer mismatch, falling back to registry' ferro-core/src/image_fetch.rs
grep -Fq 'lan mirror: browsed 5000 ms, 0 peers; unicast /24 probe attempted' ferro-core/src/lan_mirror.rs
grep -Fq 'X-Ferrocrate-Instance' ferro-cli/src/main.rs
grep -Fq 'connect_timeout(Duration::from_millis(200))' ferro-core/src/lan_mirror.rs

echo 'lan image mirror self-test passed'
