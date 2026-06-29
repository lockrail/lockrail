#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p scan-logs
LOG="scan-logs/full-scan-$(date +%Y%m%d-%H%M%S).log"
LATEST="scan-logs/latest.log"
exec > >(tee "$LOG") 2>&1
ln -sf "$(basename "$LOG")" "$LATEST"

printf '== Lockrail full scan ==\n'
printf 'root=%s\n' "$ROOT"
printf 'time=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
printf '\n== toolchain ==\n'
command -v cargo || true
cargo --version || true
rustc --version || true

status=0
run() {
  printf '\n== %s ==\n' "$*"
  "$@"
  code=$?
  printf 'exit=%s\n' "$code"
  if [ "$code" -ne 0 ]; then status=1; fi
}

run cargo metadata --no-deps --format-version 1
run cargo fmt --all -- --check
run cargo check --workspace
run cargo test --workspace
run cargo build --workspace
if cargo clippy --version >/dev/null 2>&1; then
  run cargo clippy --workspace --all-targets -- -D warnings
else
  printf '\n== clippy ==\nnot installed/available\n'
fi

printf '
== hygiene scan ==
'
if ./scripts/hygiene-scan.py; then
  printf 'ok
'
else
  status=1
fi

printf '\n== final status ==\n%s\n' "$status"
exit "$status"
