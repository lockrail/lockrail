#!/usr/bin/env bash
# Local quality gate: fmt, clippy, tests, cargo-deny (if installed), release build.
# Every step must pass; a missing optional tool is reported, never silently skipped.
set -euo pipefail
cd "$(dirname "$0")/.."

HEAVY="${LOCKRAIL_HEAVY:-$HOME/.claude-alt/hooks/heavy.sh}"
run() {
  if [ -x "$HEAVY" ] || [ -f "$HEAVY" ]; then bash "$HEAVY" "$@"; else "$@"; fi
}

step() { printf '\n== %s\n' "$*"; }

step "rustfmt"
cargo fmt --all --check

step "clippy (-D warnings)"
run cargo clippy --workspace --all-targets --locked -- -D warnings

step "tests"
run cargo test --workspace --locked 2>&1 | tee target/gate-test.log
passed=$(grep -E '^test result: ok' target/gate-test.log | awk '{s+=$4} END {print s+0}')
failed=$(grep -E '^test result:' target/gate-test.log | awk '{s+=$6} END {print s+0}')
echo "tests passed=${passed} failed=${failed}"
[ "$failed" -eq 0 ]

step "cargo-deny"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check
else
  echo "cargo-deny NOT INSTALLED - this gate step did not run (install: cargo install --locked cargo-deny)"
  [ "${LOCKRAIL_REQUIRE_DENY:-0}" = 1 ] && exit 1
fi

step "release build"
run cargo build --workspace --release --locked

echo
echo "gate: OK (tests passed=${passed})"
