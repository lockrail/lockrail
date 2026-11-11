#!/usr/bin/env bash
# install.sh fail-closed test (PLAN.md GATE 8, D7).
#
#   bash scripts/test-install.sh [path/to/install.sh]
#
# Drives the installer against local fixtures with no network: a fake `curl` on PATH maps the
# GitHub URLs to fixture files, a fake `minisign` accepts only a signature naming the binary's
# sha256, and HOME/LOCKRAIL_INSTALL point at a temp dir. Works on the 0.3.7 script unchanged, so
# the same cases red-test it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$(cd "$(dirname "${1:-$ROOT/install.sh}")" && pwd)/$(basename "${1:-$ROOT/install.sh}")"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lockrail-install-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) TARGET="aarch64-apple-darwin" ;;
  Darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
  Linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
  *) echo "unsupported host for this test"; exit 2 ;;
esac
ART="lockrail-${TARGET}"

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# stubs: curl, minisign; a tools dir without sha256 programs for the no-sha case.
STUB="$WORK/stub"; mkdir -p "$STUB"
cat > "$STUB/curl" <<'EOF'
#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  */releases/latest) body="$FIXTURES/latest.json" ;;
  */releases/download/*) body="$FIXTURES/$(basename "$url")" ;;
  *) exit 22 ;;
esac
[ -f "$body" ] || exit 22
if [ -n "$out" ]; then cp "$body" "$out"; else cat "$body"; fi
EOF
cat > "$STUB/minisign" <<'EOF'
#!/bin/sh
m=""; x=""
while [ $# -gt 0 ]; do case "$1" in -Vm) m="$2"; shift 2 ;; -x) x="$2"; shift 2 ;; *) shift ;; esac; done
want="SIGOK:$(shasum -a 256 "$m" 2>/dev/null | awk '{print $1}')"
[ "$(cat "$x")" = "$want" ]
EOF
chmod +x "$STUB/curl" "$STUB/minisign"
NOSHA="$WORK/nosha"; mkdir -p "$NOSHA"
for t in sh bash cat cp awk sed grep uname mkdir mktemp chmod mv rm basename dirname tr printf env head; do
  p="$(command -v "$t" || true)"; [ -n "$p" ] && ln -sf "$p" "$NOSHA/$t"
done
ln -sf "$STUB/curl" "$NOSHA/curl"

fixtures() { # fixtures <dir> : a fake binary and its sha256 + signature
  local d="$1"; mkdir -p "$d"
  printf '#!/bin/sh\ncase "$1" in --version) echo "lockrail 9.9.9";; *) exit 0;; esac\n' > "$d/$ART"
  chmod +x "$d/$ART"
  echo '{"tag_name": "v9.9.9"}' > "$d/latest.json"
  echo "$(sha "$d/$ART")  $ART" > "$d/$ART.sha256"
  echo "SIGOK:$(sha "$d/$ART")" > "$d/$ART.minisig"
}

FAIL=0
case_run() { # case_run <name> <expect:ok|fail> <fixtures> <PATH>
  local name="$1" expect="$2" fx="$3" path="$4" home="$WORK/home-$1" rc=0
  mkdir -p "$home"
  env -i PATH="$path" HOME="$home" FIXTURES="$fx" LOCKRAIL_INSTALL="$home/bin" \
    LOCKRAIL_MINISIGN_PUBKEY="RWTESTKEY" sh "$SCRIPT" --release > "$WORK/$name.log" 2>&1 || rc=$?
  local installed=no; [ -x "$home/bin/lockrail" ] && installed=yes
  if { [ "$expect" = ok ] && [ "$rc" = 0 ] && [ "$installed" = yes ]; } \
     || { [ "$expect" = fail ] && [ "$rc" != 0 ] && [ "$installed" = no ]; }; then
    echo "test-install: $name ok (exit=$rc installed=$installed)"
  else
    echo "test-install: $name FAILED (expected $expect; exit=$rc installed=$installed)"; sed 's/^/    /' "$WORK/$name.log" | tail -5; FAIL=1
  fi
}

BASE_PATH="$STUB:/usr/bin:/bin:/usr/sbin:/sbin"

fixtures "$WORK/good"; case_run good ok "$WORK/good" "$BASE_PATH"

fixtures "$WORK/tampered"
printf '\n# tampered\n' >> "$WORK/tampered/$ART"
echo "$(sha "$WORK/tampered/$ART")  $ART" > "$WORK/tampered/$ART.sha256"   # attacker controls the release host
case_run tampered-binary fail "$WORK/tampered" "$BASE_PATH"

fixtures "$WORK/nosig"; rm "$WORK/nosig/$ART.minisig"; case_run missing-minisig fail "$WORK/nosig" "$BASE_PATH"

fixtures "$WORK/nosumfile"; rm "$WORK/nosumfile/$ART.sha256"; case_run missing-sha256-file fail "$WORK/nosumfile" "$BASE_PATH"

fixtures "$WORK/nosha"; case_run no-sha-tool fail "$WORK/nosha" "$NOSHA:$STUB"

# From a checkout: --dry-run builds (or reuses) the binary and changes nothing in HOME.
if grep -q -- "--from-source" "$SCRIPT"; then
  CARGO_DIR="$(dirname "$(command -v cargo)")"
  home="$WORK/home-source-dry"; mkdir -p "$home"; rc=0
  env -i PATH="$CARGO_DIR:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$home" sh "$SCRIPT" --dry-run \
    > "$WORK/source-dry.log" 2>&1 || rc=$?
  left="$(find "$home" -mindepth 1 | head -5)"
  if [ "$rc" = 0 ] && [ -z "$left" ] && grep -q "dry run" "$WORK/source-dry.log"; then
    echo "test-install: source-dry-run ok (exit=0, HOME untouched)"
  else
    echo "test-install: source-dry-run FAILED (exit=$rc, left: $left)"; tail -5 "$WORK/source-dry.log" | sed 's/^/    /'; FAIL=1
  fi
  # Without Rust, source mode stops with the rustup hint and installs nothing.
  home="$WORK/home-source-nocargo"; mkdir -p "$home"; rc=0
  env -i PATH="/usr/bin:/bin:/usr/sbin:/sbin" HOME="$home" sh "$SCRIPT" --from-source \
    > "$WORK/source-nocargo.log" 2>&1 || rc=$?
  if [ "$rc" != 0 ] && grep -q "rustup.rs" "$WORK/source-nocargo.log" && [ -z "$(find "$home" -mindepth 1 | head -1)" ]; then
    echo "test-install: source-without-rust ok (exit=$rc)"
  else
    echo "test-install: source-without-rust FAILED (exit=$rc)"; tail -5 "$WORK/source-nocargo.log" | sed 's/^/    /'; FAIL=1
  fi
fi

if [ "$FAIL" = 0 ]; then echo "test-install: all cases passed for $SCRIPT"; else echo "test-install: failures for $SCRIPT"; exit 1; fi
