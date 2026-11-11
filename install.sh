#!/usr/bin/env sh
# Lockrail installer - https://github.com/lockrail/lockrail
#
# From a checkout (builds with your Rust toolchain, nothing downloaded):
#   ./install.sh                 # build, install, set up protection (one password prompt on macOS)
#   ./install.sh --dry-run       # show what would change
#   ./install.sh --no-trust      # skip trusting the local CA (no prompt)
#   ./install.sh --uninstall     # remove everything, restore previous settings
# Release binaries (needs a pinned signing key; refuses until one exists):
#   curl -fsSL https://raw.githubusercontent.com/lockrail/lockrail/main/install.sh | sh
set -eu

MODE=""
DRY_RUN=0
NO_TRUST=0
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --from-source) MODE=source ;;
    --release) MODE=release ;;
    --dry-run) DRY_RUN=1 ;;
    --no-trust) NO_TRUST=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) printf 'unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done
# Run from a checkout: build from source unless --release was asked for.
SRC_DIR=""
case "$0" in
  */install.sh|install.sh)
    SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
    [ -f "$SRC_DIR/Cargo.toml" ] && [ -d "$SRC_DIR/crates/lockrail-cli" ] || SRC_DIR=""
    ;;
esac
[ -n "$MODE" ] || { [ -n "$SRC_DIR" ] && MODE=source || MODE=release; }

REPO="lockrail/lockrail"
BIN="lockrail"
EXT=""
# Release-signing key (minisign), pinned at release time (PLAN.md D7, owner item O-3). Until a
# key is pinned this installer refuses to install; use the signed package instead.
MINISIGN_PUBKEY="${LOCKRAIL_MINISIGN_PUBKEY:-RWQ_PENDING_RELEASE_KEY}"

if [ -t 1 ]; then
  C_RESET="$(printf '\033[0m')"
  C_DIM="$(printf '\033[2m')"
  C_BOLD="$(printf '\033[1m')"
  C_GREEN="$(printf '\033[32m')"
  C_BLUE="$(printf '\033[34m')"
  C_CYAN="$(printf '\033[36m')"
  C_RED="$(printf '\033[31m')"
else
  C_RESET=""; C_DIM=""; C_BOLD=""; C_GREEN=""; C_BLUE=""; C_CYAN=""; C_RED=""
fi

say() { printf '%s\n' "$*"; }
banner() {
  say ""
  say "${C_CYAN}${C_BOLD}lockrail//installer${C_RESET} ${C_DIM}secret firewall bootstrap${C_RESET}"
  say "${C_DIM}------------------------------------------------------------${C_RESET}"
}
step() { printf '%s[%-2s]%s %s\n' "$C_BLUE" "$1" "$C_RESET" "$2"; }
ok() { printf '%s[ok]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
warn() { printf '%s[!!]%s %s\n' "$C_RED" "$C_RESET" "$1" >&2; }
die() { warn "$1"; exit 1; }

progress() {
  label="$1"
  printf '     %s%-20s%s [' "$C_DIM" "$label" "$C_RESET"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    printf '#'
  done
  printf '] done\n'
}

fetch_to_stdout() {
  url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
  else
    die "curl or wget is required"
  fi
}

fetch_to_file() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget "$url" -O "$out"
  else
    die "curl or wget is required"
  fi
}

banner

step "01" "scanning host kernel"
OS_RAW="$(uname -s)"
case "$OS_RAW" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  CYGWIN*|MINGW*|MSYS*) OS=windows ;;
  *) die "unsupported OS: $OS_RAW" ;;
esac
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  armv7l) die "32-bit ARM is not supported; use: cargo install lockrail" ;;
  *) die "unsupported architecture: $ARCH_RAW" ;;
esac
ok "host=${OS}/${ARCH}"

# Where the `lockrail` command goes on PATH (a symlink to the installed binary). Shell profiles
# are never edited.
LINK_DIR="${LOCKRAIL_LINK_DIR:-$HOME/.local/bin}"

finish() {
  # $1: path of a working lockrail binary. On macOS `lockrail install` copies it to
  # ~/Library/Application Support/Lockrail/bin and sets up the sealer, CA, hooks and proxy.
  LR="$1"
  if [ "$OS" = "darwin" ]; then
    set -- install
    [ "$DRY_RUN" -eq 1 ] && set -- "$@" --dry-run
    [ "$NO_TRUST" -eq 1 ] && set -- "$@" --no-trust
    step "IN" "setting up agent protection (lockrail install)"
    (unset LOCKRAIL_PASSWORD; "$LR" "$@") || die "lockrail install did not finish (it rolls back what it changed; see the message above)"
    TARGET_BIN="$HOME/Library/Application Support/Lockrail/bin/lockrail"
  else
    step "IN" "setting up the vault and Claude Code hooks"
    # The hooks run this binary on every prompt and tool call: copy it out of the build tree
    # first, so `cargo clean` cannot leave the hooks pointing at nothing.
    TARGET_BIN="$HOME/.local/share/lockrail/bin/lockrail"
    [ "$DRY_RUN" -eq 1 ] && { ok "dry run: would copy to $TARGET_BIN and run: setup && ai hooks"; return 0; }
    mkdir -p "$(dirname "$TARGET_BIN")"
    cp "$LR" "$TARGET_BIN.tmp" && chmod 755 "$TARGET_BIN.tmp" && mv "$TARGET_BIN.tmp" "$TARGET_BIN"
    (unset LOCKRAIL_PASSWORD; "$TARGET_BIN" setup && "$TARGET_BIN" ai hooks) || die "setup did not finish"
  fi
  if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$LINK_DIR"
    ln -sf "$TARGET_BIN" "$LINK_DIR/lockrail"
    ok "command=$LINK_DIR/lockrail"
    case ":${PATH}:" in
      *":${LINK_DIR}:"*) ;;
      *) warn "$LINK_DIR is not on PATH; add it, or run $LINK_DIR/lockrail directly" ;;
    esac
    if [ "$OS" = "darwin" ]; then
      "$TARGET_BIN" protection || warn "some checks need attention (above); start a new Claude Code session after fixing"
    fi
  fi
  say ""
  ok "done"
}

if [ "$UNINSTALL" -eq 1 ]; then
  step "UN" "removing Lockrail"
  LR="$(command -v lockrail 2>/dev/null || true)"
  [ -n "$LR" ] || LR="$HOME/Library/Application Support/Lockrail/bin/lockrail"
  [ -x "$LR" ] || die "no lockrail binary found to uninstall with"
  # On every OS this removes the Claude Code hooks and restores the proxy env; on macOS it also
  # removes the LaunchAgent and the CA trust.
  "$LR" uninstall --all
  rm -f "$LINK_DIR/lockrail"
  [ "$OS" = "darwin" ] || rm -f "$HOME/.local/share/lockrail/bin/lockrail"
  ok "removed (the vault and audit log are kept; lockrail uninstall --all --purge-data deletes them)"
  exit 0
fi

if [ "$MODE" = "source" ]; then
  [ -n "$SRC_DIR" ] || die "--from-source must be run from a Lockrail checkout (./install.sh)"
  step "02" "building from source in $SRC_DIR"
  command -v cargo >/dev/null 2>&1 || die "Rust is required to build from source: https://rustup.rs (then re-run ./install.sh)"
  if [ "$DRY_RUN" -eq 1 ] && [ -x "$SRC_DIR/target/release/lockrail" ]; then
    ok "dry run: using the existing build"
  else
    (cd "$SRC_DIR" && cargo build --release --locked -p lockrail) || die "build failed"
  fi
  BUILT="$SRC_DIR/target/release/lockrail"
  [ -x "$BUILT" ] || die "build produced no binary at $BUILT"
  ok "$("$BUILT" --version)"
  finish "$BUILT"
  exit 0
fi

step "02" "selecting release artifact"
case "${OS}-${ARCH}" in
  linux-x86_64) TARGET="x86_64-unknown-linux-musl" ;;
  linux-aarch64) TARGET="aarch64-unknown-linux-musl" ;;
  darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
  darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
  windows-x86_64) TARGET="x86_64-pc-windows-msvc"; EXT=".exe" ;;
  *) die "no prebuilt binary for ${OS}-${ARCH}; use: cargo install lockrail" ;;
esac
ok "target=${TARGET}"

step "03" "querying github releases"
TAG="$(fetch_to_stdout "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)".*/\1/')"
[ -n "$TAG" ] || die "could not resolve latest release; visit https://github.com/${REPO}/releases"
ok "release=${TAG}"

step "04" "choosing install path"
if [ -n "${LOCKRAIL_INSTALL:-}" ]; then
  INSTALL_DIR="$LOCKRAIL_INSTALL"
elif [ "$OS" = "windows" ]; then
  INSTALL_DIR="${USERPROFILE:-$HOME}/.local/bin"
elif [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="${HOME}/.local/bin"
fi
mkdir -p "$INSTALL_DIR"
ok "path=${INSTALL_DIR}"

BIN_FILE="${BIN}${EXT}"
ARTIFACT="lockrail-${TARGET}${EXT}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ARTIFACT}"
SHA_URL="${DOWNLOAD_URL}.sha256"
TMP="$(mktemp -d)"
TMP_BIN="${TMP}/${BIN_FILE}"
TMP_SHA="${TMP}/lockrail.sha256"
TMP_SIG="${TMP}/lockrail.minisig"
trap 'rm -rf "$TMP"' EXIT INT TERM

step "05" "pulling binary payload"
progress "download"
fetch_to_file "$DOWNLOAD_URL" "$TMP_BIN" >/dev/null 2>&1 || die "download failed: ${DOWNLOAD_URL}"

step "06" "verifying payload hash and signature"
# D7: every check fails closed. 0.3.7 continued without a checksum file, and with no sha tool it
# set the expected hash equal to the actual one.
fetch_to_file "$SHA_URL" "$TMP_SHA" >/dev/null 2>&1 \
  || die "checksum file unavailable (${SHA_URL}); refusing to install an unverified binary"
EXPECTED="$(awk '{print $1}' "$TMP_SHA")"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')"
else
  die "no sha256 tool (sha256sum or shasum) found; refusing to install an unverified binary"
fi
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch; aborting"
ok "sha256=${ACTUAL}"
case "$MINISIGN_PUBKEY" in
  RWQ_PENDING*) die "no release-signing key is pinned in this installer yet; install from the signed package" ;;
esac
command -v minisign >/dev/null 2>&1 \
  || die "minisign is required to verify the release signature (macOS: brew install minisign)"
fetch_to_file "${DOWNLOAD_URL}.minisig" "$TMP_SIG" >/dev/null 2>&1 \
  || die "signature file unavailable (${DOWNLOAD_URL}.minisig); refusing to install"
minisign -Vm "$TMP_BIN" -x "$TMP_SIG" -P "$MINISIGN_PUBKEY" >/dev/null 2>&1 \
  || die "signature verification failed; aborting"
ok "signature verified"

step "07" "arming executable"
chmod +x "$TMP_BIN"
mv "$TMP_BIN" "${INSTALL_DIR}/${BIN_FILE}"
ok "installed=${INSTALL_DIR}/${BIN_FILE}"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) PATH_OK=1 ;;
  *) PATH_OK=0 ;;
esac

if "${INSTALL_DIR}/${BIN_FILE}" --version >/dev/null 2>&1; then
  ok "$("${INSTALL_DIR}/${BIN_FILE}" --version)"
fi

finish "${INSTALL_DIR}/${BIN_FILE}"
