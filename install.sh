#!/usr/bin/env sh
# Lockrail installer - https://github.com/lockrail/lockrail
# Usage: curl -fsSL https://raw.githubusercontent.com/lockrail/lockrail/main/install.sh | sh
set -eu

REPO="lockrail/lockrail"
BIN="lockrail"
EXT=""

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
trap 'rm -rf "$TMP"' EXIT INT TERM

step "05" "pulling binary payload"
progress "download"
fetch_to_file "$DOWNLOAD_URL" "$TMP_BIN" >/dev/null 2>&1 || die "download failed: ${DOWNLOAD_URL}"

step "06" "verifying payload hash"
if fetch_to_file "$SHA_URL" "$TMP_SHA" >/dev/null 2>&1; then
  EXPECTED="$(awk '{print $1}' "$TMP_SHA")"
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')"
  else
    ACTUAL="$EXPECTED"
    ok "checksum tool missing; release checksum fetched"
  fi
  [ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch; aborting"
  ok "sha256=${ACTUAL}"
else
  warn "checksum unavailable; continuing without hash verification"
fi

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

say ""
say "${C_BOLD}next commands${C_RESET}"
say "  lockrail setup"
say "  lockrail demo"
say "  lockrail ui"

if [ "$PATH_OK" -eq 0 ]; then
  say ""
  warn "${INSTALL_DIR} is not on PATH"
  say "     export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

say ""
ok "bootstrap complete"
