#!/usr/bin/env sh
# Lockrail installer — https://github.com/lockrail/lockrail
# Usage: curl -fsSL https://raw.githubusercontent.com/lockrail/lockrail/main/install.sh | sh
set -e

REPO="lockrail/lockrail"
BIN="lockrail"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  \033[34m•\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

bold "Lockrail installer"
echo ""

# ── detect OS ──────────────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  CYGWIN*|MINGW*|MSYS*) OS=windows ;;
  *) err "Unsupported OS: $OS" ;;
esac
info "OS detected: $OS"

# ── detect architecture ────────────────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)   ARCH=x86_64 ;;
  aarch64|arm64)  ARCH=aarch64 ;;
  armv7l)         err "32-bit ARM is not supported. Please build from source: cargo install lockrail" ;;
  *) err "Unsupported architecture: $ARCH" ;;
esac
info "Arch detected: $ARCH"

# ── resolve target triple ──────────────────────────────────────────────────────
# On Linux we prefer the musl (statically-linked) build: it works on every
# distro regardless of glibc version (Alpine, Ubuntu, Fedora, Arch, etc.).
case "${OS}-${ARCH}" in
  linux-x86_64)   TARGET="x86_64-unknown-linux-musl" ;;
  linux-aarch64)  TARGET="aarch64-unknown-linux-musl" ;;
  darwin-x86_64)  TARGET="x86_64-apple-darwin" ;;
  darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
  windows-x86_64) TARGET="x86_64-pc-windows-msvc" ; EXT=".exe" ;;
  *) err "No pre-built binary for ${OS}-${ARCH}. Build from source: cargo install lockrail" ;;
esac
info "Target: $TARGET"

# ── resolve latest release tag ─────────────────────────────────────────────────
if command -v curl >/dev/null 2>&1; then
  FETCH="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  FETCH="wget -qO-"
else
  err "Neither curl nor wget found. Install one and retry."
fi

info "Fetching latest release tag…"
TAG="$($FETCH "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)".*/\1/')"
[ -z "$TAG" ] && err "Could not fetch latest release. Check your internet connection or visit https://github.com/${REPO}/releases"
info "Latest release: $TAG"

# ── determine install directory ────────────────────────────────────────────────
if [ "$OS" = "windows" ]; then
  INSTALL_DIR="${USERPROFILE}/.local/bin"
else
  if [ -w /usr/local/bin ]; then
    INSTALL_DIR=/usr/local/bin
  elif [ -w "${HOME}/.local/bin" ]; then
    INSTALL_DIR="${HOME}/.local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi
info "Install directory: $INSTALL_DIR"

# ── download binary ────────────────────────────────────────────────────────────
BIN_FILE="${BIN}${EXT:-}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/lockrail-${TARGET}${EXT:-}"
SHA_URL="https://github.com/${REPO}/releases/download/${TAG}/lockrail-${TARGET}${EXT:-}.sha256"

TMP="$(mktemp -d)"
TMP_BIN="${TMP}/${BIN_FILE}"
TMP_SHA="${TMP}/lockrail.sha256"

info "Downloading $DOWNLOAD_URL…"
$FETCH "$DOWNLOAD_URL" > "$TMP_BIN" || err "Download failed"

# ── verify checksum ────────────────────────────────────────────────────────────
if $FETCH "$SHA_URL" > "$TMP_SHA" 2>/dev/null; then
  info "Verifying checksum…"
  if command -v sha256sum >/dev/null 2>&1; then
    EXPECTED="$(awk '{print $1}' "$TMP_SHA")"
    ACTUAL="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    EXPECTED="$(awk '{print $1}' "$TMP_SHA")"
    ACTUAL="$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')"
  else
    info "sha256sum/shasum not found — skipping checksum verification"
    EXPECTED="$ACTUAL"
  fi

  if [ "$EXPECTED" != "$ACTUAL" ]; then
    rm -rf "$TMP"
    err "Checksum mismatch! Expected $EXPECTED, got $ACTUAL. Aborting."
  fi
  ok "Checksum verified"
fi

# ── install ────────────────────────────────────────────────────────────────────
chmod +x "$TMP_BIN"
mkdir -p "$INSTALL_DIR"
mv "$TMP_BIN" "${INSTALL_DIR}/${BIN_FILE}"
rm -rf "$TMP"
ok "Installed to ${INSTALL_DIR}/${BIN_FILE}"

# ── PATH warning ───────────────────────────────────────────────────────────────
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) : ;;
  *)
    echo ""
    bold "  ⚠  Add $INSTALL_DIR to your PATH:"
    echo "     export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
    ;;
esac

# ── verify install ─────────────────────────────────────────────────────────────
if "${INSTALL_DIR}/${BIN_FILE}" --version >/dev/null 2>&1; then
  ok "$(${INSTALL_DIR}/${BIN_FILE} --version)"
fi

echo ""
bold "  Quick start:"
echo "    lockrail init"
echo "    lockrail protect --tool all"
echo "    lockrail demo"
echo "    lockrail ui        # dashboard at http://127.0.0.1:8790"
echo ""
ok "Done. Run 'lockrail --help' to get started."
