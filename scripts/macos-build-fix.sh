#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DEFAULT="$HOME/Developer/lockrail"
DEST="${1:-$DEST_DEFAULT}"

cat <<MSG
== Lockrail macOS build fix ==
Current project: $ROOT
Recommended project location: $DEST

Why this exists:
macOS/EDR can kill unsigned Cargo-generated build scripts when a project lives under Downloads/quarantined paths.
This script copies Lockrail to a clean developer folder, clears quarantine xattrs, and gives you build commands.
MSG

mkdir -p "$(dirname "$DEST")"
if [ "$ROOT" != "$DEST" ]; then
  echo "Copying project to $DEST ..."
  rsync -a --delete \
    --exclude target \
    --exclude target-local \
    --exclude scan-logs \
    --exclude .git \
    "$ROOT/" "$DEST/"
else
  echo "Already in destination path."
fi

cd "$DEST"

echo "Clearing quarantine/provenance attributes where possible..."
xattr -cr . 2>/dev/null || true
xattr -dr com.apple.quarantine . 2>/dev/null || true
xattr -dr com.apple.provenance . 2>/dev/null || true

rm -rf target target-local
mkdir -p scan-logs

cat <<MSG

Now run:

  cd "$DEST"
  source ~/.cargo/env
  CARGO_TARGET_DIR="$HOME/.cargo-target/lockrail" CARGO_BUILD_JOBS=1 ./scripts/full-scan.sh

If it still SIGKILLs build scripts, run:

  log show --last 10m --style compact --predicate 'eventMessage CONTAINS "build-script-build" OR eventMessage CONTAINS "malware" OR eventMessage CONTAINS "deny" OR eventMessage CONTAINS "killed"' > scan-logs/macos-kill.log

Then send:

  $DEST/scan-logs/latest.log
  $DEST/scan-logs/macos-kill.log
MSG
