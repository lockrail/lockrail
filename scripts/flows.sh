#!/usr/bin/env bash
# Legacy-flow re-drive recorder (PLAN.md Phase 0B, GATE 0 / GATE 6 / GATE 11; adv_message_1 M12).
#
# Drives the 9 legacy flows (setup, seal, secret set, capability issue, relay, proxy, env seal,
# demo, ui) against one lockrail binary, inside a throwaway HOME and LOCKRAIL_HOME, and writes one
# normalised transcript per flow.
#
#   bash scripts/flows.sh --record <name> [--bin <path>]   write tests/flows/<name>/NN-flow.txt
#   bash scripts/flows.sh --compare <name> [--bin <path>]  re-drive and diff against <name>
#
# Safety: nothing outside the temporary directory is written. `security` and `sudo` are replaced
# by stubs that exit 1, so `proxy install-ca` only generates the CA inside the temp home and never
# touches a trust store. The script aborts if the stubs do not resolve first on PATH.
# No network: every request goes to 127.0.0.1, and the relay is only asked for refusals.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=""
NAME=""
ACCEPT=0
BIN="$ROOT/target/release/lockrail"
while [ $# -gt 0 ]; do
  case "$1" in
    --record) MODE=record; NAME="${2:?name}"; shift 2 ;;
    --compare) MODE=compare; NAME="${2:?name}"; shift 2 ;;
    --bin) BIN="${2:?path}"; shift 2 ;;
    --accept) ACCEPT=1; shift ;;
    *) echo "usage: flows.sh --record|--compare <name> [--bin <path>]" >&2; exit 2 ;;
  esac
done
[ -n "$MODE" ] || { echo "usage: flows.sh --record|--compare <name> [--bin <path>]" >&2; exit 2; }
[ -x "$BIN" ] || { echo "flows: binary not found: $BIN (build with cargo build --release)" >&2; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lockrail-flows.XXXXXX")"
WORK="$(cd "$WORK" && pwd -P)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

if [ "$MODE" = record ]; then OUT="$ROOT/tests/flows/$NAME"; else OUT="$WORK/out"; fi
# Replace only the transcripts; ALLOWED_DIFFS.md and ALLOWED_DIFFS.lines are kept.
mkdir -p "$OUT"; rm -f "$OUT"/[0-9][0-9]-*.txt

# --- isolation -----------------------------------------------------------------------------
STUBS="$WORK/stubs"; mkdir -p "$STUBS"
for s in security sudo certutil update-ca-certificates update-ca-trust open xdg-open; do
  printf '#!/bin/sh\necho "flows-stub: %s refused" >&2\nexit 1\n' "$s" > "$STUBS/$s"
  chmod +x "$STUBS/$s"
done
export PATH="$STUBS:$PATH"
for s in security sudo; do
  [ "$(command -v "$s")" = "$STUBS/$s" ] || { echo "flows: stub for $s does not resolve first; aborting" >&2; exit 3; }
done

NORM="$WORK/norm.py"
cat > "$NORM" <<'PY'
import re, sys
work, binpath, text = sys.argv[1], sys.argv[2], sys.stdin.read()
text = text.replace(binpath, "<BIN>").replace(work, "<WORK>")
subs = [
    (r"lockrail://[^\s\"'\\,}]+", "<HANDLE>"),
    (r"lrap\d\.[A-Za-z0-9_.\-]+", "<CAP>"),
    (r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<UUID>"),
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?", "<TS>"),
    (r"\b(?:fp|h)_[0-9a-f]{16,32}\b", "<FP>"),
    (r"sha256:[0-9a-f]{64}", "sha256:<HEX>"),
    (r"\b[0-9a-fA-F]{16,}\b", "<HEX>"),
    (r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----", "<PEM>"),
    # Random base64/base64url values: any run of 40+ token characters, or 32-39 with a digit
    # (shorter digit-free runs are identifiers worth keeping readable). A digit-free random key
    # used to stay raw and made the compare flaky.
    (r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{40,}={0,2}", "<B64>"),
    (r"(?<![A-Za-z0-9_\-])(?=[A-Za-z_\-]*\d)[A-Za-z0-9_\-]{32,39}={0,2}", "<B64>"),
    (r"127\.0\.0\.1:\d+", "127.0.0.1:<PORT>"),
    (r"localhost:\d+", "localhost:<PORT>"),
    (r"\b1[6-9]\d{8,11}\b", "<EPOCH>"),
    (r"\b\d+(\.\d+)?\s?(ms|µs|us|s)\b", "<DUR>"),
    (r"(?<![\d.])0\.\d+\.\d+(?![\d.])", "<VER>"),
]
for pat, rep in subs:
    text = re.sub(pat, rep, text)
sys.stdout.write(text)
PY

free_port() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
wait_port() {
  for _ in $(seq 1 100); do
    if python3 -I -c "import socket,sys;s=socket.socket();s.settimeout(0.2);sys.exit(s.connect_ex(('127.0.0.1',$1)))" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 1
}

FLOW_FILE=""
FLOW_HOME=""
new_flow() {
  FLOW_FILE="$OUT/$1.txt"
  FLOW_HOME="$WORK/home-$1"
  mkdir -p "$FLOW_HOME/project"
  : > "$FLOW_FILE"
}
# step <label> <cmd...>: run in the flow's isolated home and record exit code and output.
step() {
  local label="$1"; shift
  local raw="$WORK/raw.txt" rc=0
  ( cd "$FLOW_HOME/project" && HOME="$FLOW_HOME" LOCKRAIL_HOME="$FLOW_HOME/.lockrail" \
      NO_COLOR=1 "$@" ) > "$raw" 2>&1 < /dev/null || rc=$?
  { echo "\$ $label"; echo "exit=$rc"; python3 -I "$NORM" "$WORK" "$BIN" < "$raw"; echo; } >> "$FLOW_FILE"
}
note() { { echo "# $*"; python3 -I "$NORM" "$WORK" "$BIN"; echo; } >> "$FLOW_FILE"; }
lr() { "$BIN" "$@"; }
home_tree() { (cd "$FLOW_HOME" && find . -path ./project -prune -o -type f -print | LC_ALL=C sort); }
bg() { # bg <logfile> <cmd...>
  local log="$1"; shift
  ( cd "$FLOW_HOME/project" && HOME="$FLOW_HOME" LOCKRAIL_HOME="$FLOW_HOME/.lockrail" NO_COLOR=1 \
      exec "$@" ) > "$log" 2>&1 < /dev/null &
  PIDS+=("$!")
  echo "$!"
}
stop() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }

# Synthetic secrets, assembled at runtime so no literal in this file matches a scanner rule.
P1=ghp; S1="${P1}_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
P2=sk; S2="${P2}-proj-flows-$(printf 'Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0')"

# --- 01 setup ------------------------------------------------------------------------------
new_flow 01-setup
step "lockrail setup --tools all --json" lr setup --tools all --json
step "lockrail status --json" lr status --json
home_tree | note "files under HOME after setup"
step "lockrail setup --json (second run is idempotent)" lr setup --json

# --- 02 seal -------------------------------------------------------------------------------
new_flow 02-seal
step "lockrail setup --json" lr setup --json
step "lockrail seal --text <github token> --json" lr seal --text "deploy with GITHUB_TOKEN=$S1 now" --json
step "lockrail seal (stdin, no secret)" sh -c "echo 'nothing secret here' | '$BIN' seal --json"
step "lockrail scan --text <openai key> --json" lr scan --text "key $S2" --json
step "lockrail secret list --json" lr secret list --json

# --- 03 secret set -------------------------------------------------------------------------
new_flow 03-secret-set
step "lockrail setup --json" lr setup --json
step "lockrail secret set FLOW_KEY <value> --json" lr secret set FLOW_KEY "$S2" --json
step "lockrail secret set FLOW_KEY <value> --env staging --json" lr secret set FLOW_KEY "$S2" --env staging --json
step "lockrail secret list --json" lr secret list --json

# --- 04 capability issue -------------------------------------------------------------------
new_flow 04-capability-issue
step "lockrail setup --json" lr setup --json
step "lockrail secret set FLOW_KEY <value>" lr secret set FLOW_KEY "$S2" --json
step "lockrail agent create flow-agent --type claude-code --json" lr agent create flow-agent --type claude-code --json
step "lockrail capability issue FLOW_KEY --host api.openai.com --json" \
  lr capability issue FLOW_KEY --host api.openai.com --method POST --path '/v1/*' --minutes 5 --json
step "lockrail capability issue FLOW_KEY --preset openai --agent flow-agent --json" \
  lr capability issue FLOW_KEY --preset openai --agent flow-agent --minutes 5 --json
step "lockrail capability issue MISSING --json (refused)" lr capability issue MISSING --host api.openai.com --json

# --- 05 relay ------------------------------------------------------------------------------
new_flow 05-relay
step "lockrail setup --json" lr setup --json
step "lockrail secret set FLOW_KEY <value>" lr secret set FLOW_KEY "$S2" --json
ISSUED="$(cd "$FLOW_HOME/project" && HOME="$FLOW_HOME" LOCKRAIL_HOME="$FLOW_HOME/.lockrail" "$BIN" capability issue FLOW_KEY \
  --host api.openai.com --method POST --path '/v1/*' --minutes 5 --json)"
read -r CAP CAP_ID < <(printf '%s' "$ISSUED" | python3 -I -c 'import json,sys
d=json.load(sys.stdin)
def find(o):
    if isinstance(o,str) and o.startswith("lrap"): return o
    if isinstance(o,dict):
        for v in o.values():
            r=find(v)
            if r: return r
    return None
print(find(d) or "-", (d.get("claims") or {}).get("cap_id") or "-")')
RP="$(free_port)"
RPID="$(bg "$WORK/relay.log" "$BIN" relay start --addr "127.0.0.1:$RP" --json)"
if wait_port "$RP"; then
  step "GET /healthz" curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:$RP/healthz"
  relay_post() { curl -s -w '\nstatus=%{http_code}\n' -X POST -H 'content-type: application/json' --data "$1" "http://127.0.0.1:$RP/relay"; }
  step "POST /relay with a garbage capability (refused)" relay_post '{"capability":"lrap3.garbage","method":"POST","upstream":"https://api.openai.com/v1/x"}'
  step "POST /relay to a host outside the capability (refused)" relay_post "{\"capability\":\"$CAP\",\"method\":\"POST\",\"upstream\":\"https://evil.example.com/v1/x\"}"
  step "POST /relay to a loopback upstream (refused)" relay_post "{\"capability\":\"$CAP\",\"method\":\"POST\",\"upstream\":\"https://127.0.0.1/v1/x\"}"
  step "POST /relay with a disallowed method (refused)" relay_post "{\"capability\":\"$CAP\",\"method\":\"DELETE\",\"upstream\":\"https://api.openai.com/v1/x\"}"
  step "lockrail capability revoke <cap_id>" lr capability revoke "$CAP_ID" --json
  step "POST /relay after revocation (refused)" relay_post "{\"capability\":\"$CAP\",\"method\":\"POST\",\"upstream\":\"https://evil.example.com/v1/x\"}"
else
  echo "relay did not start" | note "relay start failed"
fi
stop "$RPID"
note "relay log" < "$WORK/relay.log"

# --- 06 proxy ------------------------------------------------------------------------------
new_flow 06-proxy
step "lockrail setup --json" lr setup --json
step "lockrail proxy status --json (before CA)" lr proxy status --json
step "lockrail proxy start before install-ca (refused)" lr proxy start --listen 127.0.0.1:1 --json
step "lockrail proxy install-ca --json (trust-store calls stubbed)" lr proxy install-ca --json
step "lockrail proxy start --listen 0.0.0.0:<port> (refused)" lr proxy start --listen 0.0.0.0:18799 --json
PP="$(free_port)"
PPID_="$(bg "$WORK/proxy.log" "$BIN" proxy start --listen "127.0.0.1:$PP" --json)"
if wait_port "$PP"; then
  step "lockrail proxy status --json" lr proxy status --json
  EP="$(free_port)"
  EPID="$(bg "$WORK/echo.log" python3 -I -m http.server "$EP" --bind 127.0.0.1)"
  wait_port "$EP" || true
  step "curl via proxy to a plain-http loopback host" curl -s -o /dev/null -w '%{http_code}\n' -x "http://127.0.0.1:$PP" "http://127.0.0.1:$EP/"
  stop "$EPID"
else
  echo "proxy did not start" | note "proxy start failed"
fi
stop "$PPID_"
note "proxy log" < "$WORK/proxy.log"

# --- 07 env seal ---------------------------------------------------------------------------
new_flow 07-env-seal
step "lockrail setup --json" lr setup --json
printf 'APP_NAME=flows\nGITHUB_TOKEN=%s\nOPENAI_API_KEY=%s\n' "$S1" "$S2" > "$FLOW_HOME/project/.env"
step "lockrail env scan .env --json" lr env scan .env --json
step "lockrail env seal .env --out .env.lockrail --dry-run --json" lr env seal .env --out .env.lockrail --dry-run --json
step "lockrail env seal .env --out .env.lockrail --json" lr env seal .env --out .env.lockrail --json
note ".env.lockrail contents" < "$FLOW_HOME/project/.env.lockrail"
step "lockrail env run --dry-run -- true" lr env run --file .env.lockrail --dry-run --json -- true
step "lockrail env run -- sh -c <resolves GITHUB_TOKEN>" \
  lr env run --file .env.lockrail -- sh -c "test \"\$GITHUB_TOKEN\" = '$S1' && echo resolved || echo not-resolved"

# --- 08 demo -------------------------------------------------------------------------------
new_flow 08-demo
step "lockrail setup --json" lr setup --json
step "lockrail demo --json" lr demo --json
step "lockrail demo" lr demo

# --- 09 ui ---------------------------------------------------------------------------------
new_flow 09-ui
step "lockrail setup --json" lr setup --json
UP="$(free_port)"
UPID="$(bg "$WORK/ui.log" "$BIN" ui --listen "127.0.0.1:$UP" --json)"
if wait_port "$UP"; then
  TOKEN="$(python3 -I -c 'import re,sys
t=open(sys.argv[1]).read()
m=re.search(r"token=([A-Za-z0-9_\-]+)",t) or re.search(r"\"(?:session_)?token\"\s*:\s*\"([^\"]+)\"",t)
print(m.group(1) if m else "")' "$WORK/ui.log")"
  step "GET / without token" curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:$UP/"
  step "GET / with a wrong token" curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Lockrail-Token: wrong' "http://127.0.0.1:$UP/"
  if [ -n "$TOKEN" ]; then
    step "GET / with the session token" curl -s -o /dev/null -w '%{http_code}\n' -H "X-Lockrail-Token: $TOKEN" "http://127.0.0.1:$UP/"
  else
    echo "no token found in ui output" | note "ui token"
  fi
else
  echo "ui did not start" | note "ui start failed"
fi
stop "$UPID"
note "ui output" < "$WORK/ui.log"

# --- result --------------------------------------------------------------------------------
COUNT="$(find "$OUT" -name '*.txt' | wc -l | tr -d ' ')"
if [ "$MODE" = record ]; then
  echo "flows: recorded $COUNT flow transcripts in tests/flows/$NAME (binary: $("$BIN" --version))"
  [ "$COUNT" = 9 ] || { echo "flows: expected 9 transcripts" >&2; exit 1; }
  exit 0
fi

BASE="$ROOT/tests/flows/$NAME"
[ -d "$BASE" ] || { echo "flows: no recorded set at tests/flows/$NAME" >&2; exit 2; }
# The allowed difference is pinned line by line: ALLOWED_DIFFS.lines holds the exact changed lines
# per flow, ALLOWED_DIFFS.md says why each one is intended. A new or altered difference fails.
ALLOW_LINES="$BASE/ALLOWED_DIFFS.lines"
ACTUAL="$WORK/actual.lines"
: > "$ACTUAL"
for f in "$BASE"/*.txt; do
  b="$(basename "$f")"
  if ! diff -u "$f" "$OUT/$b" > "$WORK/$b.diff"; then
    echo "## $b" >> "$ACTUAL"
    grep -E '^[-+]' "$WORK/$b.diff" | grep -vE '^(---|\+\+\+) ' >> "$ACTUAL" || true
  fi
done
if [ "$ACCEPT" = 1 ]; then
  cp "$ACTUAL" "$ALLOW_LINES"
  echo "flows: wrote $(grep -c '^## ' "$ACTUAL" || true) flow differences to $ALLOW_LINES; document each in ALLOWED_DIFFS.md"
  exit 0
fi
for f in "$BASE"/*.txt; do
  b="$(basename "$f")"
  if [ -s "$WORK/$b.diff" ]; then echo "flows: $b differs"; else echo "flows: $b equivalent"; fi
done
if [ -f "$ALLOW_LINES" ] && cmp -s "$ACTUAL" "$ALLOW_LINES"; then
  echo "flows: all $COUNT flows equivalent to $NAME except the differences documented in ALLOWED_DIFFS.md"
  exit 0
fi
if [ ! -s "$ACTUAL" ]; then
  echo "flows: all $COUNT flows equivalent to $NAME"
  [ -s "$ALLOW_LINES" ] 2>/dev/null && echo "flows: note: ALLOWED_DIFFS.lines lists differences that no longer occur; update it" >&2 && exit 1
  exit 0
fi
echo "flows: undocumented differences against $NAME:" >&2
diff -u "${ALLOW_LINES:-/dev/null}" "$ACTUAL" 2>/dev/null | sed 's/^/    /' >&2 || true
[ -f "$ALLOW_LINES" ] || sed 's/^/    /' "$ACTUAL" >&2
echo "flows: fix the regression, or document it in ALLOWED_DIFFS.md and re-run with --accept" >&2
exit 1
