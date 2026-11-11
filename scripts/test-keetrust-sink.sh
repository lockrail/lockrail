#!/usr/bin/env bash
# KeeTrust sink end-to-end against a mock (PLAN.md GATE 7: T3, T7, T8).
#   bash scripts/test-keetrust-sink.sh [path/to/lockrail]
# The mock answers like KeeTrust: it rebuilds the payload server-side (trim, de-duplicated
# controls, key order) and hashes JSON.stringify(payload) with Node, so the hash read-back is
# checked against JavaScript, not against Lockrail's own code. Needs python3 and node.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/lockrail}"
W="$(mktemp -d)"; trap 'kill "${MP:-0}" 2>/dev/null || true; rm -rf "$W"' EXIT
export LOCKRAIL_HOME="$W/home" LOCKRAIL_KEYSTORE=file LOCKRAIL_SYSTEM_DIR="$W/sys"
mkdir -p "$W/sys"
cat > "$W/mock.py" <<'PY'
import json, subprocess, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
STATE = {"hashes": [], "redact": int(sys.argv[2])}
NODE = r'''
const crypto=require("node:crypto");const i=JSON.parse(require("node:fs").readFileSync(0,"utf8"));const t=s=>s.trim();
const p={kind:"external_push",title:t(i.title),description:i.description===undefined?null:t(i.description),source:t(i.source),pushed_by:"lockrail-laptop",controls:[...new Set(i.controls.map(t))],data:i.data};
process.stdout.write(crypto.createHash("sha256").update(JSON.stringify(p)).digest("hex"));'''
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers["content-length"]))
        req = json.loads(body)
        allowed = {"controls","title","description","source","data","valid_days"}
        if set(req) - allowed:
            self.send_response(400); self.end_headers(); return
        h = subprocess.run(["node","-e",NODE], input=body, capture_output=True).stdout.decode()
        STATE["hashes"].append(h)
        out = json.dumps({"evidence_id":"e1","sha256":h,"redactions":STATE["redact"]}).encode()
        self.send_response(201); self.send_header("content-type","application/json"); self.end_headers(); self.wfile.write(out)
    def do_GET(self):
        out = json.dumps([{"sha256": h} for h in STATE["hashes"]]).encode()
        self.send_response(200); self.send_header("content-type","application/json"); self.end_headers(); self.wfile.write(out)
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
port() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
start_mock() { P=$(port); python3 -I "$W/mock.py" "$P" "$1" & MP=$!; for _ in $(seq 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done; }
"$BIN" policy keygen --out "$W/org.key" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["org_pub"])' > "$W/sys/org.pub"
for _ in 1 2 3; do "$BIN" policy show --json >/dev/null; done
"$BIN" evidence anchor --json >/dev/null; "$BIN" evidence digest --json >/dev/null
export LOCKRAIL_KEETRUST_TOKEN=test-write LOCKRAIL_KEETRUST_READ_TOKEN=test-read
FAIL=0
start_mock 1
if "$BIN" evidence ship --sink keetrust --url "http://127.0.0.1:$P" --controls CC7.2 CC7.2 --json >/dev/null 2>&1; then
  echo "keetrust-sink: FAILED (redactions=1 was accepted)"; FAIL=1
else
  n=$(ls "$LOCKRAIL_HOME/outbox" | wc -l | tr -d ' '); echo "keetrust-sink: redactions>0 refused, outbox keeps $n digest(s) ok"
fi
kill "$MP"; start_mock 0
"$BIN" evidence ship --sink keetrust --url "http://127.0.0.1:$P" --controls CC7.2 CC7.2 --json >/dev/null
if "$BIN" evidence verify --sink keetrust --url "http://127.0.0.1:$P" --token-name lockrail-laptop --json > "$W/v.json"; then
  echo "keetrust-sink: verify against JS-computed hash ok (unanchored_tail $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["chain"]["unanchored_tail"])' "$W/v.json"))"
else echo "keetrust-sink: FAILED verify"; cat "$W/v.json"; FAIL=1; fi
f=$(ls "$LOCKRAIL_HOME"/shipped/keetrust-*.json | head -1)
python3 -I - "$f" <<'PY'
import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["request"]["title"]=d["request"]["title"].replace("digest","Digest",1); json.dump(d,open(p,"w"))
PY
if "$BIN" evidence verify --sink keetrust --url "http://127.0.0.1:$P" --token-name lockrail-laptop --json > "$W/v2.json"; then
  echo "keetrust-sink: FAILED (a changed payload verified)"; FAIL=1
else
  grep -q shipped_hash_mismatch "$W/v2.json" && echo "keetrust-sink: one changed byte -> shipped_hash_mismatch ok" || { echo "keetrust-sink: FAILED wrong problem"; FAIL=1; }
fi
exit $FAIL
