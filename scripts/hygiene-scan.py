#!/usr/bin/env python3
from pathlib import Path
import re, sys

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {'target', 'target-local', 'scan-logs', '.git'}
TEXT_EXTS = {'.rs', '.md', '.toml', '.sh'}
old_name_re = re.compile(r'\b(Specter|specter|SAPP|spct)\b')
todo_re = re.compile(r'\b(TODO|FIXME)\b')
secret_re = re.compile(r'(sk-proj-|ghp_|xoxb-|AKIA[0-9A-Z]{16}|BEGIN PRIVATE KEY)')
unwrap_re = re.compile(r'\b(unwrap\(|expect\(|panic!)')

# Files where literal detector patterns or fake fixtures are expected.
ALLOW_OLD_TODO_FILES = {
    'scripts/full-scan.sh',
    'scripts/hygiene-scan.py',
    'docs/MACOS_BUILD_TROUBLESHOOTING.md',
    'docs/LOCKRAIL_COMPLETE_ARCHITECTURE.md',
}

ALLOW_SECRET_FILES = {
    'crates/lockrail-protocol/src/seal.rs',
    'crates/lockrail-protocol/src/lib.rs',
    'README.md',
    'scripts/full-scan.sh',
    'scripts/hygiene-scan.py',
    'docs/MACOS_BUILD_TROUBLESHOOTING.md',
    'docs/LOCKRAIL_COMPLETE_ARCHITECTURE.md',
}

ALLOW_UNWRAP_TEST_FILES = {
    'crates/lockrail-audit/src/lib.rs',
    'crates/lockrail-protocol/src/lib.rs',
    'crates/lockrail-vault/src/lib.rs',
    'crates/lockrail-cli/tests/lrap_flow.rs',
}

def files():
    for p in ROOT.rglob('*'):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name == 'Cargo.lock':
            continue
        if p.suffix not in TEXT_EXTS and p.name != 'Cargo.toml':
            continue
        yield p

def rel(p):
    return str(p.relative_to(ROOT))

failures = []
for p in files():
    rp = rel(p)
    text = p.read_text(errors='ignore')
    for i, line in enumerate(text.splitlines(), 1):
        if old_name_re.search(line) and rp not in ALLOW_OLD_TODO_FILES:
            failures.append((rp, i, 'old-name', line.strip()))
        if todo_re.search(line) and rp not in ALLOW_OLD_TODO_FILES:
            failures.append((rp, i, 'todo', line.strip()))
        if secret_re.search(line) and rp not in ALLOW_SECRET_FILES and '/tests/' not in rp:
            failures.append((rp, i, 'secret-marker', line.strip()))
        if unwrap_re.search(line) and rp not in ALLOW_UNWRAP_TEST_FILES and rp not in ALLOW_OLD_TODO_FILES and '/tests/' not in rp:
            failures.append((rp, i, 'runtime-unwrap', line.strip()))

if failures:
    for f in failures:
        print(f'{f[0]}:{f[1]}:{f[2]}: {f[3]}')
    sys.exit(1)
print('hygiene ok')
