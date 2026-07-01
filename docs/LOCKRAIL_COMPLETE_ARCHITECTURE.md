# Lockrail Complete Working Architecture

## One-line explanation

**Lockrail is a local-first secret firewall for AI coding tools. It catches API keys, tokens, passwords, and other secrets before AI models see them, encrypts those secrets locally, replaces them with safe `lockrail://secret/...` handles, and only releases or uses the real secret through policy-controlled tool calls.**

## Why Lockrail exists

AI tools like Claude Code, Codex, Cursor, MCP servers, and custom agents often touch developer secrets:

- API keys pasted into prompts
- `.env` values read by an agent
- cloud tokens exposed in shell output
- Slack/Jira/GitHub/Stripe keys used by tools
- upstream API responses accidentally returning sensitive values

Without a guardrail, these secrets can enter the model context, logs, terminal history, or tool traces.

Lockrail creates a local trust boundary:

```text
Human / agent workflow
        |
        v
Lockrail secret firewall
        |
        +-- detects raw secrets
        +-- encrypts them locally
        +-- replaces them with safe handles
        +-- audits what happened
        |
        v
AI tool sees handles, not raw secrets
```

## User experience

The target daily UX is:

```bash
curl -fsSL https://raw.githubusercontent.com/lockrail/lockrail/main/install.sh | sh
```

After setup, open a new terminal and use tools normally:

```bash
claude
codex
cursor
```

Lockrail installs PATH shims so `claude`, `codex`, and `cursor` run through Lockrail first.

A prompt like this:

```text
Use this key: sk-proj-abcdefghijklmnopqrstuvwxyz123456
```

is transformed before the agent sees it:

```text
Use this key: lockrail://secret/openai-key/fp_a1b2c3d4e5f6...
```

The raw key is stored encrypted in the local vault.

## Main components

```text
lockrail-cli
├── setup / doctor / install-shims
├── scan / seal / hook prompt
├── run -- <tool>
├── protect <vendor>
├── serve relay
└── audit verify

lockrail-protocol
├── secret detection and sealing
├── LRAP capability tokens
├── LRAP request proofs
├── request caveat enforcement
└── receipts

lockrail-vault
├── encrypted local vault
├── stored secrets
├── issuer signing key
├── agent signing keys
├── capability revocation
└── capability usage counters

lockrail-relay
├── validates capabilities
├── enforces host/method/path policy
├── verifies agent request proofs
├── injects real credentials into outbound requests
├── scans upstream responses for leaked secrets
└── emits receipts and audit events

lockrail-audit
├── append-only JSONL audit log
└── tamper-evident hash chain
```

## Data directories

By default Lockrail uses:

```text
~/.lockrail/
├── vault.lockrail        # encrypted vault envelope
├── audit.jsonl           # hash-chained audit log
├── replay-cache.json     # replay protection cache
├── agents/               # local agent signing keys
└── bin/                  # shims for claude/codex/cursor
```

You can override the home directory:

```bash
export LOCKRAIL_HOME=/custom/path
```

The vault password is provided through:

```bash
```

## Secret sealing flow

### 1. User input enters Lockrail

Input can come from:

- `lockrail seal`
- `lockrail hook prompt`
- `lockrail run -- claude`
- a PATH shim like `~/.lockrail/bin/claude`

### 2. Lockrail scans the text

The scanner detects common sensitive values:

- OpenAI-style keys: `sk-proj-...`
- generic `sk-...` API keys
- Slack tokens: `xoxb-...`, `xoxp-...`
- GitHub tokens: `ghp_...`, `github_pat_...`
- AWS access/session key IDs: `AKIA...`, `ASIA...`
- Bearer tokens
- JWT-like tokens
- private key blocks
- assignment-style secrets like `api_key=...`, `password=...`, `client_secret=...`
- generic high-entropy tokens

### 3. Lockrail fingerprints the secret

Each secret gets a stable fingerprint:

```text
fingerprint = first 16 hex chars of SHA-256(secret)
```

Example:

```text
fp_a1b2c3d4e5f6a7b8
```

### 4. Lockrail encrypts the raw value

The raw value is stored in the encrypted vault under a name like:

```text
sealed/fp_a1b2c3d4e5f6a7b8
response/openai-key/fp_a1b2c3d4e5f6a7b8
```

### 5. Lockrail replaces the text

The agent/model receives a safe handle:

```text
lockrail://secret/openai-key/fp_a1b2c3d4e5f6a7b8
```

On intercepted flows, the raw key is replaced before it reaches the model context.

## CLI examples

### Scan without storing

```bash
echo 'my key is sk-proj-abcdefghijklmnopqrstuvwxyz123456' | lockrail scan
```

This reports detections and safe text, but does not store secrets.

### Seal and store

```bash
echo 'my key is sk-proj-abcdefghijklmnopqrstuvwxyz123456' | lockrail seal --json
```

Output contains:

```json
{
  "count": 1,
  "safe_text": "my key is lockrail://secret/openai-key/fp_...",
  "handles": ["lockrail://secret/openai-key/fp_..."]
}
```

### Protect a vendor API key

```bash
printf 'sk-live-stripe-key' | lockrail protect stripe --secret - --agent-id agt_xxx
```

This stores the key and issues a constrained capability for Stripe.

### Protect an unknown vendor

```bash
printf 'vendor-token' | lockrail protect generic --secret - --host api.vendor.com --agent-id agt_xxx
```

### Direct AI tool protection

After:

```bash
lockrail setup
```

Run:

```bash
claude
```

The shell finds:

```text
~/.lockrail/bin/claude
```

which forwards to:

```bash
lockrail run -- claude
```

## PATH shim architecture

Lockrail creates small wrapper scripts:

```text
~/.lockrail/bin/claude
~/.lockrail/bin/codex
~/.lockrail/bin/cursor
```

Each shim looks conceptually like:

```sh
#!/bin/sh
LOCKRAIL_SHIM=1 exec /path/to/lockrail run -- claude "$@"
```

Lockrail detects `LOCKRAIL_SHIM=1` to avoid recursion. It searches PATH for the real `claude` binary while skipping the shim path.

```text
user runs claude
      |
      v
~/.lockrail/bin/claude shim
      |
      v
lockrail run -- claude
      |
      v
real claude binary
```

## Interactive PTY guard

When `lockrail run -- claude` is used interactively, Lockrail starts the child process in a pseudo-terminal (PTY):

```text
user terminal
  -> lockrail PTY parent
  -> real claude child process
```

Current behavior:

- reads submitted input line-by-line
- scans the line for secrets
- seals any detected secrets
- forwards the safe line to the child process
- mirrors child output back to the terminal

This protects many common paste/type flows. It is the first interactive protection layer. A fully polished terminal emulator with advanced paste detection and resize handling is a future hardening layer.

## Relay architecture

Lockrail also has an explicit HTTP relay for tools/API calls.

```text
agent/tool
  -> POST /relay with capability + request
  -> Lockrail verifies policy
  -> Lockrail injects real credential
  -> upstream API
  -> Lockrail scans response
  -> agent receives safe response
```

Relay request shape:

```json
{
  "capability": "lrap2....",
  "method": "POST",
  "upstream": "https://api.openai.com/v1/chat/completions",
  "headers": {"Content-Type": "application/json"},
  "json": {"model": "gpt-4.1-mini", "messages": []},
  "proof": {"payload": {}, "signature": "..."}
}
```

The relay:

1. verifies capability signature
2. enforces host/method/path caveats
3. verifies optional LRAP agent proof
4. checks replay cache
5. decrypts the real credential from vault
6. injects it into the request
7. forwards upstream
8. scans upstream response for leaked secrets
9. returns safe response with a receipt

## LRAP: Lockrail Request Attestation Protocol

LRAP is Lockrail's protocol for proof-bound credential use.

A capability token says:

```text
This agent may use this credential for this host/method/path, until this time, with these limits.
```

A proof says:

```text
This exact agent signed this exact request body, URL, method, task, and purpose.
```

Together:

```text
capability + proof + policy = safe credential use
```

## Capability token format

```text
lrap2.<base64url(canonical_json(claims))>.<base64url(ed25519_signature)>
```

Claims include:

```json
{
  "version": "LRAP/0.2",
  "cap_id": "uuid",
  "key": "openai",
  "aud": "lockrail-relay",
  "iat": 1710000000,
  "exp": 1710003600,
  "allowed_hosts": ["api.openai.com"],
  "allowed_methods": ["POST"],
  "allowed_paths": ["/v1/*"],
  "inject_header": "Authorization",
  "inject_prefix": "Bearer ",
  "max_uses": 100,
  "agent_public_key": "base64url-ed25519-public-key",
  "task_id": "ticket-123",
  "purpose": "summarize-ticket"
}
```

## Proof format

```json
{
  "payload": {
    "version": "LRAP/0.2",
    "agent_id": "agt_...",
    "capability_hash": "sha256:...",
    "method": "POST",
    "upstream": "https://api.openai.com/v1/chat/completions",
    "body_hash": "sha256:...",
    "nonce": "...",
    "timestamp": 1710000000,
    "task_id": "ticket-123",
    "purpose": "summarize-ticket"
  },
  "signature": "base64url-ed25519-signature"
}
```

## Cryptography used

### Vault encryption

Lockrail stores secrets in an encrypted local vault.

The vault uses:

- **Argon2id** for password-based key derivation
- **AES-256-GCM** for authenticated encryption
- random salt
- random nonce
- authenticated metadata

Vault file:

```json
{
  "version": 1,
  "kdf": {
    "name": "argon2id",
    "memory_kib": 19456,
    "iterations": 2,
    "parallelism": 1,
    "output_len": 32
  },
  "salt": "base64url-random-salt",
  "nonce": "base64url-random-nonce",
  "ciphertext": "base64url-aes-gcm-ciphertext"
}
```

The vault does not store raw secrets in plaintext.

### Capability signatures

Capabilities are signed with:

- **Ed25519** issuer signing key

The issuer signing key is stored inside the encrypted vault.

### Agent proofs

Agent request proofs are signed with:

- **Ed25519** agent signing keys

Each local agent has a keypair in:

```text
~/.lockrail/agents/
```

The public key can be bound into capabilities.

### Hashing

Lockrail uses:

- **SHA-256** for fingerprints
- **SHA-256** for capability hashes
- **SHA-256** for body hashes
- **SHA-256** for audit hash chains
- **SHA-256** for receipt hashes

### Encoding

Lockrail uses:

- **base64url without padding** for token parts and key bytes
- canonical JSON for signed payloads

## Audit log

Lockrail writes an append-only JSONL audit log:

```text
~/.lockrail/audit.jsonl
```

Each event includes:

```json
{
  "sequence": 1,
  "timestamp": 1710000000,
  "actor": "local-user",
  "action": "seal.text",
  "resource": "sealed",
  "metadata": {},
  "previous_hash": "sha256:...",
  "event_hash": "sha256:..."
}
```

Each event hash depends on the previous event hash. If an old event is modified or deleted, verification fails.

Verify audit log:

```bash
lockrail audit verify
```

## Response leak scanning

Lockrail scans upstream API responses before returning them to agents.

If a response contains:

```text
secret sk-proj-responseleak...
```

Lockrail returns:

```text
secret lockrail://secret/openai-key/fp_...
```

The raw response secret is sealed in the vault under:

```text
response/<kind>/<fingerprint>
```

This prevents tool/API responses from leaking secrets back into the model context.

## Vendor presets

Lockrail includes built-in presets for common services:

- OpenAI
- Anthropic
- GitHub
- Slack
- Stripe
- Jira / Atlassian
- AWS
- GCP
- Azure
- generic HTTP APIs

Example:

```bash
printf 'xoxb-token' | lockrail protect slack --secret - --agent-id agt_xxx
```

Generic fallback:

```bash
printf 'token' | lockrail protect generic --secret - --host api.vendor.com --agent-id agt_xxx
```

## What happens in the background during setup

Command:

```bash
curl -fsSL https://raw.githubusercontent.com/lockrail/lockrail/main/install.sh | sh
```

Does:

1. creates `~/.lockrail` if missing
2. creates encrypted vault if missing
3. creates default local agent key if missing
4. installs shims into `~/.lockrail/bin`
5. updates shell rc to add `~/.lockrail/bin` before normal PATH
6. prints next steps

Then:

```bash
claude
```

actually runs:

```bash
~/.lockrail/bin/claude
```

which runs:

```bash
lockrail run -- claude
```

## What Lockrail protects against

Lockrail helps prevent:

- accidental key pasting into prompts
- raw secrets entering model context
- secrets stored in chat transcripts
- secrets stored in tool logs
- upstream responses leaking secrets to the agent
- stolen capabilities being reused without proof-bound context
- tampering with local audit history going unnoticed

## What Lockrail does not fully protect against

Lockrail does **not** protect against:

- full local machine compromise while vault is unlocked
- malware reading your terminal before Lockrail sees it
- screenshots or clipboard managers capturing secrets before input
- browser/GUI chat input unless a browser extension or app hook is installed
- all possible secret formats with 100% accuracy
- malicious upstream services receiving credentials that policy allows
- AWS SigV4 signing yet: AWS requires a dedicated signer adapter for full support

## Current project status

Current full scan passes:

```text
cargo metadata: pass
cargo fmt: pass
cargo check: pass
cargo test: pass
cargo build: pass
cargo clippy -D warnings: pass
hygiene scan: pass
```

Current tests:

```text
7 passed
0 failed
```

## Recommended explanation to others

Use this short version:

> Lockrail is a local secret firewall for AI coding tools. It installs shims for tools like Claude and Codex, scans prompts and tool traffic for secrets, encrypts any detected secret into a local AES-GCM vault, replaces it with a safe handle, and only lets agents use real credentials through signed, policy-bound relay calls. Under the hood it uses Argon2id, AES-256-GCM, Ed25519 signatures, SHA-256 fingerprints, and a tamper-evident audit log.

## Recommended demo

```bash
lockrail setup

echo 'Use sk-proj-abcdefghijklmnopqrstuvwxyz123456' | lockrail seal --json

grep -R 'sk-proj-abcdefghijklmnopqrstuvwxyz123456' ~/.lockrail \
  && echo 'BAD: plaintext leaked' \
  || echo 'OK: no plaintext secret in Lockrail files'
```

Expected:

```text
safe_text contains lockrail://secret/...
OK: no plaintext secret in Lockrail files
```
