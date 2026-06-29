# Lockrail

[![CI](https://github.com/lockrail/lockrail/actions/workflows/ci.yml/badge.svg)](https://github.com/lockrail/lockrail/actions/workflows/ci.yml)
[![Security](https://github.com/lockrail/lockrail/actions/workflows/security.yml/badge.svg)](https://github.com/lockrail/lockrail/actions/workflows/security.yml)
[![crates.io](https://img.shields.io/crates/v/lockrail.svg)](https://crates.io/crates/lockrail)

**Local secret firewall for AI coding tools.**

AI tools read your .env files, your terminal output, and everything you type. Lockrail intercepts secrets before they reach the model, stores them encrypted locally, and only allows real API use through policy-checked relay calls — with a signed, verifiable audit trail.

## Install

```bash
cargo install lockrail
lockrail init
lockrail protect --tool all
```

## Quick demo

```bash
lockrail demo
echo 'OPENAI_API_KEY=sk-proj-...' | lockrail seal
```

## How it works

```
Your terminal input
  → Lockrail secret scanner (30+ vendor formats + entropy)
  → Secrets replaced with lockrail://secret/... handles
  → AI tool receives only safe handles

Agent needs to call an API
  → Capability token (LRAP): time-bound, signed, max-use enforced
  → Relay checks policy: host, path, method, SSRF, replay, usage
  → Secret injected at last moment — model never had it
  → Signed receipt + chained audit event written
```

## Core commands

```bash
lockrail init                          # First-time setup
lockrail protect --tool all            # Install shims for claude, codex, cursor, agy
lockrail demo                          # See interception in action
lockrail status                        # Vault, tools, recent activity
lockrail ui                            # Local dashboard (localhost only)

# Secrets
lockrail seal                          # Seal stdin — outputs safe handles
lockrail scan                          # Scan stdin — report findings only
lockrail pipe                          # Filter piped output before paste
lockrail secret set MY_KEY             # Store a secret (prompted)
lockrail secret list                   # List stored secrets (metadata only)
lockrail secret import .env            # Import from .env file
lockrail secret export --format dotenv # Export to .env (plaintext — handle with care)

# Relay
lockrail relay start                   # Start local HTTP relay
lockrail relay check                   # Check if relay is running
lockrail capability issue MY_KEY       # Issue time-bound capability token
lockrail capability inspect <token>    # Decode a token

# Proxy (HTTPS interception for all AI tools)
lockrail proxy install-ca              # Generate CA + install in system trust store
lockrail proxy start                   # Start HTTPS intercepting proxy
lockrail proxy status                  # Check proxy is running

# Audit
lockrail audit verify                  # Verify hash chain — detect tampering
lockrail audit list                    # Show recent events

# AI tool integration
lockrail ai enable                     # Install Lockrail skill in Claude/Codex/Cursor
lockrail ai hooks --tool claude        # Install Claude Code UserPromptSubmit + PostToolUse hooks
```

## What Lockrail protects

| Surface | Protection |
|---|---|
| Terminal stdin | Scanned and sealed before AI tool sees it |
| .env files | Handle-based sealing — safe for agent inspection |
| Terminal/command output | Scanned before output returns to model |
| API responses | Relay scans response bodies for leaked secrets |
| All AI API traffic (proxy mode) | HTTPS intercept for claude, cursor, codex, browsers |
| Relay calls | Signed capabilities, replay protection, SSRF blocking |
| Audit trail | Hash-chained, tamper-evident, signed receipts |

## What Lockrail does not protect

- GUI or browser flows not going through the proxy
- Clipboard capture, keyloggers, or malware
- A fully compromised host while the vault is unlocked

## How it compares

| | Lockrail | Infisical Agent Vault | ggshield ai-hook | Pipelock | Doppler/Phase |
|---|---|---|---|---|---|
| Intercepts AI tool prompts | Yes (shim + proxy) | No | 4 tools only | No | No |
| Opaque handle round-trip | Yes (LRAP) | No | No | No | No |
| Local / no cloud required | **Yes** | **No** (needs server) | No (cloud API) | Yes | No |
| No account needed | **Yes** | No | No | Yes | No |
| SSRF + DNS rebinding protection | Yes | Partial | No | Partial | No |
| Signed audit receipts | **Yes** | No | No | No | No |
| Response body scanning | **Yes** | No | No | No | No |

**Infisical Agent Vault** requires PostgreSQL + Redis + a running server (no offline mode — three unresolved GitHub issues confirm this). Lockrail works standalone with a single binary.

**ggshield ai-hook** requires a GitGuardian account and cloud API; blocks pre-prompt for 4 tools only; only notifies (does not block) on post-tool-use secrets.

**Pipelock** scans HTTP traffic at egress but does not intercept what enters the model's context window and has no reversible tokenization.

## Vault security

- AES-256-GCM encryption with Argon2id KDF (OWASP recommended parameters)
- Per-save fresh nonce and salt
- File permissions 0o600 on Unix
- Atomic writes with fsync
- Agent private keys stored encrypted in vault — never plaintext on disk

## Author

Built by [Het Mehta](https://hetmehta.com) — [hi@hetmehta.com](mailto:hi@hetmehta.com) — [@hetmehtaa](https://x.com/hetmehtaa)

## License

MIT OR Apache-2.0
