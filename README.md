<p align="center">
  <img src="assets/banner.svg" alt="Lockrail" width="600">
</p>

<p align="center">
  <a href="https://github.com/lockrail/lockrail/actions/workflows/ci.yml"><img src="https://github.com/lockrail/lockrail/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/lockrail/lockrail/actions/workflows/security.yml"><img src="https://github.com/lockrail/lockrail/actions/workflows/security.yml/badge.svg" alt="Security"></a>
  <a href="https://crates.io/crates/lockrail"><img src="https://img.shields.io/crates/v/lockrail.svg" alt="crates.io"></a>
  <a href="https://img.shields.io/crates/d/lockrail"><img src="https://img.shields.io/crates/d/lockrail.svg" alt="Downloads"></a>
  <img src="https://img.shields.io/badge/rust-1.96%2B-orange.svg" alt="Rust 1.96+">
  <img src="https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-green.svg" alt="License">
</p>

<p align="center">
  <b>AI tools read everything you type. Lockrail stops your secrets from reaching them.</b>
</p>

---

Lockrail sits between you and your AI coding tool. Secrets are intercepted before they enter the model's context window, encrypted locally with AES-256-GCM, and replaced with opaque handles. When the agent needs to make an API call, a time-bound signed token is checked against relay policy — the raw secret is injected at the last moment and never stored in any model context.

No cloud. No account. Single binary.

---

## Features

- **Two interception modes** — PTY shim (wraps any CLI tool) or conservative HTTPS proxy (`lockrail proxy`, port 8789)
- **30+ detection patterns** — OpenAI, Anthropic, AWS, GCP, GitHub, npm, PyPI, HuggingFace, JWT, private keys, high-entropy strings
- **Opaque handle round-trip** — `lockrail://secret/<name>/<fp>` replaces plaintext; model cannot reconstruct the original
- **Local encrypted vault** — AES-256-GCM + Argon2id KDF (19,456 KiB, 2 iterations), file perms 0600, atomic writes with fsync
- **LRAP capability tokens** — Ed25519-signed, time-bound, max-use enforced, replayed tokens rejected
- **SSRF + DNS rebinding protection** — relay blocks localhost, link-local, metadata endpoints, and rebinding attempts
- **Hash-chained audit log** — SHA-256 chained events with signed receipts; `lockrail audit verify` detects any tampering
- **Claude Code hooks** — UserPromptSubmit and PostToolUse hooks block secrets entering and leaving the model
- **Works offline** — vault, relay, and proxy all run locally; no Lockrail cloud required
- **Supports** Claude Code · Codex · Cursor · Antigravity · any MCP server

## Install

```bash
cargo install lockrail
```

Or download a prebuilt binary for your platform from [Releases](https://github.com/lockrail/lockrail/releases).

**Supported:** macOS (ARM, Intel) · Linux (x86\_64, ARM64) · Windows (x86\_64)

## Quickstart

```bash
export LOCKRAIL_PASSWORD="$(openssl rand -base64 32)"
lockrail init --yes
lockrail ai hooks                   # install Claude Code hooks (UserPromptSubmit + PostToolUse)
lockrail demo                       # see interception in action
```

Or use the HTTPS proxy instead of PTY shims:

```bash
lockrail proxy install-ca           # generate local CA + install in system trust store
lockrail proxy start                # start HTTPS intercepting proxy on :8789
```

## How it works

```
Input path (PTY shim or HTTPS proxy)
  → secret scanner  (30+ patterns, Shannon entropy)
  → plaintext sealed → AES-256-GCM vault  →  lockrail://secret/<name>/<fp>
  → AI tool receives only the opaque handle

Agent makes an API call
  → LRAP capability token (Ed25519-signed, time-bound, max-use)
  → relay checks: host · path · SSRF · replay · usage limits
  → secret injected at last millisecond — model context never held it
  → signed receipt written → SHA-256 chained audit event appended
```

## Commands

<details>
<summary><b>Setup</b></summary>

| Command | Description |
|---|---|
| `lockrail init` | First-time setup — create vault, generate keys |
| `lockrail protect --tool all` | Install PTY shims for claude, codex, cursor, agy |
| `lockrail ai hooks` | Install Claude Code UserPromptSubmit + PostToolUse hooks |
| `lockrail ai enable` | Install Lockrail skill file into Claude/Codex/Cursor config |
| `lockrail status` | Vault state, installed tools, recent activity |
| `lockrail doctor` | Diagnose common configuration problems |
| `lockrail ui` | Open local dashboard (localhost, token-protected) |

</details>

<details>
<summary><b>Secrets</b></summary>

| Command | Description |
|---|---|
| `lockrail secret set <NAME>` | Store a secret (value prompted, never echoed) |
| `lockrail secret list` | List stored secrets (metadata only — no plaintext) |
| `lockrail secret delete <NAME>` | Remove a secret from the vault |
| `lockrail secret import <FILE>` | Bulk import from a `.env` file |
| `lockrail secret export --format dotenv` | Export to plaintext `.env` — handle with care |
| `lockrail seal` | Read stdin, seal any secrets found, print safe output |
| `lockrail scan` | Read stdin, report findings only — nothing is stored |
| `lockrail pipe` | Filter piped output before pasting into an AI tool |

</details>

<details>
<summary><b>Relay</b></summary>

| Command | Description |
|---|---|
| `lockrail relay start` | Start local HTTP relay |
| `lockrail relay check` | Ping relay healthz endpoint; exits 1 if unreachable |
| `lockrail capability issue <NAME>` | Issue a time-bound capability token for a secret |
| `lockrail capability inspect <TOKEN>` | Decode and display token claims |
| `lockrail use-key <NAME>` | Resolve a handle to a secret (records last-used timestamp) |

</details>

<details>
<summary><b>HTTPS Proxy</b></summary>

| Command | Description |
|---|---|
| `lockrail proxy install-ca` | Generate local CA cert + install in system trust store |
| `lockrail proxy start` | Start HTTPS intercepting proxy on port 8789 |
| `lockrail proxy status` | Check if proxy is running and CA is trusted |

</details>

<details>
<summary><b>Audit</b></summary>

| Command | Description |
|---|---|
| `lockrail audit list` | Show recent audit events |
| `lockrail audit verify` | Verify the SHA-256 hash chain — detect any tampering |
| `lockrail proof pack` | Export a signed compliance bundle (zip + manifest) |

</details>

<details>
<summary><b>Sync</b></summary>

| Command | Description |
|---|---|
| `lockrail sync github` | Push secrets to GitHub Actions (X25519 sealed-box) |
| `lockrail sync vercel` | Sync secrets to Vercel environment variables |

</details>

## Protection surface

| Surface | What Lockrail does |
|---|---|
| Terminal stdin | Scanned and sealed before the AI tool sees it |
| `.env` files | Handle-based sealing — safe for agent inspection |
| Tool output / responses | PostToolUse hook scans before the model incorporates it |
| Supported AI API HTTPS hosts (proxy mode) | Scans uncompressed textual/JSON request and response bodies; streams, compressed bodies, and unknown binary content pass through unchanged |
| Relay calls | LRAP token check · SSRF block · replay detection · usage cap |
| Audit log | SHA-256 hash chain · signed receipts · tamper detection |

**Not covered:** GUI flows outside the proxy, clipboard capture, keyloggers, compressed or streaming proxy bodies that cannot be safely rewritten, unsupported AI API hosts, or a fully compromised host while the vault is unlocked.

## Comparison

| | Lockrail | ggshield ai-hook | Infisical Agent Vault | Doppler / Phase |
|---|:---:|:---:|:---:|:---:|
| Intercepts AI prompt context | ✓ | 4 tools | — | — |
| HTTPS proxy for supported AI hosts | ✓ | — | — | — |
| Opaque handle round-trip | ✓ | — | — | — |
| Local vault, no server required | ✓ | — | — | — |
| No account or cloud dependency | ✓ | — | — | — |
| SSRF + DNS rebinding protection | ✓ | — | partial | — |
| Signed audit receipts | ✓ | — | — | — |
| Post-response secret scanning | ✓ | notify only | — | — |
| Open source, MIT / Apache-2.0 | ✓ | ✓ | ✓ | ✓ |

## Cryptography

- **Vault:** AES-256-GCM, fresh 96-bit nonce and 128-bit salt per save
- **KDF:** Argon2id — 19,456 KiB memory, 2 iterations, 1 lane (OWASP recommended)
- **Capability tokens:** Ed25519 (ed25519-dalek), time-bound, max-use enforced, replay-rejected
- **Audit chain:** SHA-256 event hashing, each event includes the hash of the previous
- **Sync encryption:** X25519 sealed-box for GitHub Actions secret push
- **Proxy TLS:** rcgen-generated local CA; rustls with ring backend

All cryptographic material stays on disk at `~/.lockrail/` with 0600 permissions. No keys leave the machine.

## Building from source

```bash
git clone https://github.com/lockrail/lockrail
cd lockrail
cargo build --release
./target/release/lockrail --version
```

Requires Rust 1.96+. Run `rustup update stable` if needed.

## Contributing

Bug reports, feature requests, and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and [SECURITY.md](SECURITY.md) for responsible disclosure.

## Author

[Het Mehta](https://hetmehta.com) — [hi@hetmehta.com](mailto:hi@hetmehta.com) — [@hetmehtaa](https://x.com/hetmehtaa)

## License

MIT OR Apache-2.0
