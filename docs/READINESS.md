# Lockrail readiness plan

Lockrail's target is 10/10 user and enterprise readiness, but readiness is earned through shipped layers, tests, audits, and real deployments.

## Current implemented layers

- Rust workspace and package metadata
- encrypted local vault
- LRAP capability/proof protocol
- explicit relay
- hash-chained audit log
- vendor presets
- secret scanning/sealing primitive
- `lockrail scan`
- `lockrail seal`
- `lockrail protect`
- `lockrail run -- <cmd>` stdin wrapper plus initial interactive PTY line guard
- `lockrail doctor` local health checks
- `lockrail install-shims` PATH shims for direct `claude` / `codex` protection
- `lockrail hook prompt` before-submit prompt sealing hook
- `lockrail setup` shell alias/quickstart output
- improved scanner: JWT, private key blocks, high-entropy token heuristics
- relay response leak scanning and sealing
- replay cache file permission hardening

## Required for consumer 10/10

- Interactive PTY wrapper for Claude/Codex/Cursor CLI (initial line-guard implemented; needs terminal polish)
- Shell installer and Homebrew formula
- Auto setup: aliases/wrappers without manual config
- Browser extension for Claude/ChatGPT/Gemini web chats
- Local daemon with menubar/status UI
- High-quality secret detector with entropy scoring and vendor regex packs
- Safe secret handle UX and one-click reveal/use policy

## Required for enterprise 10/10

- SQLite state and migrations
- Policy engine (Cedar or custom constrained DSL)
- AWS SigV4 signer adapter
- OAuth adapters for Slack/Jira/GitHub/Google/Microsoft
- MCP gateway/adapter
- Response leak scanning
- SSO/OIDC/SCIM for team mode
- Central audit export (JSONL/OCSF/SIEM)
- Signed releases, SBOM, cargo audit/deny
- Fuzzing for parsers/protocol canonicalization
- External security review
- Threat model and formal test vectors

## Release gates

- Alpha: local CLI sealing + non-interactive `run`
- Beta: interactive PTY wrapper + relay + presets + tests passing on macOS/Linux
- 1.0: signed installers + browser extension + MCP adapter + AWS signer + security review
