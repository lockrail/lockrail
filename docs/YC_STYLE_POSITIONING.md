# Positioning

## The problem

AI coding agents can read secrets from prompts, .env files, terminal output, and API responses. Every tested AI IDE tool (Claude Code, Cursor, Copilot, Codex) transmits secrets to the AI provider's API unless explicitly prevented. Claude Code's feature request for secret redaction was closed "not planned." Cursor stores API keys in an unprotected local SQLite database. The secret leak rate for AI-assisted commits is double the baseline.

## What exists and why it is not enough

- **Secret managers** (Vault, Infisical, Doppler, Phase): Store and inject secrets into processes. None intercept what goes into AI model context.
- **Infisical Agent Vault** (April 2026): HTTPS_PROXY MITM — closest technical competitor. **Requires a running Infisical server** (PostgreSQL + Redis). No offline mode. Three GitHub issues requesting local-only mode remain unimplemented.
- **ggshield ai-hook** (March 2026): Pre-prompt blocking for 4 tools. Requires cloud API account. Does not block post-tool-use output (notify only).
- **Pipelock** (May 2026): Scans AI API egress traffic. No reversible tokenization. No vault. No signed receipts.
- **MCP secret servers** (Doppler, 1Password, HashiCorp): Pass raw plaintext secrets to the AI model. Architecturally backward — 24,008 plaintext secrets found in public MCP configs in 2025.

## The gap

No tool simultaneously provides: local + no-account + real-time interception + opaque reversible handles + SSRF egress policy + response scanning + signed audit trail.

## Lockrail's position

The only local-first, zero-dependency secret firewall for AI tools that works completely offline with a single binary. Lockrail intercepts secrets at the terminal level (shim), at the HTTPS transport level (proxy), and at the relay level (LRAP capability protocol) — covering the full path from developer input to AI API response.

## One-liner

Lockrail stops secrets from entering AI tool context — locally, without a server, with a verifiable audit trail.

## Moat

- LRAP capability protocol: opaque handle round-trip that survives LLM reasoning
- Signed receipts: the only tool with cryptographic proof of what was intercepted
- Response body scanning: catches secrets leaking back in API responses
- Post-tool-use blocking: Claude Code hook that blocks secrets in tool output before the model sees them
- No server dependency: works offline; Infisical's closest equivalent requires a server
