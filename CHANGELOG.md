# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `lockrail proxy` — HTTPS intercepting proxy that scans all AI API traffic (api.openai.com, api.anthropic.com, etc.) for secrets before they reach the model
- `lockrail proxy install-ca` — generates a local CA certificate and installs it in the system trust store
- `lockrail proxy start` — runs the local HTTPS proxy on port 8789
- `lockrail hook post-tool-use` — Claude Code PostToolUse hook; blocks secrets in tool output before the model incorporates them
- `lockrail ai hooks` now installs both UserPromptSubmit and PostToolUse hooks for Claude Code
- `lockrail seal` in plain (non-`--json`) mode now outputs only the safe text, not the full JSON object
- `lockrail relay check` now actually pings the relay healthz endpoint and exits 1 when unreachable
- `--quiet --json` combination now correctly emits JSON output (quiet suppresses stderr noise only)
- `vault_permissions` in `lockrail doctor` now displays in octal (e.g. `0600`) instead of decimal

### Changed
- Relay startup now uses `FileReplayStore` and `FileUsageStore` by default (was already the case; confirmed correct)
- `get_key` renamed to `use_key` (records last-used timestamp; more accurate name)
- Relay `response.text().await` errors now propagate instead of silently returning empty string
- `--quiet` flag no longer suppresses `--json` output
- `revoke_agent` now uses a single `get_mut` call instead of two
- `sha256_hex` avoids double allocation

### Fixed
- `atty` replaced with `std::io::IsTerminal` (atty had known soundness issues)
- `ai install-hooks` no longer panics on malformed `settings.json`
- `inject.rs` now uses `BTreeMap` for deterministic env var ordering

## [0.2.0] - 2025-01-01

### Added
- LRAP/0.3 capability protocol with agent proof binding
- Encrypted local vault (AES-256-GCM + Argon2id)
- Replay protection and max-use enforcement
- Hash-chained audit log with tamper detection
- SSRF denial with DNS rebinding protection
- Signed receipts
- Secret scanning: 30+ vendor formats, JWT, private key blocks, Shannon entropy
- Claude Code, Codex, Cursor, Antigravity shim support
- `lockrail env scan/seal/run` for .env file workflows
- `lockrail proof pack` for compliance exports
- `lockrail sync` for GitHub Actions and Vercel secret push
- Local UI dashboard (`lockrail ui`)
- `lockrail ai enable/hooks` for AI tool skill and hook installation

## [0.1.0] - 2024-12-01

### Added
- Initial local vault and secret scanning prototype

[Unreleased]: https://github.com/lockrail/lockrail/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/lockrail/lockrail/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lockrail/lockrail/releases/tag/v0.1.0
