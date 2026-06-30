# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.6] - 2026-07-01

### Changed
- `lockrail setup` now recovers from older password-based local state by archiving the previous `~/.lockrail` directory and creating a fresh auto-managed setup when no generated vault key exists.
- Installers now ignore stale `LOCKRAIL_PASSWORD` values during automatic setup, so old shell exports do not poison new installs.
- Installers now print clearer recovery commands for setup failures and warn when the shell resolves `lockrail` to a different binary than the one just installed.
- README now documents update, stale PATH, unset-password, and reset flows.

## [0.3.5] - 2026-07-01

### Changed
- Release installers now run `lockrail setup` automatically after installing the binary, so the normal install path is a single command.
- `lockrail setup` now generates a random local vault key and stores it at `~/.lockrail/vault.key` with private file permissions by default.
- Vault-opening commands now reuse the generated local key automatically; users no longer need to export `LOCKRAIL_PASSWORD` for normal use.
- README and quickstart now present the simple path first and keep Cargo as the source-build fallback.

## [0.3.4] - 2026-07-01

### Changed
- `lockrail setup` is now the simple first-run path: it creates the local vault, generates local agent keys, installs default tool shims, and prints the PATH command and next steps.
- Install docs and installer next-step output now consistently point to `lockrail setup` instead of a multi-command `init` / `protect` sequence.
- README and quickstart now explicitly state that Homebrew is not supported yet, so users do not try the non-existent `lockrail/tap`.

### Fixed
- `lockrail setup` no longer requires users to know `--apply` or pre-set `LOCKRAIL_PASSWORD`; it prompts for the local vault password when creating a new vault.

## [0.3.3] - 2026-06-30

### Added
- Branded `install.sh` and `install.ps1` bootstrap output for prebuilt binary installs, avoiding Cargo's dependency download/build stream for normal users.
- Release notes and README now point users to the no-Rust installer first, with `cargo install lockrail` kept as the source-build fallback.

### Changed
- `lockrail init` and `lockrail status` now use compact `lockrail//...` console output with clearer vault, audit, network, shim, and security sections.

## [0.3.2] - 2026-06-30

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

[Unreleased]: https://github.com/lockrail/lockrail/compare/v0.3.6...HEAD
[0.3.6]: https://github.com/lockrail/lockrail/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/lockrail/lockrail/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/lockrail/lockrail/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/lockrail/lockrail/compare/041225b...v0.3.3
[0.3.2]: https://github.com/lockrail/lockrail/compare/v0.2.0...041225b
[0.2.0]: https://github.com/lockrail/lockrail/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lockrail/lockrail/releases/tag/v0.1.0
