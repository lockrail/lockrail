# Quickstart

## Install

macOS / Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/lockrail/lockrail/main/install.sh | sh
lockrail setup
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/lockrail/lockrail/main/install.ps1 | iex
lockrail setup
```

Fallback if you want to build from source:

```bash
cargo install lockrail
lockrail setup
```

Homebrew is not supported yet. Do not run `brew tap lockrail/tap`; that tap does not exist.

## Offline demo

```bash
lockrail demo
```

## Seal a pasted secret

```bash
echo 'OPENAI_API_KEY=sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456' | lockrail seal --json
```

Expected result:

- the raw key is replaced with a `lockrail://secret/openai-key/fp_<hash>` handle
- the raw key is stored only in the encrypted local vault
- the audit log records the sealing event without the raw secret

## Check status

```bash
lockrail status
lockrail harness check
lockrail audit verify
```

## Local dashboard

```bash
lockrail ui
```

The UI stays local-only by default and does not render raw secrets.

## Agent-safe `.env` workflow

```bash
lockrail env scan .env
lockrail env seal .env --out .env.lockrail
lockrail env run --file .env.lockrail -- <command>
```

## Output firewall

```bash
some-command | lockrail pipe
```

Use it before pasting logs or command output into an AI tool.
