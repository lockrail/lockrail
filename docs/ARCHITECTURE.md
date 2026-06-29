# Lockrail Architecture

Lockrail is a local-first credential-use firewall for AI coding tools.

It is intentionally narrow: inspect input, seal secrets locally, authorize real
secret use with short-lived capabilities, and enforce the last-mile network
policy at relay time.

## Crates

### `lockrail-protocol`

- secret detection and sealing
- LRAP capability claims and verification
- agent proof signing and verification
- request policy enforcement
- signed receipt generation and verification

### `lockrail-vault`

- Argon2id password KDF
- AES-256-GCM envelope encryption
- encrypted secret storage
- encrypted agent private-key storage
- issuer signing key storage
- revocation and usage metadata

### `lockrail-audit`

- append-only JSONL audit stream
- hash-chain verification
- export and listing support

### `lockrail-relay`

- capability verification
- proof verification
- SSRF-deny policy checks
- replay and max-use enforcement
- upstream forwarding with redirects disabled by default
- response scanning and sealing

### `lockrail`

- setup and doctor UX
- stdin sealing and shim installation
- vault, agent, and capability commands
- relay startup and audit commands

## Product path

```text
stdin / prompt / child input
  -> secret firewall
  -> local vault sealing
  -> safe handle substitution
  -> agent sees only handles

agent proof + capability
  -> relay verification
  -> policy enforcement
  -> replay and usage checks
  -> secret injection at the last moment
  -> upstream request
  -> response scan and reseal
  -> signed receipt + chained audit event
```

## Persistence model

`LOCKRAIL_HOME` defaults to `~/.lockrail` and contains:

- `vault.lockrail`
- `audit.jsonl`
- `config.json`
- `replay-cache.json`
- `usage-store.json`
- `agents/*.agent.json`
- `bin/<shim>`

Only public agent documents are stored in plaintext. Secret values and agent
private keys stay encrypted in the vault.

## Trust boundaries

- Before Lockrail sees a secret: not protected by Lockrail
- After Lockrail sees a secret: raw value should not reach model or agent
  context
- Relay boundary: the only supported place where a real secret is reintroduced
  for upstream use

## Non-goals

- cloud control plane
- SaaS account model
- telemetry pipeline
- secret synchronization service
- enterprise-only code paths
