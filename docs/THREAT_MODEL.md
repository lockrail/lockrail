# Threat Model

## Assets

- Local vault contents
- Agent private signing keys
- Capability tokens
- Replay and usage state
- Audit chain and signed receipts

## Trust boundaries

1. User terminal input entering Lockrail
2. Vault encryption boundary at rest
3. LRAP capability verification boundary
4. Relay egress boundary to upstream APIs
5. Response sealing boundary before data returns to an agent

## Primary threats

- Prompt or stdin secrets reaching an agent unchanged
- Relay SSRF into localhost, metadata, or private networks
- Capability theft without proof binding
- Replay of a previously valid proof
- Unlimited repeated use of a leaked capability
- Tampering with receipts or audit history
- Plaintext private agent keys under `~/.lockrail`

## Implemented mitigations

- Central sealing pipeline with handle replacement
- Encrypted vault and encrypted agent key storage
- Audience, time, task, purpose, and proof validation
- Replay store and usage store enforcement
- Signed receipts and audit hash chaining
- Default SSRF blocks and no redirects

## Residual risks

- Host compromise while the vault is unlocked
- GUI/browser-only flows outside Lockrail hooks
- Incomplete network-level protection against every DNS rebinding edge case
- Current relay secret injection path is still header-centric
- Unpublished crates and unrun supply-chain tooling do not change the local
  security path, but they still matter for release trust and must be checked
  before broader distribution
