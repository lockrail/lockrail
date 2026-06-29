# LRAP v0.2 - Lockrail Request Attestation Protocol

LRAP binds credential use to an agent-signed request proof.

## Capability token

```text
lrap2.<base64url(canonical_json(claims))>.<base64url(ed25519_signature)>
```

Claims include:

- `cap_id`
- `key`
- `aud = lockrail-relay`
- `iat`, `exp`
- `allowed_hosts`
- `allowed_methods`
- `allowed_paths`
- `inject_header`, `inject_prefix`
- `max_uses`
- optional `agent_public_key`
- optional `task_id`
- optional `purpose`

## Proof

```json
{
  "payload": {
    "version": "LRAP/0.2",
    "agent_id": "agt_...",
    "capability_hash": "sha256:...",
    "method": "POST",
    "upstream": "https://api.example.com/v1/do",
    "body_hash": "sha256:...",
    "nonce": "...",
    "timestamp": 1710000000,
    "task_id": "...",
    "purpose": "..."
  },
  "signature": "base64url(ed25519(payload))"
}
```

## Security properties

- Stolen capability alone is not enough.
- Proof is request-specific.
- Replay is rejected.
- Task and purpose are enforceable.
- Receipts become audit evidence.
