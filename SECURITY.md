# Security Policy

## Supported versions

| Version | Status |
| --- | --- |
| `0.2.x` | supported |
| older | unsupported |

## Reporting a vulnerability

Open a private security report through the repository security advisory feature
or contact the maintainers through the security contact documented in the
repository hosting settings.

Do not include real secrets in a report.

When reporting:

- use synthetic or revoked credentials only
- include the exact Lockrail version or commit
- include reproduction steps
- include expected versus actual behavior
- include whether the issue affects vault secrecy, relay policy, audit
  integrity, receipt verification, replay protection, or agent-key handling

## What Lockrail logs never contain

In the intended product path, raw secrets must not appear in:

- CLI output
- audit logs
- signed receipts
- debug output
- replay or usage stores
- plaintext vault files
- public agent documents

## Safe bug report guidance

- Never paste a production key, token, password, or private key into an issue.
- If a leak is suspected, prove it with synthetic test data and file paths.
- If you believe a release artifact or workflow leaks secrets, say which file
  or command leaked and what boundary was crossed.

## Known limitations

- Lockrail is not a host intrusion prevention system.
- GUI applications, browser prompts, clipboards, and malware remain outside the
  enforced boundary unless they go through a Lockrail hook or relay.
- PTY interception is best-effort and not a formal terminal isolation layer.
- DNS rebinding and local network races cannot be eliminated entirely by URL
  checks alone.
- Some upstream injection modes remain header-oriented in the current relay
  implementation.

See `docs/LIMITATIONS.md` and `docs/THREAT_MODEL.md` for the detailed scope.
