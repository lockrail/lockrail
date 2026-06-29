# lockrail-relay

Policy-enforcing relay for Lockrail.

This crate verifies LRAP capabilities and proofs, enforces request policy,
blocks SSRF-style abuse by default, injects secrets only at the last moment,
and emits signed receipts and audit events.
