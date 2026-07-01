# Contributing to Lockrail

Lockrail is a source-available, local-first Rust security tool. Contributions need
to preserve that model: no telemetry, no hosted control plane, no runtime license
checks in the local binary, and no secret exposure in tests, logs, or docs.

## Development setup

```bash
cargo fmt --all
cargo check --all --all-features
cargo test --all --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all --all-features
```

Optional local tools:

```bash
cargo install cargo-audit cargo-deny cargo-machete
```

## Adding a new secret detector

1. Update `crates/lockrail-protocol/src/seal.rs`.
2. Classify the detector confidence correctly:
   - `High`: seal by default
   - `Medium`: seal in protection mode
   - `Low`: report only unless aggressive mode is enabled
3. Add tests proving:
   - the detector finds the secret
   - sealing replaces the raw value with a handle
   - debug output does not leak the raw value

## Adding a provider preset

1. Update `crates/lockrail-protocol/src/presets.rs`.
2. Set secure defaults for:
   - scheme
   - hosts
   - methods
   - paths
   - query policy
   - injection method
   - recommended TTL and max uses
3. Add relay or protocol tests for the new preset constraints.

## Security expectations

- Do not print raw secrets in tests, examples, errors, or logs.
- Keep SSRF-deny behavior secure by default.
- Keep replay protection and usage enforcement real and test-backed.
- Treat agent private keys like secrets.
- Do not add cloud-only, account-based, telemetry, or enterprise-only paths.

## Coding style

- Follow `cargo fmt`.
- Keep Clippy clean under `-D warnings`.
- Prefer narrow changes over redesign.
- Add tests with every security-relevant behavior change.

## Release checks

Before opening a release-oriented change:

```bash
cargo fmt --all -- --check
cargo check --all --all-features
cargo test --all --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release --all-features
cargo package --allow-dirty
```
