# Lockrail Release Process

Lockrail is an open-source local-first security tool. A release is only ready
when the documented checks pass and the published limitations remain accurate.

## Required checks

```bash
cargo fmt --all -- --check
cargo check --all --all-features
cargo test --all --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release --all-features
cargo package --allow-dirty
```

## Optional supply-chain checks

Install once:

```bash
cargo install cargo-audit cargo-deny cargo-machete
```

Run before shipping when available:

```bash
cargo audit
cargo deny check
cargo machete
```

## crates.io dry run

Dry-run each package in dependency order:

```bash
cargo publish -p lockrail-protocol --dry-run
cargo publish -p lockrail-vault --dry-run
cargo publish -p lockrail-audit --dry-run
cargo publish -p lockrail-relay --dry-run
cargo publish -p lockrail --dry-run
```

## Actual publish order

Do not run this until the dry runs are clean:

```bash
cargo login
cargo publish -p lockrail-protocol
cargo publish -p lockrail-vault
cargo publish -p lockrail-audit
cargo publish -p lockrail-relay
cargo publish -p lockrail
```

## GitHub release artifacts

If you publish binaries, build them from the same tagged commit that passed the
release checks:

```bash
cargo build --release --all-features
```

Attach the produced `lockrail` binary or platform-specific archives to the
GitHub release notes. Do not claim support for installers or package managers
that are not actually maintained in the repo.
