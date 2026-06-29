# macOS build troubleshooting

If Cargo fails with many dependency build scripts killed by `signal: 9, SIGKILL`, and the project is under `~/Downloads`, this is usually not a Rust source error. It is often macOS quarantine/provenance or endpoint security killing unsigned generated executables.

Typical failing pattern:

```text
failed to run custom build command for `proc-macro2`
.../target/debug/build/proc-macro2-.../build-script-build (signal: 9, SIGKILL)
```

Fix:

```bash
cd /path/to/lockrail
./scripts/macos-build-fix.sh ~/Developer/lockrail
cd ~/Developer/lockrail
source ~/.cargo/env
CARGO_TARGET_DIR="$HOME/.cargo-target/lockrail" CARGO_BUILD_JOBS=1 ./scripts/full-scan.sh
```

Why move out of Downloads?

`Downloads` often carries quarantine/provenance metadata. Some macOS security policies and enterprise EDR tools are stricter about executing freshly generated unsigned binaries from quarantined locations.

If it still fails, collect macOS logs:

```bash
log show --last 10m --style compact --predicate 'eventMessage CONTAINS "build-script-build" OR eventMessage CONTAINS "malware" OR eventMessage CONTAINS "deny" OR eventMessage CONTAINS "killed"' > scan-logs/macos-kill.log
```
