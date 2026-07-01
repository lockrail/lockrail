# Limitations

## PTY and interactive tools

`lockrail run -- <tool>` can seal piped stdin and guard interactive submitted lines, but it is not a complete terminal emulator. Interactive output scanning is limited and should not be treated as a perfect barrier.

## Browser and GUI apps

Lockrail does not automatically intercept arbitrary GUI text, browser chat boxes, clipboard contents, or application-local state. Those flows need a dedicated hook, extension, or app integration.

## Host compromise

Lockrail does not protect against malware, keyloggers, hostile browser extensions, screen capture, or a fully compromised local host while the vault is unlocked.

## Relay injection coverage

The current relay implementation is strongest for header-based secret injection. Generic query/body injection flows are not yet complete.

## Network enforcement

The relay blocks obvious SSRF targets and rejects unsafe URL forms by default, but local URL checks are not a complete substitute for hardened network segmentation and egress policy.

## Production status

This repository now has a significantly harder security-critical path, but it should not be called production-ready just because local tests pass. It still needs broader adversarial testing, dependency security tooling, and tighter integration coverage.

## Source-available license boundary

Lockrail is source-available for noncommercial use. This repo does not add accounts, hosted control
planes, paid tiers, commercial SaaS licensing, telemetry, or enterprise-only execution paths. If those
appear later, they should be treated as a product-scope change rather than an
incidental implementation detail.
