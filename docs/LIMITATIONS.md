# Limitations

## PTY and interactive tools

`lockrail run -- <tool>` can seal piped stdin and guard interactive submitted lines, but it is not a complete terminal emulator. Interactive output scanning is limited and should not be treated as a perfect barrier.

## Browser and GUI apps

Lockrail does not automatically intercept arbitrary GUI text, browser chat boxes, clipboard contents, or application-local state. Those flows need a dedicated hook, extension, or app integration.

## Host compromise

Lockrail does not protect against malware, keyloggers, hostile browser extensions, screen capture, or a fully compromised local host while the vault is unlocked.

## Relay injection coverage

The current relay implementation is strongest for header-based secret injection. Generic query/body injection flows are not yet complete.

## Sealer scans request bodies, not URLs

The sealer seals the body of requests to model APIs. It does not scan or rewrite the URL query string, and a request with an empty body is forwarded as is. Model APIs carry prompts and tool output in the body; the query string holds parameters, and Gemini's `?key=` is the user's own API key, so blocking secret-shaped queries would break Gemini sign-in. A secret placed in a query string on a model host is therefore not sealed.

## Network enforcement

The relay blocks obvious SSRF targets and rejects unsafe URL forms by default, but local URL checks are not a complete substitute for hardened network segmentation and egress policy.

## Production status

This repository now has a significantly harder security-critical path, but it should not be called production-ready just because local tests pass. It still needs broader adversarial testing, dependency security tooling, and tighter integration coverage.

## Source-available license boundary

Lockrail is source-available for noncommercial use. This repo does not add accounts, hosted control
planes, paid tiers, commercial SaaS licensing, telemetry, or enterprise-only execution paths. If those
appear later, they should be treated as a product-scope change rather than an
incidental implementation detail.

## AI-tool hooks are guards, not a sandbox

The PreToolUse guard parses shell commands (quotes, `$(...)`, `sh -c`, `eval`, wrappers, `cd`,
`~`/`$HOME`/`${HOME...}`, globs, brace lists, symlinks) and refuses reads of Lockrail's own state,
Keychain reveals and the Lockrail commands that print, write or upload values. It cannot see a
path built at run time (`$(echo ... | base64 -d)`), a script file, or `python -c`. As a second
layer, PostToolUse replaces the exact contents of `vault.key` and the key files, and every vault
value, wherever they appear in tool output. The boundary that holds against a determined agent
is the broker's presence check on managed machines.

## Output that the model transforms

Sealing replaces values that appear in tool output. A model that transforms output before it
reaches the hook (for example `printenv | rev`, or encoding a value in a way no detector or
known-value form matches) can still read a secret that the command was given. Do not give an
agent session secrets it should not see; on managed machines `lockrail env run` needs presence.

## Detection numbers

Secret recall, PHI recall and false-positive figures in `research/` are reported per corpus.
Held-out corpora v1-v3 have all been inspected after scoring, so numbers on them after detection
v2 are fitted, not blind. Only a fresh blind corpus measures generalisation.

## Failed tool calls

Claude Code's `PostToolUseFailure` hook can only add context; it cannot replace the error text. A
failing command's output (stdout and stderr) reaches the model as the error, so no hook can seal
it. The sealer covers this case on the wire: it seals the tool result inside the next model
request. Without the sealer running, secrets in a failing command's output reach the model.

## Same-user boundary

The agent runs as the developer. Anything Lockrail stores in the same user account (the helper,
the LaunchAgent, Claude Code settings, file-based keys on unmanaged machines) is protected by
guards, not by an OS boundary. The prompt hook proves the sealer is genuine with a keyed health
challenge, and the guard refuses commands that unload or edit Lockrail's service or settings, but a
determined agent can still find a route the guard does not parse. Claude Code's own sandboxing
(`lockrail ai managed-settings --claude-sandbox`) adds a kernel-enforced boundary for shell commands.
