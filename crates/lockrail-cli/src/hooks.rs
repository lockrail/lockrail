//! Claude Code hook decisions (PLAN.md Phase 6a; D3, M14, B8). Pure functions over the hook's
//! JSON input, so every rule is tested without Claude Code.
//!
//! Contract (code.claude.com/docs/en/hooks, checked 2026-11-08):
//! - UserPromptSubmit cannot edit a prompt; it can only block it (`decision: "block"`) or add
//!   context. 0.3.7 printed a sealed copy as context, so the raw prompt still reached the model
//!   (D3). A typed secret is therefore sealed only by the sealer on the network path; without the
//!   sealer the prompt is blocked with a reason.
//! - PostToolUse replaces what the model sees with `hookSpecificOutput.updatedToolOutput`, which
//!   must match the tool's output shape (a mismatched value is silently ignored). The tool's own
//!   `tool_response` is rewritten leaf by leaf, so the shape is preserved exactly.

use crate::guard::{GuardContext, bash_violation, token_is_protected};
use lockrail_engine::handle::{self, Class, keyed_fingerprint, phi_handle, secret_handle};
use lockrail_engine::phi::{PhiOptions, scan_phi};
use lockrail_engine::seal::{ScanOptions, SecretFinding, fingerprint, scan_text};
use serde_json::Value;
use std::path::Path;

/// What the hook knows about this machine and session.
#[derive(Clone, Copy)]
pub struct Context {
    /// This session's traffic goes through the Lockrail sealer (proxy self-check passed).
    pub sealer_active: bool,
    /// Policy PHI mode is block (or seal) for this tool.
    pub phi_on: bool,
    /// A BAA covers this tool's provider: PHI becomes handles instead of being withheld.
    pub baa: bool,
    pub aggressive: bool,
    pub fp_key: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub enum PromptDecision {
    Allow,
    Block(String),
}

/// The prompt text from a UserPromptSubmit input (`prompt`), or the raw input when it is not
/// hook JSON (manual use: `echo text | lockrail hook prompt`).
pub fn prompt_text(input: &str) -> String {
    serde_json::from_str::<Value>(input)
        .ok()
        .and_then(|v| v.get("prompt").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| input.to_string())
}

fn options(ctx: &Context) -> ScanOptions {
    ScanOptions {
        aggressive: ctx.aggressive,
        protection_mode: true,
    }
}

/// Keyed handles of the secrets in a prompt, for the audit event of a blocked prompt.
pub fn prompt_handles(prompt: &str, ctx: &Context) -> Vec<String> {
    scan_text(prompt, options(ctx))
        .into_iter()
        .filter(|f| f.should_seal)
        .map(|f| secret_handle(&f.kind, &keyed_fingerprint(&ctx.fp_key, &f.value)))
        .collect()
}

pub fn prompt_decision(prompt: &str, ctx: &Context) -> PromptDecision {
    let secrets = scan_text(prompt, options(ctx))
        .into_iter()
        .filter(|f| f.should_seal)
        .count();
    if ctx.phi_on && !ctx.baa && !scan_phi(prompt, PhiOptions::default()).is_empty() {
        return PromptDecision::Block(
            "lockrail_phi_in_prompt: this prompt contains patient identifiers and this tool has no BAA. Remove them, or refer to the record by a non-identifying reference."
                .into(),
        );
    }
    if secrets > 0 && !ctx.sealer_active {
        return PromptDecision::Block(format!(
            "lockrail_secret_in_prompt: this prompt contains {secrets} secret(s). A hook cannot edit a prompt and the Lockrail sealer is not active for this session, so it was not sent. Remove the secret, or paste the output of `lockrail seal` instead."
        ));
    }
    PromptDecision::Allow
}

/// Counters for one rewritten tool output.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OutputReport {
    pub secrets: usize,
    pub phi_withheld: usize,
    pub phi_sealed: usize,
    pub known_values: usize,
    /// Keyed handles of the secrets replaced (for the exposure ledger; never values).
    pub handles: Vec<String>,
}

/// Rewrite one string: secrets to keyed handles; PHI withheld (or handles under a BAA).
/// Returns the new text and the secret findings (so the caller can keep values resolvable).
fn rewrite_text(
    text: &str,
    ctx: &Context,
    report: &mut OutputReport,
) -> (Option<String>, Vec<SecretFinding>) {
    let secrets: Vec<SecretFinding> = scan_text(text, options(ctx))
        .into_iter()
        .filter(|f| f.should_seal)
        .collect();
    let mut spans: Vec<(usize, usize, String, u8)> = secrets
        .iter()
        .map(|f| {
            (
                f.start,
                f.end,
                secret_handle(&f.kind, &keyed_fingerprint(&ctx.fp_key, &f.value)),
                0,
            )
        })
        .collect();
    if ctx.phi_on {
        for f in scan_phi(text, PhiOptions::default()) {
            if spans.iter().any(|(s, e, _, _)| f.start < *e && *s < f.end) {
                continue;
            }
            let replacement = if ctx.baa {
                phi_handle(f.kind, &keyed_fingerprint(&ctx.fp_key, f.value(text)))
            } else {
                "[PHI withheld]".to_string()
            };
            spans.push((f.start, f.end, replacement, if ctx.baa { 2 } else { 1 }));
        }
    }
    if spans.is_empty() {
        return (None, secrets);
    }
    spans.sort_by_key(|s| s.0);
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end, replacement, kind) in spans {
        if start < cursor {
            continue;
        }
        out.push_str(&text[cursor..start]);
        out.push_str(&replacement);
        cursor = end;
        match kind {
            0 => {
                report.secrets += 1;
                report.handles.push(replacement.clone());
            }
            1 => report.phi_withheld += 1,
            _ => report.phi_sealed += 1,
        }
    }
    out.push_str(&text[cursor..]);
    (Some(out), secrets)
}

/// Exact values already in the vault, so a value no detector recognises (a custom password, an
/// internal token) is still replaced when a tool prints it, for example
/// `lockrail env run -- printenv` (competitors/A-agent-secret-tools.md idea 4). The raw value,
/// its standard base64 and its percent-encoding are matched; values shorter than 8 bytes are
/// skipped because they would match ordinary text.
pub struct KnownValues {
    automaton: Option<aho_corasick::AhoCorasick>,
    handles: Vec<String>,
}

pub const MIN_KNOWN_VALUE_BYTES: usize = 8;

impl KnownValues {
    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            automaton: None,
            handles: Vec::new(),
        }
    }

    /// `values` are `(kind, value)`: a value sealed earlier keeps the kind it was found as, so the
    /// same credential always gets the same handle; a user-set secret is `vault-value`.
    pub fn new<'a>(
        values: impl IntoIterator<Item = (&'a str, &'a str)>,
        fp_key: &[u8; 32],
    ) -> Self {
        use base64ct::{Base64, Encoding};
        let mut patterns = Vec::new();
        let mut handles = Vec::new();
        for (kind, value) in values {
            if value.len() < MIN_KNOWN_VALUE_BYTES {
                continue;
            }
            let handle = secret_handle(kind, &keyed_fingerprint(fp_key, value));
            let percent: String = value
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect();
            let mut forms = vec![value.to_string(), Base64::encode_string(value.as_bytes())];
            if percent != value {
                forms.push(percent);
            }
            for form in forms {
                patterns.push(form);
                handles.push(handle.clone());
            }
        }
        let automaton = (!patterns.is_empty()).then(|| {
            aho_corasick::AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .build(&patterns)
                .expect("aho-corasick")
        });
        Self { automaton, handles }
    }

    /// Replace every known value in `text`; `None` when nothing matched.
    fn scrub(&self, text: &str) -> Option<(String, usize, Vec<String>)> {
        let automaton = self.automaton.as_ref()?;
        let mut count = 0usize;
        let mut seen = Vec::new();
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for m in automaton.find_iter(text) {
            let handle = &self.handles[m.pattern().as_usize()];
            out.push_str(&text[cursor..m.start()]);
            out.push_str(handle);
            cursor = m.end();
            count += 1;
            seen.push(handle.clone());
        }
        if count == 0 {
            return None;
        }
        out.push_str(&text[cursor..]);
        Some((out, count, seen))
    }
}

fn rewrite_value(
    v: &mut Value,
    ctx: &Context,
    known: &KnownValues,
    report: &mut OutputReport,
    found: &mut Vec<SecretFinding>,
) -> bool {
    match v {
        Value::String(s) => {
            // Known vault values first: a detector would otherwise cut a custom value into a
            // partial finding.
            let mut changed = false;
            if let Some((scrubbed, n, handles)) = known.scrub(s) {
                *s = scrubbed;
                report.known_values += n;
                report.handles.extend(handles);
                changed = true;
            }
            let (new, secrets) = rewrite_text(s, ctx, report);
            found.extend(secrets);
            match new {
                Some(n) => {
                    *s = n;
                    true
                }
                None => changed,
            }
        }
        Value::Array(items) => items.iter_mut().fold(false, |changed, x| {
            rewrite_value(x, ctx, known, report, found) | changed
        }),
        Value::Object(map) => map.values_mut().fold(false, |changed, x| {
            rewrite_value(x, ctx, known, report, found) | changed
        }),
        _ => false,
    }
}

/// The PostToolUse decision: `Some((hook_output_json, report, secret_findings))` when the tool
/// output must be replaced, `None` when it is clean.
pub fn tool_output_update(
    input: &str,
    ctx: &Context,
    known: &KnownValues,
) -> Option<(Value, OutputReport, Vec<SecretFinding>)> {
    let parsed: Value = serde_json::from_str(input).ok()?;
    let mut response = parsed.get("tool_response")?.clone();
    let mut report = OutputReport::default();
    let mut found = Vec::new();
    if !rewrite_value(&mut response, ctx, known, &mut report, &mut found) {
        return None;
    }
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": response,
        }
    });
    Some((out, report, found))
}

/// Replace every string in the tool's response with `reason`, keeping its shape (a mismatched
/// `updatedToolOutput` is ignored by Claude Code). Used when the output could not be scanned:
/// withholding is the only safe answer, because a failed hook leaves the raw output in place.
pub fn withhold_all(input: &str, reason: &str) -> Option<Value> {
    fn walk(v: &mut Value, reason: &str) {
        match v {
            Value::String(s) => *s = reason.to_string(),
            Value::Array(a) => a.iter_mut().for_each(|x| walk(x, reason)),
            Value::Object(m) => m.values_mut().for_each(|x| walk(x, reason)),
            _ => {}
        }
    }
    let parsed: Value = serde_json::from_str(input).ok()?;
    let mut response = parsed.get("tool_response")?.clone();
    walk(&mut response, reason);
    Some(serde_json::json!({
        "hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": response}
    }))
}

/// A PreToolUse decision.
#[derive(Debug, PartialEq)]
pub enum PreDecision {
    /// Say nothing: the normal permission flow runs.
    Pass,
    /// Refuse the call; the reason is shown to the model.
    Deny(String),
    /// Replace the tool input (complete object) and ask the user, so resolving a handle never
    /// also approves the call (docs: `updatedInput` "replaces the entire input object";
    /// combine with `ask` "to show the modified input to the user").
    Ask {
        reason: String,
        updated_input: Value,
    },
}

/// Tools that write a file: handles in their input are resolved against the file's current
/// content (5F). MultiEdit and NotebookEdit input fields are not documented, so every string
/// leaf is walked rather than named fields.
const EDIT_TOOLS: &[&str] = &["Edit", "Write", "MultiEdit", "NotebookEdit"];

/// The file a writing tool targets, chosen by tool: NotebookEdit writes `notebook_path`, the
/// others `file_path` (security review U2: an extra `file_path` on a NotebookEdit must not pick
/// the file the handle is checked against).
fn target_path<'a>(tool: &str, tool_input: &'a Value) -> Option<&'a str> {
    let key = if tool == "NotebookEdit" {
        "notebook_path"
    } else {
        "file_path"
    };
    tool_input.get(key).and_then(Value::as_str)
}

/// Every `lockrail://...` handle in `text`, with its span.
fn handles_in(text: &str) -> Vec<(usize, usize, handle::Handle)> {
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(pos) = text[offset..].find("lockrail://") {
        let start = offset + pos;
        let end = text[start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '_' | '-')))
            .map_or(text.len(), |e| start + e);
        if let Some(h) = handle::parse(&text[start..end]) {
            out.push((start, end, h));
        } else {
            // An unparseable `lockrail://` literal is still a handle-shaped string.
            out.push((
                start,
                end,
                handle::Handle {
                    class: Class::Secret,
                    kind: String::new(),
                    fingerprint: String::new(),
                },
            ));
        }
        offset = end.max(start + 1);
    }
    out
}

fn collect_strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

/// Rewrite every string leaf except the path fields, which are never rewritten.
fn replace_strings(v: &mut Value, f: &dyn Fn(&str) -> String) {
    match v {
        Value::String(s) => *s = f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| replace_strings(x, f)),
        Value::Object(m) => m
            .iter_mut()
            .filter(|(k, _)| !matches!(k.as_str(), "file_path" | "notebook_path" | "path"))
            .for_each(|(_, x)| replace_strings(x, f)),
        _ => {}
    }
}

/// The value behind a secret handle, only if `file_content` already holds it: a value in the
/// file whose fingerprint matches (detector findings), or a vault value that occurs in the file.
/// Resolving into any other file would let the model place a secret it never saw where a later
/// command can send it out (B2, 5F).
fn resolve_in_file(
    h: &handle::Handle,
    file_content: &str,
    fp_key: &[u8; 32],
    vault_values: &[String],
) -> Option<String> {
    let matches = |value: &str| {
        if h.is_legacy() {
            fingerprint(value) == h.fingerprint
        } else {
            keyed_fingerprint(fp_key, value) == h.fingerprint
        }
    };
    let options = ScanOptions {
        aggressive: true,
        protection_mode: true,
    };
    if let Some(f) = scan_text(file_content, options)
        .into_iter()
        .find(|f| matches(&f.value))
    {
        return Some(f.value);
    }
    vault_values
        .iter()
        .find(|v| matches(v) && file_content.contains(v.as_str()))
        .cloned()
}

/// A Claude Code settings file at any level (`.claude/settings.json` or `settings.local.json`):
/// the user-level ones hold Lockrail's hooks and proxy, and a project-level one can set
/// `disableAllHooks`. The path is resolved first, so `..`, a symlinked directory or a different
/// letter case (macOS file systems are case-insensitive) cannot skip the check.
fn is_claude_settings(target: &Path) -> bool {
    let p = crate::guard::lexical_normalize(target);
    let real = match (p.parent(), p.file_name()) {
        (Some(dir), Some(name)) => std::fs::canonicalize(dir)
            .map(|d| d.join(name))
            .unwrap_or_else(|_| p.clone()),
        _ => p,
    };
    let name = real
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let parent = real
        .parent()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    parent == ".claude" && matches!(name.as_str(), "settings.json" | "settings.local.json")
}

/// The PreToolUse decision for one hook input.
pub fn pre_tool_decision(
    input: &str,
    lockrail_home: &Path,
    user_home: &Path,
    fp_key: &[u8; 32],
    load_vault_values: &dyn Fn() -> Result<Vec<String>, String>,
) -> PreDecision {
    let Ok(parsed) = serde_json::from_str::<Value>(input) else {
        return PreDecision::Pass;
    };
    let tool = parsed
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(tool_input) = parsed.get("tool_input") else {
        return PreDecision::Pass;
    };
    let cwd = parsed
        .get("cwd")
        .and_then(Value::as_str)
        .map_or_else(|| user_home.to_path_buf(), std::path::PathBuf::from);
    let gctx = GuardContext {
        lockrail_home,
        user_home,
        cwd: &cwd,
    };
    if tool == "Bash" {
        let command = tool_input
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("");
        return bash_violation(command, &gctx).map_or(PreDecision::Pass, PreDecision::Deny);
    }
    // Any path-taking tool (Read, Write, Edit, Grep, Glob, LS, NotebookEdit, ...).
    let mut paths: Vec<String> = ["file_path", "notebook_path", "path"]
        .iter()
        .filter_map(|k| {
            tool_input
                .get(*k)
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    // Grep's `glob` filter (`**/vault.key`) reaches files under its `path` just as a Glob does.
    if let Some(glob) = tool_input.get("glob").and_then(Value::as_str)
        && tool == "Grep"
    {
        let base = tool_input
            .get("path")
            .and_then(Value::as_str)
            .map_or_else(|| cwd.to_string_lossy().to_string(), str::to_string);
        paths.push(format!("{}/{glob}", base.trim_end_matches('/')));
    }
    if let Some(pattern) = tool_input.get("pattern").and_then(Value::as_str)
        && tool == "Glob"
    {
        let base = tool_input
            .get("path")
            .and_then(Value::as_str)
            .map_or_else(|| cwd.to_string_lossy().to_string(), str::to_string);
        paths.push(format!("{}/{pattern}", base.trim_end_matches('/')));
    }
    // A handle in a path would be rewritten into the secret, so the write would target a file
    // named after it (security review finding 5).
    if paths
        .iter()
        .any(|p| p.contains("lockrail://") || p.contains("lockrail:/secret/"))
    {
        return PreDecision::Deny(
            "lockrail_handle_in_path: a lockrail:// handle cannot be part of a file path.".into(),
        );
    }
    if paths.iter().any(|p| token_is_protected(p, &gctx)) {
        return PreDecision::Deny(format!(
            "lockrail_guard_path: {tool} on Lockrail's private state ({}) is blocked for AI tools.",
            lockrail_home.display()
        ));
    }
    if !EDIT_TOOLS.contains(&tool) {
        return PreDecision::Pass;
    }
    // Claude Code's user settings hold Lockrail's hooks and proxy: an edit there could switch
    // protection off, so the user decides (ask), with the reason shown to them.
    let target = target_path(tool, tool_input).unwrap_or("");
    // Lockrail's helper and LaunchAgent: overwriting them switches protection off.
    if !target.is_empty()
        && crate::guard::path_in_protection(Path::new(target), &gctx)
        && !is_claude_settings(Path::new(target))
    {
        return PreDecision::Deny(
            "lockrail_guard_protection: this edit changes Lockrail's helper or background service. Ask the user to do it.".into(),
        );
    }
    if is_claude_settings(Path::new(target)) {
        return PreDecision::Ask {
            reason: "This edit changes a Claude Code settings file, which can switch Lockrail's hooks and proxy off. Allow it only if you meant to change it.".into(),
            updated_input: tool_input.clone(),
        };
    }
    let mut strings = Vec::new();
    collect_strings(tool_input, &mut strings);
    let handles: Vec<handle::Handle> = strings
        .iter()
        .flat_map(|s| handles_in(s))
        .map(|(_, _, h)| h)
        .collect();
    if handles.is_empty() {
        return PreDecision::Pass;
    }
    if handles.iter().any(|h| h.class == Class::Phi) {
        return PreDecision::Deny(
            "lockrail_phi_handle_in_edit: patient data handles are never written back into files. Edit around the withheld value, or ask the user to make this change."
                .into(),
        );
    }
    let file = target_path(tool, tool_input).unwrap_or("");
    let content = std::fs::read_to_string(file).unwrap_or_default();
    // The vault is opened (an Argon2 unlock, ~13 ms) only here, for an edit that carries a
    // handle; every other tool call skips it. A vault that cannot be opened refuses the edit.
    let vault_values = match load_vault_values() {
        Ok(values) => values,
        Err(e) => {
            return PreDecision::Deny(format!(
                "lockrail_vault_unavailable: sealed values cannot be restored ({e})."
            ));
        }
    };
    let vault_values = vault_values.as_slice();
    let mut resolved: Vec<(String, String)> = Vec::new();
    for h in &handles {
        let text = handle::secret_handle(&h.kind, &h.fingerprint);
        if h.fingerprint.is_empty() {
            return PreDecision::Deny(
                "lockrail_unresolved_handle: this edit contains a malformed lockrail:// handle. Write the surrounding text without it."
                    .into(),
            );
        }
        match resolve_in_file(h, &content, fp_key, vault_values) {
            Some(value) => resolved.push((text, value)),
            None => {
                return PreDecision::Deny(format!(
                    "lockrail_unresolved_handle: {text} stands for a secret that is not already in {file}, so Lockrail will not write it there. Keep the existing line unchanged, or ask the user to place the secret."
                ));
            }
        }
    }
    let mut updated = tool_input.clone();
    replace_strings(&mut updated, &|s: &str| {
        let mut out = s.to_string();
        for (h, v) in &resolved {
            out = out.replace(h.as_str(), v);
        }
        out
    });
    // A restored edit that cannot apply fails, and a failed tool's output does not pass through
    // PostToolUse, so it could echo the restored value to the model. Refuse it here instead:
    // every restored `old_string` must occur in the file, exactly once unless `replace_all`.
    let mut edits: Vec<&Value> = vec![&updated];
    if let Some(list) = updated.get("edits").and_then(Value::as_array) {
        edits.extend(list.iter());
    }
    for edit in edits {
        let Some(old) = edit.get("old_string").and_then(Value::as_str) else {
            continue;
        };
        let all = edit
            .get("replace_all")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let count = content.matches(old).count();
        if count == 0 || (count > 1 && !all) {
            return PreDecision::Deny(format!(
                "lockrail_edit_would_not_apply: after restoring sealed values, old_string occurs {count} time(s) in {file}. Re-read the file and match the text exactly{}.",
                if count > 1 {
                    ", or set replace_all"
                } else {
                    ""
                }
            ));
        }
    }
    PreDecision::Ask {
        reason: format!(
            "Lockrail restored {} sealed value(s) in this edit to the originals already in {file}.",
            resolved.len()
        ),
        updated_input: updated,
    }
}

/// A prompt that `@`-mentions Lockrail's private state. `@` file mentions are read without a
/// PreToolUse event (hooks docs), so the prompt hook is the only place to stop them.
pub fn prompt_mentions_protected_at(
    prompt: &str,
    lockrail_home: &Path,
    user_home: &Path,
    cwd: &Path,
) -> bool {
    let gctx = GuardContext {
        lockrail_home,
        user_home,
        cwd,
    };
    // Relative mentions resolve against the session's `cwd`; a quoted mention
    // (`@"~/.lockrail/x"`) is unquoted first (security review finding 6).
    prompt
        .split(|c: char| c.is_whitespace())
        .filter_map(|w| w.strip_prefix('@'))
        .map(|w| {
            w.trim_start_matches(['"', '\''])
                .trim_end_matches(['.', ',', ';', ':', ')', ']', '"', '\''])
        })
        .any(|w| !w.is_empty() && token_is_protected(w, &gctx))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(sealer_active: bool, phi_on: bool, baa: bool) -> Context {
        Context {
            sealer_active,
            phi_on,
            baa,
            aggressive: false,
            fp_key: [7u8; 32],
        }
    }

    fn secret() -> String {
        ["ghp_", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0Ed9Cb8"].concat()
    }

    #[test]
    fn typed_secret_blocks_without_the_sealer_and_passes_with_it() {
        let p = format!("deploy with {}", secret());
        assert!(
            matches!(prompt_decision(&p, &ctx(false, false, false)), PromptDecision::Block(r) if r.starts_with("lockrail_secret_in_prompt"))
        );
        assert_eq!(
            prompt_decision(&p, &ctx(true, false, false)),
            PromptDecision::Allow
        );
        assert_eq!(
            prompt_decision("hello", &ctx(false, false, false)),
            PromptDecision::Allow
        );
    }

    #[test]
    fn phi_prompt_blocks_without_a_baa_only() {
        let p = "Patient Jane Roe DOB: 03/14/1962 needs a refill";
        assert!(
            matches!(prompt_decision(p, &ctx(true, true, false)), PromptDecision::Block(r) if r.starts_with("lockrail_phi_in_prompt"))
        );
        assert_eq!(
            prompt_decision(p, &ctx(true, true, true)),
            PromptDecision::Allow
        );
        assert_eq!(
            prompt_decision(p, &ctx(true, false, false)),
            PromptDecision::Allow,
            "PHI mode off"
        );
    }

    #[test]
    fn hook_json_prompt_is_extracted() {
        assert_eq!(
            prompt_text(r#"{"session_id":"s","prompt":"hi there"}"#),
            "hi there"
        );
        assert_eq!(prompt_text("plain text"), "plain text");
    }

    #[test]
    fn tool_output_keeps_its_shape_and_loses_the_secret() {
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "cat .env"},
            "tool_response": {"stdout": format!("TOKEN={}\nOK", secret()), "stderr": "", "interrupted": false, "isImage": false}
        }).to_string();
        let (out, report, found) =
            tool_output_update(&input, &ctx(true, false, false), &KnownValues::empty()).unwrap();
        let updated = &out["hookSpecificOutput"]["updatedToolOutput"];
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        let keys: Vec<&String> = updated.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            vec!["interrupted", "isImage", "stderr", "stdout"],
            "shape changed"
        );
        assert_eq!(updated["interrupted"], false);
        let stdout = updated["stdout"].as_str().unwrap();
        assert!(
            !stdout.contains(&secret()) && stdout.contains("lockrail://secret/github-token/h_")
        );
        assert_eq!(report.secrets, 1);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn tool_output_phi_is_withheld_span_by_span() {
        let input = serde_json::json!({"tool_name":"Read","tool_input":{},"tool_response":{"file":{"content":"Patient MRN: 00482913\nVisit notes: stable"}}}).to_string();
        let (out, report, _) =
            tool_output_update(&input, &ctx(true, true, false), &KnownValues::empty()).unwrap();
        let content = out["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
            .as_str()
            .unwrap();
        assert_eq!(content, "Patient MRN: [PHI withheld]\nVisit notes: stable");
        assert_eq!(report.phi_withheld, 1);
    }

    #[test]
    fn clean_output_is_left_alone() {
        let input = r#"{"tool_name":"Bash","tool_input":{},"tool_response":{"stdout":"all good","stderr":""}}"#;
        assert!(
            tool_output_update(input, &ctx(true, true, false), &KnownValues::empty()).is_none()
        );
        assert!(
            tool_output_update("not json", &ctx(true, true, false), &KnownValues::empty())
                .is_none()
        );
    }

    // ---- PreToolUse (5F edit guard, path guards) and the known-value scrub ----

    struct Homes {
        _dir: tempfile::TempDir,
        user: std::path::PathBuf,
        lockrail: std::path::PathBuf,
    }

    fn homes() -> Homes {
        let dir = tempfile::tempdir().unwrap();
        let user = std::fs::canonicalize(dir.path()).unwrap();
        let lockrail = user.join(".lockrail");
        std::fs::create_dir_all(&lockrail).unwrap();
        Homes {
            _dir: dir,
            user,
            lockrail,
        }
    }

    fn pre(h: &Homes, tool: &str, tool_input: Value, vault: &[String]) -> PreDecision {
        let input = serde_json::json!({
            "tool_name": tool,
            "tool_input": tool_input,
            "cwd": h.user.join("project"),
        })
        .to_string();
        let owned = vault.to_vec();
        pre_tool_decision(&input, &h.lockrail, &h.user, &[7u8; 32], &move || {
            Ok(owned.clone())
        })
    }

    #[test]
    fn edit_handle_resolves_only_into_the_file_that_holds_the_value() {
        let h = homes();
        let file = h.user.join("config.env");
        std::fs::write(&file, format!("TOKEN={}\nMODE=dev\n", secret())).unwrap();
        let handle = secret_handle("github-token", &keyed_fingerprint(&[7u8; 32], &secret()));
        let edit = serde_json::json!({
            "file_path": file,
            "old_string": format!("TOKEN={handle}\nMODE=dev"),
            "new_string": format!("TOKEN={handle}\nMODE=prod"),
        });
        let PreDecision::Ask { updated_input, .. } = pre(&h, "Edit", edit, &[]) else {
            panic!("expected ask");
        };
        assert_eq!(
            updated_input["old_string"],
            format!("TOKEN={}\nMODE=dev", secret())
        );
        assert_eq!(updated_input["file_path"], file.to_string_lossy().as_ref());
        // The same handle written into a file that does not hold the value is refused, even
        // when the vault knows the value.
        let other = h.user.join("leak.txt");
        let write = serde_json::json!({"file_path": other, "content": format!("x {handle}")});
        assert!(matches!(
            pre(&h, "Write", write, &[secret()]),
            PreDecision::Deny(r) if r.starts_with("lockrail_unresolved_handle")
        ));
    }

    #[test]
    fn vault_values_resolve_when_no_detector_knows_the_format() {
        let h = homes();
        let custom = "corp-internal:Zq81!xx".to_string() + "Lm3";
        let file = h.user.join("app.ini");
        std::fs::write(&file, format!("secret_blob = {custom}\n")).unwrap();
        let handle = secret_handle("vault-value", &keyed_fingerprint(&[7u8; 32], &custom));
        let edit = serde_json::json!({
            "file_path": file,
            "old_string": format!("secret_blob = {handle}"),
            "new_string": format!("secret_blob = {handle} # rotated monthly"),
        });
        assert!(matches!(
            pre(&h, "Edit", edit.clone(), std::slice::from_ref(&custom)),
            PreDecision::Ask { .. }
        ));
        assert!(matches!(pre(&h, "Edit", edit, &[]), PreDecision::Deny(_)));
    }

    #[test]
    fn phi_handles_and_malformed_handles_are_refused_in_edits() {
        let h = homes();
        let file = h.user.join("n.txt");
        std::fs::write(&file, "x").unwrap();
        let phi = phi_handle("mrn", &keyed_fingerprint(&[7u8; 32], "00482913"));
        // Assert the rule, not just "denied": with the PHI rule removed the handle would still be
        // denied as unresolved, and a bare `Deny(_)` check would pass with the fix reverted.
        for (content, rule) in [
            (format!("MRN {phi}"), "lockrail_phi_handle_in_edit"),
            (
                "see lockrail://secret/bad".to_string(),
                "lockrail_unresolved_handle",
            ),
        ] {
            let write = serde_json::json!({"file_path": file, "content": content});
            assert!(
                matches!(pre(&h, "Write", write, &[]), PreDecision::Deny(ref r) if r.starts_with(rule)),
                "{rule}"
            );
        }
        let clean = serde_json::json!({"file_path": file, "content": "no handles"});
        assert_eq!(pre(&h, "Write", clean, &[]), PreDecision::Pass);
    }

    #[test]
    fn path_tools_and_bash_are_guarded() {
        let h = homes();
        let key = h.lockrail.join("vault.key");
        for (tool, input) in [
            ("Read", serde_json::json!({"file_path": key})),
            (
                "Grep",
                serde_json::json!({"pattern": "x", "path": h.lockrail}),
            ),
            (
                "Glob",
                serde_json::json!({"pattern": ".lockrail/*", "path": h.user}),
            ),
            (
                "Write",
                serde_json::json!({"file_path": key, "content": "x"}),
            ),
            (
                "Bash",
                serde_json::json!({"command": "cat ~/.lockrail/vault.key"}),
            ),
        ] {
            assert!(
                matches!(pre(&h, tool, input.clone(), &[]), PreDecision::Deny(r) if r.starts_with("lockrail_guard")),
                "{tool} {input}"
            );
        }
        let skill = serde_json::json!({"file_path": h.lockrail.join("SKILL.md")});
        assert_eq!(pre(&h, "Read", skill, &[]), PreDecision::Pass);
        let ordinary = serde_json::json!({"file_path": h.user.join("project/src/main.rs")});
        assert_eq!(pre(&h, "Read", ordinary, &[]), PreDecision::Pass);
    }

    #[test]
    fn at_mentions_of_lockrail_state_are_caught() {
        let h = homes();
        assert!(prompt_mentions_protected_at(
            "summarise @~/.lockrail/vault.key please",
            &h.lockrail,
            &h.user,
            &h.user
        ));
        assert!(!prompt_mentions_protected_at(
            "read @~/.lockrail/SKILL.md and @src/main.rs, email me@example.com",
            &h.lockrail,
            &h.user,
            &h.user
        ));
    }

    #[test]
    fn known_vault_values_are_scrubbed_in_every_encoding() {
        use base64ct::{Base64, Encoding};
        let custom = "corp-internal:Zq81!xx".to_string() + "Lm3";
        let known = KnownValues::new(
            [("vault-value", custom.as_str()), ("vault-value", "short")],
            &[7u8; 32],
        );
        let percent = "corp-internal%3AZq81%21xxLm3";
        let b64 = Base64::encode_string(custom.as_bytes());
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "lockrail env run -- printenv"},
            "tool_response": {"stdout": format!("A={custom}\nB={percent}\nC={b64}\nD=short"), "stderr": ""}
        })
        .to_string();
        let (out, report, _) =
            tool_output_update(&input, &ctx(true, false, false), &known).unwrap();
        let stdout = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
            .as_str()
            .unwrap();
        assert!(!stdout.contains(&custom) && !stdout.contains(percent) && !stdout.contains(&b64));
        assert!(stdout.contains("lockrail://secret/vault-value/h_"));
        assert!(
            stdout.ends_with("D=short"),
            "values under 8 bytes are not scrubbed"
        );
        assert_eq!(report.known_values, 3);
    }

    // ---- Security review round 1 (findings 5, 6, U2) ----

    #[test]
    fn handles_in_paths_are_refused_not_rewritten() {
        let h = homes();
        let value = secret();
        let handle = secret_handle("github-token", &keyed_fingerprint(&[7u8; 32], &value));
        let dir = h.user.join("p");
        std::fs::create_dir_all(&dir).unwrap();
        let odd = dir.join(handle.replace("://", ":/"));
        let _ = std::fs::create_dir_all(odd.parent().unwrap());
        let _ = std::fs::write(&odd, &value);
        let write = serde_json::json!({"file_path": dir.join(&handle), "content": handle});
        assert!(matches!(
            pre(&h, "Write", write, &[value]),
            PreDecision::Deny(r) if r.starts_with("lockrail_handle_in_path")
        ));
    }

    #[test]
    fn notebook_edit_resolves_against_the_notebook() {
        let h = homes();
        let env = h.user.join(".env");
        std::fs::write(&env, format!("T={}", secret())).unwrap();
        let nb = h.user.join("n.ipynb");
        std::fs::write(&nb, "{}").unwrap();
        let handle = secret_handle("github-token", &keyed_fingerprint(&[7u8; 32], &secret()));
        let edit = serde_json::json!({"notebook_path": nb, "file_path": env, "new_source": handle});
        assert!(matches!(
            pre(&h, "NotebookEdit", edit, &[]),
            PreDecision::Deny(_)
        ));
    }

    #[test]
    fn mentions_use_cwd_and_quotes() {
        let h = homes();
        let project = h.user.join("project");
        assert!(prompt_mentions_protected_at(
            "read @../.lockrail/vault.key",
            &h.lockrail,
            &h.user,
            &project
        ));
        assert!(prompt_mentions_protected_at(
            "read @\"~/.lockrail/vault.key\"",
            &h.lockrail,
            &h.user,
            &project
        ));
    }

    /// Security-guidance finding: a restored Edit that cannot apply fails, and a failure's output
    /// does not pass through PostToolUse, so it could echo the restored value to the model.
    #[test]
    fn restored_edits_that_would_not_apply_are_refused() {
        let h = homes();
        let file = h.user.join("c.env");
        std::fs::write(&file, format!("A={0}\nB={0}\n", secret())).unwrap();
        let handle = secret_handle("github-token", &keyed_fingerprint(&[7u8; 32], &secret()));
        // old_string not in the file once restored.
        let missing = serde_json::json!({"file_path": file, "old_string": format!("Z={handle}"), "new_string": "x"});
        assert!(
            matches!(pre(&h, "Edit", missing, &[]), PreDecision::Deny(r) if r.starts_with("lockrail_edit_would_not_apply"))
        );
        // Ambiguous without replace_all (the value appears twice).
        let twice = serde_json::json!({"file_path": file, "old_string": handle, "new_string": "x"});
        assert!(
            matches!(pre(&h, "Edit", twice.clone(), &[]), PreDecision::Deny(r) if r.starts_with("lockrail_edit_would_not_apply"))
        );
        let mut all = twice;
        all["replace_all"] = serde_json::json!(true);
        assert!(matches!(pre(&h, "Edit", all, &[]), PreDecision::Ask { .. }));
        // MultiEdit: every restored old_string must be present.
        let multi = serde_json::json!({"file_path": file, "edits": [
            {"old_string": format!("A={handle}"), "new_string": "A=1"},
            {"old_string": format!("C={handle}"), "new_string": "C=1"}
        ]});
        assert!(matches!(
            pre(&h, "MultiEdit", multi, &[]),
            PreDecision::Deny(_)
        ));
    }

    #[test]
    fn edits_to_claude_user_settings_ask_the_user() {
        let h = homes();
        let settings = h.user.join(".claude").join("settings.json");
        let edit = serde_json::json!({"file_path": settings, "old_string": "a", "new_string": "b"});
        assert!(matches!(
            pre(&h, "Edit", edit, &[]),
            PreDecision::Ask { .. }
        ));
        let other = serde_json::json!({"file_path": h.user.join("project/.claude/settings.json"), "content": "{}"});
        assert!(
            matches!(pre(&h, "Write", other, &[]), PreDecision::Ask { .. }),
            "a project settings file can set disableAllHooks"
        );
        // Other spellings of the same files (security-guidance finding): `..`, case, a symlinked
        // directory, and the local settings file.
        std::fs::create_dir_all(h.user.join(".claude")).unwrap();
        std::os::unix::fs::symlink(h.user.join(".claude"), h.user.join("cfg")).unwrap();
        for path in [
            h.user.join("project/../.claude/settings.json"),
            h.user.join(".Claude/Settings.json"),
            h.user.join("cfg/settings.json"),
            h.user.join(".claude/settings.local.json"),
        ] {
            let w = serde_json::json!({"file_path": path, "content": "{}"});
            assert!(
                matches!(pre(&h, "Write", w, &[]), PreDecision::Ask { .. }),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn lockrail_helper_and_agent_cannot_be_overwritten_and_grep_globs_are_checked() {
        let h = homes();
        let helper = h
            .user
            .join("Library/Application Support/Lockrail/bin/lockrail");
        let w = serde_json::json!({"file_path": helper, "content": "#!/bin/sh\nexit 0"});
        assert!(
            matches!(pre(&h, "Write", w, &[]), PreDecision::Deny(r) if r.starts_with("lockrail_guard_protection"))
        );
        let plist = h
            .user
            .join("Library/LaunchAgents/dev.lockrail.sealer.plist");
        let e = serde_json::json!({"file_path": plist, "old_string": "a", "new_string": "b"});
        assert!(matches!(pre(&h, "Edit", e, &[]), PreDecision::Deny(_)));
        std::fs::write(h.lockrail.join("vault.key"), "k").unwrap();
        let g = serde_json::json!({"pattern": ".", "path": h.user, "glob": "**/vault.key"});
        assert!(
            matches!(pre(&h, "Grep", g, &[]), PreDecision::Deny(r) if r.starts_with("lockrail_guard_path"))
        );
        let ok =
            serde_json::json!({"pattern": "TODO", "path": h.user.join("project"), "glob": "*.rs"});
        assert_eq!(pre(&h, "Grep", ok, &[]), PreDecision::Pass);
    }
}
