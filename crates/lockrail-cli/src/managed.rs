//! The Claude Code managed-settings payload (PLAN.md Phase 6a), for MDM to place at
//! `/Library/Application Support/ClaudeCode/managed-settings.json`.
//!
//! Every key and rule form below was checked against code.claude.com (permissions, settings,
//! settings-reference, managed-settings, env-vars and hooks pages, read 2026-11-08):
//! - Hooks with `onFailure: "block"` (v2.1.295+) fail closed.
//! - `permissions.deny` `Read(~/path)` rules are enforced by Claude Code itself for its file tools,
//!   for file commands it recognises in Bash (`cat`, `head`, `tail`, `sed`, `tee`) and for
//!   redirection targets, and also block Edit and Write. They do not cover a command that reads
//!   a file without naming it, so the PreToolUse guard stays. A deny rule cannot carry an
//!   exception for `~/` paths, so the files are listed one by one and `SKILL.md` stays readable.
//! - `allowedProviders` and `allowManagedHooksOnly` are managed-only keys.
//! - `CLAUDE_CODE_DISABLE_FILE_MENTIONS=1` (v2.1.299+) makes `@` mentions go through the file
//!   tools, so PreToolUse and PostToolUse see them. It changes how `@` works for users, so it is
//!   opt-in (DEV-RULES: no UX change unless asked).
//! - `allowManagedHooksOnly: true` blocks every user, project and plugin hook, so it is opt-in.

use serde_json::{Value, json};

pub struct ManagedOptions<'a> {
    /// Absolute path of the installed `lockrail` binary the hooks run.
    pub binary: &'a str,
    pub proxy: &'a str,
    pub org_uuid: Option<&'a str>,
    pub disable_file_mentions: bool,
    pub managed_hooks_only: bool,
    /// The HIPAA sample settings (Anthropic-only provider, claude.ai login, transcript
    /// retention): opt-in, because they change how people sign in and delete local history.
    pub hipaa: bool,
    /// Turn on Claude Code's own sandbox for shell commands (kernel-enforced filesystem and
    /// egress limits; docs: code.claude.com/docs/en/sandboxing), with no unsandboxed fallback.
    /// A structural layer under Lockrail's guard; opt-in because commands needing hosts outside
    /// the allowlist will be refused until an admin allows them.
    pub claude_sandbox: bool,
    pub cleanup_period_days: u32,
}

/// Files under `~/.lockrail` that hold secrets or reach them. `SKILL.md` is not listed: AI
/// tools are told to read it.
pub const PROTECTED_FILES: &[&str] = &[
    "~/.lockrail/vault.lockrail",
    "~/.lockrail/vault.key",
    "~/.lockrail/broker.sock",
    "~/.lockrail/keys/**",
    "~/.lockrail/audit.jsonl",
    "~/.lockrail/config.json",
    // The sealer CA's private key: with it, anyone can mint certificates for the model hosts.
    "~/.lockrail/proxy-ca.json",
    "~/.lockrail/agents/**",
];

fn valid_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn hook(command: String) -> Value {
    json!({ "hooks": [{ "type": "command", "command": command, "onFailure": "block", "timeout": 30 }] })
}

pub fn claude_managed_settings(o: &ManagedOptions) -> Result<Value, String> {
    if !o.binary.starts_with('/') {
        return Err("the hook binary must be an absolute path".into());
    }
    if let Some(id) = o.org_uuid
        && !valid_uuid(id)
    {
        return Err(format!("not an organization UUID: {id}"));
    }
    let quoted = format!("'{}'", o.binary.replace('\'', "'\\''"));
    let mut env = json!({
        "HTTPS_PROXY": o.proxy,
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "DISABLE_FEEDBACK_COMMAND": "1",
        "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
    });
    if o.disable_file_mentions {
        env["CLAUDE_CODE_DISABLE_FILE_MENTIONS"] = json!("1");
    }
    let mut deny: Vec<String> = PROTECTED_FILES
        .iter()
        .map(|p| format!("Read({p})"))
        .collect();
    deny.push("Edit(~/.lockrail/**)".into());
    deny.push("Bash(lockrail secret export:*)".into());
    deny.push("Bash(lockrail keys export-legacy:*)".into());
    let mut settings = json!({
        "env": env,
        "permissions": { "deny": deny },
        "hooks": {
            "UserPromptSubmit": [hook(format!("{quoted} hook prompt"))],
            "PreToolUse": [hook(format!("{quoted} hook pre-tool-use"))],
            "PostToolUse": [hook(format!("{quoted} hook post-tool-use"))],
        },
    });
    if let Some(id) = o.org_uuid {
        settings["forceLoginOrgUUID"] = json!(id);
    }
    if o.managed_hooks_only {
        settings["allowManagedHooksOnly"] = json!(true);
    }
    if o.claude_sandbox {
        settings["sandbox"] = json!({
            "enabled": true,
            "failIfUnavailable": true,
            "allowUnsandboxedCommands": false
        });
    }
    if o.hipaa {
        settings["allowedProviders"] = json!(["anthropic"]);
        settings["forceLoginMethod"] = json!("claudeai");
        settings["cleanupPeriodDays"] = json!(o.cleanup_period_days);
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ManagedOptions<'static> {
        ManagedOptions {
            binary: "/usr/local/lockrail/bin/lockrail",
            proxy: "http://127.0.0.1:8789",
            org_uuid: Some("123e4567-e89b-12d3-a456-426614174000"),
            disable_file_mentions: false,
            managed_hooks_only: false,
            hipaa: true,
            claude_sandbox: false,
            cleanup_period_days: 30,
        }
    }

    #[test]
    fn payload_has_fail_closed_hooks_proxy_and_deny_rules() {
        let s = claude_managed_settings(&opts()).unwrap();
        for event in ["UserPromptSubmit", "PreToolUse", "PostToolUse"] {
            let h = &s["hooks"][event][0]["hooks"][0];
            assert_eq!(h["onFailure"], "block", "{event}");
            assert!(
                h["command"]
                    .as_str()
                    .unwrap()
                    .starts_with("'/usr/local/lockrail/bin/lockrail' hook ")
            );
        }
        assert_eq!(s["env"]["HTTPS_PROXY"], "http://127.0.0.1:8789");
        assert_eq!(s["allowedProviders"], json!(["anthropic"]));
        assert_eq!(
            s["forceLoginOrgUUID"],
            "123e4567-e89b-12d3-a456-426614174000"
        );
        let deny: Vec<&str> = s["permissions"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(deny.contains(&"Read(~/.lockrail/vault.key)"));
        assert!(deny.contains(&"Read(~/.lockrail/proxy-ca.json)"));
        assert!(
            !deny
                .iter()
                .any(|d| d.contains("SKILL.md") || *d == "Read(~/.lockrail/**)")
        );
        let mut plain = opts();
        plain.hipaa = false;
        let p = claude_managed_settings(&plain).unwrap();
        assert!(p.get("allowedProviders").is_none() && p.get("cleanupPeriodDays").is_none());
        // Opt-in switches are absent by default (no UX change unless asked).
        assert!(s.get("allowManagedHooksOnly").is_none());
        assert!(s["env"].get("CLAUDE_CODE_DISABLE_FILE_MENTIONS").is_none());
    }

    #[test]
    fn opt_ins_and_input_checks() {
        let mut o = opts();
        o.disable_file_mentions = true;
        o.managed_hooks_only = true;
        let s = claude_managed_settings(&o).unwrap();
        assert_eq!(s["env"]["CLAUDE_CODE_DISABLE_FILE_MENTIONS"], "1");
        assert_eq!(s["allowManagedHooksOnly"], true);
        o.claude_sandbox = true;
        let sb = claude_managed_settings(&o).unwrap();
        assert_eq!(sb["sandbox"]["allowUnsandboxedCommands"], false);
        o.binary = "lockrail";
        assert!(claude_managed_settings(&o).is_err());
        o.binary = "/x/lockrail";
        o.org_uuid = Some("not-a-uuid");
        assert!(claude_managed_settings(&o).is_err());
    }
}
