//! `lockrail install`, `lockrail uninstall --all` and `lockrail protection`: the one-step
//! per-user setup the macOS app calls, also usable from a terminal (research/.../fleet/
//! INSTALL-DECISION.md).
//!
//! What install does, all per user, no admin password:
//! 1. Copies this binary to `~/Library/Application Support/Lockrail/bin/lockrail`. The helper
//!    lives outside any app bundle, so dragging the app to the Trash cannot leave Claude Code's
//!    fail-closed hooks and proxy setting pointing at a missing program (packaging report R1).
//! 2. Creates the local CA (name-constrained to the model hosts) and trusts it in the **user**
//!    domain for TLS only: macOS asks for the login password once.
//! 3. Writes a LaunchAgent that starts the sealer on demand (launchd socket activation on
//!    127.0.0.1:8789) and loads it.
//! 4. Installs the Claude Code hooks pointing at the helper, and sets `HTTPS_PROXY` and
//!    `NODE_EXTRA_CA_CERTS` in `~/.claude/settings.json` `env`, remembering previous values.
//! 5. Records everything it changed in `<LOCKRAIL_HOME>/install.json`, which uninstall reverses.
//!
//! System commands (`launchctl`, `security`) go through [`System`], so tests can check every file
//! change without touching the login session or the keychain.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const LAUNCH_AGENT_LABEL: &str = "dev.lockrail.sealer";
pub const CA_COMMON_NAME: &str = "Lockrail Local CA";
const SEALER_PORT: &str = "8789";

/// Where install puts things, derived from the user's home and `LOCKRAIL_HOME`.
#[derive(Clone, Debug)]
pub struct Layout {
    pub user_home: PathBuf,
    pub lockrail_home: PathBuf,
}

impl Layout {
    pub fn support_dir(&self) -> PathBuf {
        self.user_home
            .join("Library")
            .join("Application Support")
            .join("Lockrail")
    }
    pub fn helper(&self) -> PathBuf {
        self.support_dir().join("bin").join("lockrail")
    }
    pub fn ca_pem(&self) -> PathBuf {
        self.support_dir().join("lockrail-ca.pem")
    }
    pub fn launch_agent(&self) -> PathBuf {
        self.user_home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LAUNCH_AGENT_LABEL}.plist"))
    }
    pub fn logs(&self) -> PathBuf {
        self.user_home.join("Library").join("Logs").join("Lockrail")
    }
    pub fn claude_settings(&self) -> PathBuf {
        self.user_home.join(".claude").join("settings.json")
    }
    pub fn manifest(&self) -> PathBuf {
        self.lockrail_home.join("install.json")
    }
    fn login_keychain(&self) -> PathBuf {
        self.user_home
            .join("Library")
            .join("Keychains")
            .join("login.keychain-db")
    }
}

/// Runs (or, in a dry run or a test, only records) the system commands install needs.
pub struct System {
    execute: bool,
    pub log: Vec<String>,
}

impl System {
    pub fn new(execute: bool) -> Self {
        Self {
            execute,
            log: Vec::new(),
        }
    }

    /// Run a command; `Ok(None)` when not executing, else `Ok(Some(success))`.
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Option<(bool, String)>> {
        self.log.push(format!("{program} {}", args.join(" ")));
        if !self.execute {
            return Ok(None);
        }
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("run {program}"))?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(Some((out.status.success(), text)))
    }
}

/// What install changed, so uninstall can put it back.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: u32,
    pub helper: PathBuf,
    pub launch_agent: PathBuf,
    pub ca_pem: PathBuf,
    pub ca_trusted: bool,
    /// Previous values of the Claude Code `env` keys install set (`None`: the key was absent).
    pub claude_env_previous: std::collections::BTreeMap<String, Option<String>>,
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The LaunchAgent: launchd owns the listening socket and starts the sealer on the first
/// connection (`sealer serve --launchd`), so nothing runs until an agent talks to a model.
pub fn launch_agent_plist(layout: &Layout) -> String {
    let helper = xml_escape(&layout.helper().to_string_lossy());
    let home = xml_escape(&layout.lockrail_home.to_string_lossy());
    let log = xml_escape(&layout.logs().join("sealer.log").to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LAUNCH_AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{helper}</string><string>sealer</string><string>serve</string><string>--launchd</string></array>
  <key>EnvironmentVariables</key>
  <dict><key>LOCKRAIL_HOME</key><string>{home}</string></dict>
  <key>Sockets</key>
  <dict>
    <key>Listeners</key>
    <dict>
      <key>SockNodeName</key><string>127.0.0.1</string>
      <key>SockServiceName</key><string>{SEALER_PORT}</string>
      <key>SockType</key><string>stream</string>
      <key>SockFamily</key><string>IPv4</string>
    </dict>
  </dict>
  <key>StandardErrorPath</key><string>{log}</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
"#
    )
}

/// Read a JSON settings file, refusing (instead of overwriting) one that does not parse.
pub fn read_settings(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        anyhow!(
            "{} is not valid JSON ({e}); fix it first, Lockrail will not overwrite it",
            path.display()
        )
    })?;
    if !value.is_object() {
        bail!("{} is not a JSON object", path.display());
    }
    Ok(value)
}

/// Write a settings file in place of the real file: a symlinked `settings.json` (dotfiles
/// managers) stays a symlink with its target updated, and the file keeps its permissions (new
/// files are 0600). Atomic: written next to the target, then renamed (hostile review).
pub fn write_settings(path: &Path, value: &Value) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let real = if path.is_symlink() {
        std::fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()))?
    } else {
        path.to_path_buf()
    };
    let dir = real
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", real.display()))?;
    std::fs::create_dir_all(dir)?;
    let mode = std::fs::metadata(&real)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o600);
    let name = real
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.lockrail-tmp"));
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    std::fs::write(&tmp, text)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, &real).with_context(|| format!("replace {}", real.display()))?;
    Ok(())
}

/// Set the Claude Code `env` keys, returning the previous values.
pub fn set_claude_env(
    settings: &mut Value,
    ca_pem: &Path,
) -> std::collections::BTreeMap<String, Option<String>> {
    let env = settings
        .as_object_mut()
        .expect("checked object")
        .entry("env")
        .or_insert_with(|| serde_json::json!({}));
    if !env.is_object() {
        *env = serde_json::json!({});
    }
    let env = env.as_object_mut().expect("object");
    let mut previous = std::collections::BTreeMap::new();
    let values = [
        (
            "HTTPS_PROXY",
            crate::proxy_check::EXPECTED_PROXY.to_string(),
        ),
        ("NODE_EXTRA_CA_CERTS", ca_pem.to_string_lossy().into_owned()),
    ];
    for (key, value) in values {
        // A value that is already Lockrail's own is not the user's: recording it would make
        // uninstall restore a dead proxy (hostile review B4).
        let current = env.get(key).and_then(Value::as_str).map(str::to_string);
        previous.insert(key.to_string(), current.filter(|c| *c != value));
        env.insert(key.to_string(), Value::String(value));
    }
    previous
}

/// Put the Claude Code `env` keys back as they were before install.
pub fn restore_claude_env(
    settings: &mut Value,
    previous: &std::collections::BTreeMap<String, Option<String>>,
) {
    let Some(env) = settings.get_mut("env").and_then(Value::as_object_mut) else {
        return;
    };
    for (key, old) in previous {
        match old {
            Some(v) => {
                env.insert(key.clone(), Value::String(v.clone()));
            }
            None => {
                env.remove(key);
            }
        }
    }
    if env.is_empty() {
        settings.as_object_mut().expect("object").remove("env");
    }
}

/// Remove every Lockrail hook entry; the user's own hooks stay.
pub fn remove_lockrail_hooks(settings: &mut Value) {
    let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) else {
        return;
    };
    for entries in hooks.values_mut() {
        if let Some(arr) = entries.as_array_mut() {
            arr.retain(|entry| {
                !entry
                    .get("hooks")
                    .and_then(Value::as_array)
                    .is_some_and(|hs| {
                        hs.iter().any(|h| {
                            h.get("command")
                                .and_then(Value::as_str)
                                .is_some_and(|c| c.contains("lockrail") && c.contains(" hook "))
                        })
                    })
            });
        }
    }
    hooks.retain(|_, entries| entries.as_array().is_none_or(|a| !a.is_empty()));
    if hooks.is_empty() {
        settings.as_object_mut().expect("object").remove("hooks");
    }
}

pub fn uid() -> String {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }.to_string()
}

/// Trust the CA in the user domain for TLS only. macOS shows its own password prompt.
pub fn trust_ca(sys: &mut System, layout: &Layout) -> Result<bool> {
    let keychain = layout.login_keychain();
    let pem = layout.ca_pem();
    let args = [
        "add-trusted-cert",
        "-r",
        "trustRoot",
        "-p",
        "ssl",
        "-k",
        &keychain.to_string_lossy(),
        &pem.to_string_lossy(),
    ];
    match sys.run("security", &args)? {
        None => Ok(false),
        Some((true, _)) => Ok(true),
        Some((false, out)) => bail!("macOS did not trust the Lockrail CA: {}", out.trim()),
    }
}

pub fn load_agent(sys: &mut System, layout: &Layout) -> Result<()> {
    let domain = format!("gui/{}", uid());
    let target = format!("{domain}/{LAUNCH_AGENT_LABEL}");
    // Reload: an older definition must not stay registered after an update.
    let _ = sys.run("launchctl", &["bootout", &target])?;
    if let Some((false, out)) = sys.run(
        "launchctl",
        &[
            "bootstrap",
            &domain,
            &layout.launch_agent().to_string_lossy(),
        ],
    )? {
        bail!("launchctl could not load the sealer agent: {}", out.trim());
    }
    Ok(())
}

pub fn unload_agent(sys: &mut System) -> Result<()> {
    let target = format!("gui/{}/{LAUNCH_AGENT_LABEL}", uid());
    let _ = sys.run("launchctl", &["bootout", &target])?;
    Ok(())
}

pub fn untrust_ca(sys: &mut System, layout: &Layout) -> Result<()> {
    let pem = layout.ca_pem();
    let _ = sys.run("security", &["remove-trusted-cert", &pem.to_string_lossy()])?;
    let keychain = layout.login_keychain();
    let _ = sys.run(
        "security",
        &[
            "delete-certificate",
            "-c",
            CA_COMMON_NAME,
            &keychain.to_string_lossy(),
        ],
    )?;
    Ok(())
}

/// One protection check: a name, whether it passes, and the fix when it does not.
#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub fix: Option<String>,
}

fn hook_installed(settings: &Value, event: &str, suffix: &str) -> bool {
    settings["hooks"][event]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|e| e["hooks"].as_array().into_iter().flatten())
        .any(|h| {
            h["command"]
                .as_str()
                .is_some_and(|c| c.contains("lockrail") && c.trim_end().ends_with(suffix))
                && h["onFailure"] == "block"
        })
}

/// Is every part of agent protection in place? Read-only, quick (one TCP connect, two
/// `security`/`launchctl` reads when `sys` executes).
/// `sealer_ok`: the process on the sealer port answered the keyed health challenge (checked by
/// the caller, which holds the key).
pub fn protection(layout: &Layout, sys: &mut System, sealer_ok: bool) -> Vec<Check> {
    let settings = read_settings(&layout.claude_settings()).unwrap_or(Value::Null);
    let hooks_ok = [
        ("UserPromptSubmit", "hook prompt"),
        ("PreToolUse", "hook pre-tool-use"),
        ("PostToolUse", "hook post-tool-use"),
    ]
    .iter()
    .all(|(event, suffix)| hook_installed(&settings, event, suffix));
    let proxy_ok = settings["env"]["HTTPS_PROXY"] == crate::proxy_check::EXPECTED_PROXY;
    let helper_ok = layout.helper().is_file();
    let agent_ok = layout.launch_agent().is_file()
        && matches!(
            sys.run(
                "launchctl",
                &["print", &format!("gui/{}/{LAUNCH_AGENT_LABEL}", uid())]
            ),
            Ok(Some((true, _)))
        );
    let trusted = matches!(
        sys.run("security", &["dump-trust-settings"]),
        Ok(Some((true, ref out))) if out.contains(CA_COMMON_NAME)
    );
    let fix = |ok: bool, f: &str| (!ok).then(|| f.to_string());
    vec![
        Check {
            name: "helper_installed",
            ok: helper_ok,
            fix: fix(helper_ok, "lockrail install"),
        },
        Check {
            name: "sealer_agent_loaded",
            ok: agent_ok,
            fix: fix(agent_ok, "lockrail install"),
        },
        Check {
            name: "sealer_verified",
            ok: sealer_ok,
            fix: fix(
                sealer_ok,
                "lockrail install, then check ~/Library/Logs/Lockrail/sealer.log",
            ),
        },
        Check {
            name: "ca_trusted",
            ok: trusted,
            fix: fix(
                trusted,
                "lockrail install (macOS asks for your login password once)",
            ),
        },
        Check {
            name: "claude_hooks",
            ok: hooks_ok,
            fix: fix(hooks_ok, "lockrail install"),
        },
        Check {
            name: "claude_proxy",
            ok: proxy_ok,
            fix: fix(proxy_ok, "lockrail install"),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_keys_are_restored_exactly() {
        let mut s = serde_json::json!({"env": {"HTTPS_PROXY": "http://corp:3128", "FOO": "1"}, "model": "x"});
        let prev = set_claude_env(&mut s, Path::new("/ca.pem"));
        assert_eq!(s["env"]["HTTPS_PROXY"], crate::proxy_check::EXPECTED_PROXY);
        restore_claude_env(&mut s, &prev);
        assert_eq!(
            s,
            serde_json::json!({"env": {"HTTPS_PROXY": "http://corp:3128", "FOO": "1"}, "model": "x"})
        );
        let mut empty = serde_json::json!({});
        let prev = set_claude_env(&mut empty, Path::new("/ca.pem"));
        restore_claude_env(&mut empty, &prev);
        assert_eq!(empty, serde_json::json!({}));
    }

    #[test]
    fn only_lockrail_hooks_are_removed() {
        let mut s = serde_json::json!({"hooks": {
            "PreToolUse": [
                {"hooks": [{"type": "command", "command": "'/x/lockrail' hook pre-tool-use"}]},
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-check.sh"}]}
            ],
            "PostToolUse": [{"hooks": [{"type": "command", "command": "/x/lockrail hook post-tool-use"}]}]
        }});
        remove_lockrail_hooks(&mut s);
        assert_eq!(
            s,
            serde_json::json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-check.sh"}]}]}})
        );
    }

    #[test]
    fn invalid_settings_are_refused_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("settings.json");
        std::fs::write(&p, "{ // a comment\n}").unwrap();
        assert!(read_settings(&p).is_err());
    }

    #[test]
    fn plist_escapes_paths() {
        let layout = Layout {
            user_home: PathBuf::from("/Users/a&b"),
            lockrail_home: PathBuf::from("/Users/a&b/.lockrail"),
        };
        let p = launch_agent_plist(&layout);
        assert!(p.contains("/Users/a&amp;b/Library/Application Support/Lockrail/bin/lockrail"));
        assert!(!p.contains("a&b"));
    }
}
