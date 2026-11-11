//! `lockrail install` / `uninstall --all` / `protection` through the real binary
//! (fleet/INSTALL-DECISION.md). `LOCKRAIL_INSTALL_NO_SYSTEM` (debug builds only) records the
//! `launchctl` and `security` commands instead of running them, so nothing outside the temp
//! home is touched.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Env {
    _dir: tempfile::TempDir,
    user: PathBuf,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let user = std::fs::canonicalize(dir.path()).unwrap();
    Env { _dir: dir, user }
}

fn run(e: &Env, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    c.args(args)
        .env("HOME", &e.user)
        .env("LOCKRAIL_HOME", e.user.join(".lockrail"))
        .env("LOCKRAIL_KEYSTORE", "file")
        .env("LOCKRAIL_INSTALL_NO_SYSTEM", "1")
        .env_remove("LOCKRAIL_PASSWORD");
    for k in [
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
        "LOCKRAIL_SYSTEM_DIR",
    ] {
        c.env_remove(k);
    }
    c.output().unwrap()
}

fn json(out: &Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "exit {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn read(p: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn install_then_uninstall_restores_the_users_settings_exactly() {
    let e = env();
    let settings = e.user.join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let before = serde_json::json!({
        "model": "opus",
        "env": {"HTTPS_PROXY": "http://corp-proxy:3128", "FOO": "1"},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-check.sh"}]}]}
    });
    std::fs::write(&settings, serde_json::to_vec_pretty(&before).unwrap()).unwrap();

    let out = json(&run(&e, &["--json", "install"]));
    assert_eq!(out["installed"], true);
    let support = e.user.join("Library/Application Support/Lockrail");
    let helper = support.join("bin/lockrail");
    assert!(helper.is_file(), "helper copied outside any app bundle");
    let pem = std::fs::read_to_string(support.join("lockrail-ca.pem")).unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    let plist = e
        .user
        .join("Library/LaunchAgents/dev.lockrail.sealer.plist");
    let lint = Command::new("plutil")
        .arg("-lint")
        .arg(&plist)
        .output()
        .unwrap();
    assert!(
        lint.status.success(),
        "{}",
        String::from_utf8_lossy(&lint.stdout)
    );
    let plist_text = std::fs::read_to_string(&plist).unwrap();
    assert!(plist_text.contains("<string>--launchd</string>") && plist_text.contains("8789"));
    // The system commands install would run: user-domain TLS trust (no `-d`) and the agent load.
    let cmds: Vec<String> = out["system_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert!(cmds.iter().any(
        |c| c.starts_with("security add-trusted-cert -r trustRoot -p ssl -k ")
            && !c.contains(" -d ")
    ));
    assert!(
        cmds.iter()
            .any(|c| c.starts_with("launchctl bootstrap gui/"))
    );

    let s = read(&settings);
    assert_eq!(s["env"]["HTTPS_PROXY"], "http://127.0.0.1:8789");
    assert_eq!(s["env"]["FOO"], "1");
    assert_eq!(s["model"], "opus");
    for event in ["UserPromptSubmit", "PreToolUse", "PostToolUse"] {
        let cmd = s["hooks"][event]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|e| e["hooks"].as_array().unwrap())
            .find_map(|h| {
                h["command"]
                    .as_str()
                    .filter(|c| c.contains("lockrail"))
                    .map(str::to_string)
            })
            .unwrap_or_else(|| panic!("{event} hook missing"));
        assert!(
            cmd.contains(&helper.to_string_lossy().to_string()),
            "{event}: {cmd}"
        );
    }

    // Installing twice changes nothing more (no duplicate hooks, previous env kept).
    json(&run(&e, &["--json", "install"]));
    let again = read(&settings);
    assert_eq!(again["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

    // Protection reports the files in place (launchctl/security are not run in this test).
    let p = run(&e, &["--json", "protection"]);
    let pj: serde_json::Value = serde_json::from_slice(&p.stdout).unwrap();
    let check = |name: &str| {
        pj["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap()["ok"]
            .as_bool()
            .unwrap()
    };
    assert!(check("helper_installed") && check("claude_hooks") && check("claude_proxy"));

    let un = json(&run(&e, &["--json", "uninstall", "--all"]));
    assert_eq!(un["uninstalled"], true);
    assert_eq!(read(&settings), before, "settings restored exactly");
    assert!(!plist.exists() && !support.exists());
    assert!(
        e.user.join(".lockrail").join("vault.lockrail").exists(),
        "data kept without --purge-data"
    );
}

#[test]
fn install_refuses_an_unreadable_claude_settings_file() {
    let e = env();
    let settings = e.user.join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(&settings, "{ // not json\n}").unwrap();
    let out = run(&e, &["install"]);
    assert!(!out.status.success());
    assert_eq!(
        std::fs::read_to_string(&settings).unwrap(),
        "{ // not json\n}"
    );
    assert!(
        !e.user
            .join("Library/LaunchAgents/dev.lockrail.sealer.plist")
            .exists(),
        "nothing changed"
    );
}

#[test]
fn dry_run_changes_nothing() {
    let e = env();
    let out = json(&run(&e, &["--json", "install", "--dry-run"]));
    assert_eq!(out["dry_run"], true);
    assert!(!e.user.join("Library").exists() && !e.user.join(".claude").exists());
}

#[test]
fn uninstall_requires_all() {
    let e = env();
    assert!(!run(&e, &["uninstall"]).status.success());
}

/// Hostile review B3: uninstall stopped the sealer before checking that settings.json parses,
/// leaving Claude Code pointed at a dead proxy. It must refuse before changing anything.
#[test]
fn uninstall_refuses_before_changing_anything_when_settings_are_unreadable() {
    let e = env();
    json(&run(&e, &["--json", "install"]));
    let settings = e.user.join(".claude").join("settings.json");
    let plist = e
        .user
        .join("Library/LaunchAgents/dev.lockrail.sealer.plist");
    std::fs::write(&settings, "{ broken").unwrap();
    let out = run(&e, &["--json", "uninstall", "--all"]);
    assert!(!out.status.success());
    assert!(
        plist.exists(),
        "the sealer agent must stay while Claude still points at it"
    );
    assert!(
        e.user
            .join("Library/Application Support/Lockrail/bin/lockrail")
            .exists()
    );
}

/// Hostile review B4: with the manifest lost, a reinstall recorded Lockrail's own proxy values as
/// the user's previous settings, and uninstall restored a dead proxy.
#[test]
fn reinstall_without_a_manifest_never_restores_lockrails_own_values() {
    let e = env();
    json(&run(&e, &["--json", "install"]));
    std::fs::remove_file(e.user.join(".lockrail").join("install.json")).unwrap();
    json(&run(&e, &["--json", "install"]));
    json(&run(&e, &["--json", "uninstall", "--all"]));
    let s = read(&e.user.join(".claude").join("settings.json"));
    assert!(
        s.get("env")
            .is_none_or(|env| env.get("HTTPS_PROXY").is_none()),
        "{s}"
    );
    assert!(
        s.get("env")
            .is_none_or(|env| env.get("NODE_EXTRA_CA_CERTS").is_none()),
        "{s}"
    );
}

/// Hostile review: a symlinked settings.json (dotfiles managers) was replaced by a plain file,
/// and mode 600 became 644.
#[test]
fn a_symlinked_settings_file_stays_a_symlink_and_keeps_its_mode() {
    use std::os::unix::fs::PermissionsExt;
    let e = env();
    let dotfiles = e.user.join("dotfiles");
    std::fs::create_dir_all(&dotfiles).unwrap();
    let real = dotfiles.join("claude-settings.json");
    std::fs::write(&real, "{\"model\":\"opus\"}").unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::create_dir_all(e.user.join(".claude")).unwrap();
    let link = e.user.join(".claude").join("settings.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    json(&run(&e, &["--json", "install"]));
    assert!(link.is_symlink(), "settings.json is no longer a symlink");
    assert_eq!(read(&real)["env"]["HTTPS_PROXY"], "http://127.0.0.1:8789");
    assert_eq!(
        std::fs::metadata(&real).unwrap().permissions().mode() & 0o777,
        0o600
    );
    json(&run(&e, &["--json", "uninstall", "--all"]));
    assert!(link.is_symlink());
    assert_eq!(read(&real), serde_json::json!({"model": "opus"}));
}

/// Hostile review: install had no rollback. A failure midway (here: LaunchAgents is a file, so
/// the agent cannot be written) must undo everything already changed.
#[test]
fn a_failed_install_rolls_back_what_it_changed() {
    let e = env();
    std::fs::create_dir_all(e.user.join("Library")).unwrap();
    std::fs::write(
        e.user.join("Library").join("LaunchAgents"),
        "not a directory",
    )
    .unwrap();
    let out = run(&e, &["install"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("rolled back"), "{err}");
    assert!(
        !e.user.join("Library/Application Support/Lockrail").exists(),
        "helper left behind"
    );
    let settings = e.user.join(".claude").join("settings.json");
    if settings.exists() {
        let s = read(&settings);
        assert!(s.get("hooks").is_none() && s.get("env").is_none(), "{s}");
    }
}
