//! PLAN.md Phase 6a (D3): what Claude Code receives from the hooks, through the real binary.
//! UserPromptSubmit can only block; PostToolUse replaces output with `updatedToolOutput`.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn hook(home: &std::path::Path, which: &str, input: &str) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    c.args(["hook", which])
        .env("LOCKRAIL_HOME", home)
        .env("LOCKRAIL_KEYSTORE", "file")
        .env_remove("LOCKRAIL_PASSWORD");
    for k in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "LOCKRAIL_SYSTEM_DIR",
    ] {
        c.env_remove(k);
    }
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn setup() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lockrail"))
        .args(["setup", "--tools", "claude", "--json"])
        .env("LOCKRAIL_HOME", tmp.path())
        .env("LOCKRAIL_KEYSTORE", "file")
        .output()
        .unwrap();
    assert!(out.status.success());
    tmp
}

fn secret() -> String {
    ["ghp_", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0Ed9Cb8"].concat()
}

#[test]
fn typed_secret_is_blocked_when_no_sealer_can_seal_it() {
    let home = setup();
    let input = serde_json::json!({"session_id":"s","hook_event_name":"UserPromptSubmit","prompt":format!("use {}", secret())}).to_string();
    let out = hook(home.path(), "prompt", &input);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["decision"], "block");
    assert!(
        v["reason"]
            .as_str()
            .unwrap()
            .starts_with("lockrail_secret_in_prompt")
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(&secret()),
        "the block message echoed the secret"
    );

    let clean = serde_json::json!({"prompt":"refactor main.rs"}).to_string();
    let out = hook(home.path(), "prompt", &clean);
    assert!(out.status.success());
    assert!(
        out.stdout.is_empty(),
        "a clean prompt must produce no output"
    );
}

#[test]
fn tool_output_is_replaced_with_the_same_shape() {
    let home = setup();
    let input = serde_json::json!({
        "hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"},
        "tool_response":{"stdout":format!("GITHUB_TOKEN={}\n", secret()),"stderr":"","interrupted":false,"isImage":false}
    }).to_string();
    let out = hook(home.path(), "post-tool-use", &input);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !text.contains(&secret()),
        "secret reached the model: {text}"
    );
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let updated = &v["hookSpecificOutput"]["updatedToolOutput"];
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    assert_eq!(updated["interrupted"], false);
    assert!(
        updated["stdout"]
            .as_str()
            .unwrap()
            .starts_with("GITHUB_TOKEN=lockrail://secret/github-token/h_")
    );
}

/// The installer writes fail-closed hooks, upgrades an older Lockrail entry in place (no
/// duplicate), quotes the binary path, and leaves the user's other hooks alone.
#[test]
fn hook_installer_is_fail_closed_upgrades_in_place_and_keeps_user_hooks() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let settings = home.join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(
        &settings,
        serde_json::json!({"hooks": {"UserPromptSubmit": [
            {"hooks": [{"type": "command", "command": "/old/path/lockrail hook prompt"}]},
            {"hooks": [{"type": "command", "command": "my-own-hook.sh"}]}
        ]}, "theme": "dark"})
        .to_string(),
    )
    .unwrap();
    let install = || {
        let out = Command::new(env!("CARGO_BIN_EXE_lockrail"))
            .args(["ai", "hooks", "--json"])
            .env("HOME", home)
            .env("LOCKRAIL_HOME", home.join(".lockrail"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()
    };
    let first = install();
    assert_eq!(first["already_present"]["UserPromptSubmit"], false);
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&settings).unwrap()).unwrap();
    let ups = v["hooks"]["UserPromptSubmit"].as_array().unwrap();
    assert_eq!(ups.len(), 2, "duplicate or lost entry: {ups:?}");
    let ours = &ups[0]["hooks"][0];
    assert_eq!(ours["onFailure"], "block");
    let cmd = ours["command"].as_str().unwrap();
    assert!(
        cmd.starts_with('\'') && cmd.ends_with("' hook prompt"),
        "{cmd}"
    );
    assert_eq!(ups[1]["hooks"][0]["command"], "my-own-hook.sh");
    assert_eq!(v["theme"], "dark");
    assert_eq!(
        v["hooks"]["PostToolUse"][0]["hooks"][0]["onFailure"],
        "block"
    );
    let second = install();
    assert_eq!(second["already_present"]["UserPromptSubmit"], true);
    assert_eq!(second["already_present"]["PostToolUse"], true);
}
