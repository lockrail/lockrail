//! PLAN.md Phase 6a (5F) and competitors/A-agent-secret-tools.md ideas 3-4, through the real
//! binary: a value sealed in tool output comes back only into the file that holds it, the
//! agent cannot read Lockrail's own state, and values no detector knows are still scrubbed.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Env {
    _dir: tempfile::TempDir,
    user: PathBuf,
    lockrail: PathBuf,
    project: PathBuf,
}

fn command(env: &Env, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    c.args(args)
        .env("HOME", &env.user)
        .env("LOCKRAIL_HOME", &env.lockrail)
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
    c
}

fn run(env: &Env, args: &[&str], stdin: &str) -> Output {
    let mut child = command(env, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn json(out: &Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "exit {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null)
}

fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let user = std::fs::canonicalize(dir.path()).unwrap();
    let lockrail = user.join(".lockrail");
    let project = user.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let env = Env {
        _dir: dir,
        user,
        lockrail,
        project,
    };
    let out = run(&env, &["setup", "--tools", "claude", "--json"], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    env
}

fn secret() -> String {
    ["ghp_", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0Ed9Cb8"].concat()
}

fn pre(env: &Env, tool: &str, input: serde_json::Value) -> serde_json::Value {
    let payload = serde_json::json!({
        "session_id": "s",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
        "cwd": env.project,
    })
    .to_string();
    json(&run(env, &["hook", "pre-tool-use"], &payload))
}

fn decision(v: &serde_json::Value) -> &str {
    v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("none")
}

fn audit(env: &Path) -> String {
    std::fs::read_to_string(env.join("audit.jsonl")).unwrap_or_default()
}

#[test]
fn read_seal_then_edit_resolves_only_into_the_same_file() {
    let env = setup();
    let file = env.project.join(".env");
    std::fs::write(&file, format!("TOKEN={}\nDEBUG=0\n", secret())).unwrap();

    // 1. The model reads the file: PostToolUse replaces the value with a keyed handle.
    let read = serde_json::json!({
        "tool_name": "Read",
        "tool_input": {"file_path": file},
        "tool_response": {"type": "text", "file": {"filePath": file, "content": format!("TOKEN={}\nDEBUG=0\n", secret())}}
    })
    .to_string();
    let v = json(&run(&env, &["hook", "post-tool-use"], &read));
    let content = v["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!content.contains(&secret()));
    let handle = content
        .lines()
        .next()
        .unwrap()
        .strip_prefix("TOKEN=")
        .unwrap()
        .to_string();
    assert!(
        handle.starts_with("lockrail://secret/github-token/h_"),
        "{handle}"
    );

    // 2. The model edits the same file using the handle: the input is restored and the user is
    //    asked (no auto-approval). The value is in the hook's output to Claude Code, which the
    //    model does not see.
    let edit = pre(
        &env,
        "Edit",
        serde_json::json!({
            "file_path": file,
            "old_string": format!("TOKEN={handle}\nDEBUG=0"),
            "new_string": format!("TOKEN={handle}\nDEBUG=1"),
            "replace_all": false,
        }),
    );
    assert_eq!(decision(&edit), "ask");
    let updated = &edit["hookSpecificOutput"]["updatedInput"];
    assert_eq!(
        updated["old_string"],
        format!("TOKEN={}\nDEBUG=0", secret())
    );
    assert_eq!(
        updated["new_string"],
        format!("TOKEN={}\nDEBUG=1", secret())
    );
    assert_eq!(updated["replace_all"], false, "unchanged fields are kept");

    // 3. The same handle written anywhere else is refused, so a later command cannot send it.
    let leak = pre(
        &env,
        "Write",
        serde_json::json!({"file_path": env.project.join("leak.txt"), "content": handle}),
    );
    assert_eq!(decision(&leak), "deny");
    let reason = leak["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.starts_with("lockrail_unresolved_handle"));
    assert!(!reason.contains(&secret()));
    assert!(audit(&env.lockrail).contains("hook.pre_tool_use.resolved"));
    assert!(!audit(&env.lockrail).contains(&secret()));
}

#[test]
fn lockrail_state_is_not_readable_by_tools_or_mentions() {
    let env = setup();
    assert!(
        env.lockrail.join("vault.key").exists(),
        "fixture has a file vault key"
    );
    for (tool, input) in [
        (
            "Bash",
            serde_json::json!({"command": "cat ~/.lockrail/vault.key"}),
        ),
        (
            "Bash",
            serde_json::json!({"command": "bash -c 'base64 < $HOME/.lockrail/vault.lockrail'"}),
        ),
        (
            "Bash",
            serde_json::json!({"command": "lockrail secret export"}),
        ),
        (
            "Read",
            serde_json::json!({"file_path": env.lockrail.join("vault.key")}),
        ),
        (
            "Grep",
            serde_json::json!({"pattern": ".", "path": env.lockrail}),
        ),
    ] {
        let v = pre(&env, tool, input.clone());
        assert_eq!(decision(&v), "deny", "{tool} {input}");
    }
    for (tool, input) in [
        (
            "Bash",
            serde_json::json!({"command": "lockrail env run -- npm test"}),
        ),
        (
            "Read",
            serde_json::json!({"file_path": env.lockrail.join("SKILL.md")}),
        ),
        (
            "Read",
            serde_json::json!({"file_path": env.project.join("src/main.rs")}),
        ),
    ] {
        let out = run(
            &env,
            &["hook", "pre-tool-use"],
            &serde_json::json!({"tool_name": tool, "tool_input": input, "cwd": env.project})
                .to_string(),
        );
        assert!(out.status.success());
        assert!(
            out.stdout.is_empty(),
            "{tool} {input} was not passed silently"
        );
    }
    let prompt = serde_json::json!({"prompt": "what is in @~/.lockrail/vault.key ?"}).to_string();
    let v = json(&run(&env, &["hook", "prompt"], &prompt));
    assert_eq!(v["decision"], "block");
    assert!(audit(&env.lockrail).contains("hook.pre_tool_use.denied"));
}

#[test]
fn values_no_detector_knows_are_scrubbed_from_tool_output() {
    let env = setup();
    let custom = ["corp-internal:Zq81", "!xxLm3"].concat();
    // `secret set NAME` with no value reads it from stdin.
    let out = run(&env, &["secret", "set", "INTERNAL_PW"], &custom);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "lockrail env run -- printenv"},
        "tool_response": {"stdout": format!("INTERNAL_PW={custom}\nPATH=/usr/bin"), "stderr": "", "interrupted": false, "isImage": false}
    })
    .to_string();
    let v = json(&run(&env, &["hook", "post-tool-use"], &input));
    let stdout = v["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap();
    assert!(!stdout.contains(&custom), "{stdout}");
    assert!(stdout.starts_with("INTERNAL_PW=lockrail://secret/vault-value/h_"));
    assert!(stdout.ends_with("PATH=/usr/bin"));
}

#[test]
fn installer_adds_the_pre_tool_use_hook() {
    let env = setup();
    let out = run(&env, &["ai", "hooks", "--json"], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let settings: serde_json::Value = serde_json::from_slice(
        &std::fs::read(env.user.join(".claude").join("settings.json")).unwrap(),
    )
    .unwrap();
    let pre = &settings["hooks"]["PreToolUse"][0]["hooks"][0];
    assert!(
        pre["command"]
            .as_str()
            .unwrap()
            .ends_with("hook pre-tool-use")
    );
    assert_eq!(pre["onFailure"], "block");
}

/// Security review U1: a burst of distinct findings used to cost one vault write each (~31 ms),
/// so 1,000 fake tokens pushed PostToolUse past its 30 s timeout.
#[test]
fn a_flood_of_findings_stays_well_inside_the_hook_timeout() {
    let env = setup();
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let tokens: Vec<String> = (0..1000u32)
        .map(|i| {
            let body: String = (0..36u32)
                .map(|j| alphabet[((i * 31 + j * 7 + i * j) % 62) as usize] as char)
                .collect();
            ["gh", "p_"].concat() + &body
        })
        .collect();
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "x"},
        "tool_response": {"stdout": tokens.join("\n"), "stderr": "", "interrupted": false, "isImage": false}
    })
    .to_string();
    let started = std::time::Instant::now();
    let v = json(&run(&env, &["hook", "post-tool-use"], &input));
    let took = started.elapsed();
    assert!(took.as_secs() < 10, "PostToolUse took {took:?}");
    let stdout = v["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap();
    assert!(tokens.iter().all(|t| !stdout.contains(t.as_str())));
}

/// Security review finding 2: output that reaches `vault.key` by a route the guard does not see
/// (`grep -r . ~`) is scrubbed by value.
#[test]
fn vault_key_contents_are_scrubbed_from_any_output() {
    let env = setup();
    let key = std::fs::read_to_string(env.lockrail.join("vault.key")).unwrap();
    let key = key.trim();
    assert!(key.len() >= 16, "fixture vault key");
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "grep -r . ~"},
        "tool_response": {"stdout": format!("/u/.lockrail/vault.key:{key}\nother"), "stderr": "", "interrupted": false, "isImage": false}
    })
    .to_string();
    let v = json(&run(&env, &["hook", "post-tool-use"], &input));
    let stdout = v["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap();
    assert!(!stdout.contains(key), "{stdout}");
}

/// The exposure ledger end to end: a secret stopped in tool output, a prompt blocked for it, and
/// `lockrail sweep` finding it in an old transcript all land on one credential row, with no value
/// in the ledger or the audit log.
#[test]
fn exposure_ledger_tracks_one_credential_across_hooks_and_sweep() {
    let env = setup();
    let post = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "cat .env"},
        "tool_response": {"stdout": format!("TOKEN={}", secret()), "stderr": "", "interrupted": false, "isImage": false}
    })
    .to_string();
    json(&run(&env, &["hook", "post-tool-use"], &post));
    let prompt =
        serde_json::json!({"prompt": format!("use {}", secret()), "cwd": env.project}).to_string();
    assert_eq!(
        json(&run(&env, &["hook", "prompt"], &prompt))["decision"],
        "block"
    );
    let transcripts = env.user.join("old-transcripts");
    std::fs::create_dir_all(&transcripts).unwrap();
    std::fs::write(
        transcripts.join("s.jsonl"),
        serde_json::json!({"message": format!("here is {}", secret())}).to_string(),
    )
    .unwrap();
    let out = run(
        &env,
        &["sweep", "--path", transcripts.to_str().unwrap()],
        "",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let l = json(&run(&env, &["--json", "ledger"], ""));
    let creds = l["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1, "{l}");
    let c = &creds[0];
    assert_eq!(c["kind"], "github-token");
    assert_eq!(c["stopped"], 1);
    assert_eq!(c["prompts_blocked"], 1);
    assert_eq!(c["found_in_transcripts"], true);
    assert_eq!(c["by_tool"]["Bash"], 1);
    assert!(!l.to_string().contains(&secret()));
    assert!(!audit(&env.lockrail).contains(&secret()));
}

/// Engineering review blocker 3: with no vault (hooks installed before `setup`), PostToolUse
/// printed a replacement and then exited 2, which Claude Code ignores, leaving the raw output in
/// context. It must exit 0 with the output sealed or withheld.
#[test]
fn post_tool_use_never_leaves_raw_output_when_it_fails() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".lockrail");
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "cat .env"},
        "tool_response": {"stdout": format!("TOKEN={}", secret()), "stderr": "", "interrupted": false, "isImage": false}
    })
    .to_string();
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    c.args(["hook", "post-tool-use"])
        .env("HOME", dir.path())
        .env("LOCKRAIL_HOME", &home)
        .env("LOCKRAIL_KEYSTORE", "file")
        .env_remove("LOCKRAIL_PASSWORD")
        .env_remove("HTTPS_PROXY")
        .env_remove("LOCKRAIL_SYSTEM_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let stdout = v["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap();
    assert!(!stdout.contains(&secret()), "{stdout}");
    assert_eq!(
        v["hookSpecificOutput"]["updatedToolOutput"]["interrupted"], false,
        "shape kept"
    );
}

/// Engineering review blocker 1: `env run` exited 0 whatever the command did.
#[test]
fn env_run_exits_with_the_commands_status() {
    let env = setup();
    std::fs::write(env.project.join(".env.lockrail"), "X=1\n").unwrap();
    let mut c = command(
        &env,
        &[
            "env",
            "run",
            "--file",
            ".env.lockrail",
            "--",
            "sh",
            "-c",
            "exit 7",
        ],
    );
    let out = c.current_dir(&env.project).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Architecture review: the prompt hook trusted `HTTPS_PROXY` alone to decide the sealer would
/// seal a typed secret. With no keyed sealer answering on the port (nothing, or a plain proxy an
/// agent started there), a prompt carrying a secret must be blocked.
#[test]
fn prompt_with_secret_is_blocked_when_the_sealer_cannot_prove_itself() {
    let env = setup();
    let prompt =
        serde_json::json!({"prompt": format!("use {}", secret()), "cwd": env.project}).to_string();
    let mut c = command(&env, &["hook", "prompt"]);
    c.env("HTTPS_PROXY", "http://127.0.0.1:8789")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(prompt.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(
        v["decision"],
        "block",
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Hostile review B2: a panic inside PostToolUse exited 2, which leaves the raw output in the
/// model's context. It must withhold the output and exit 0.
#[test]
fn a_panic_in_post_tool_use_withholds_instead_of_leaking() {
    let env = setup();
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "cat .env"},
        "tool_response": {"stdout": format!("TOKEN={}", secret()), "stderr": "", "interrupted": false, "isImage": false}
    })
    .to_string();
    let mut c = command(&env, &["hook", "post-tool-use"]);
    c.env("LOCKRAIL_DEBUG_PANIC_POST_TOOL", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let stdout = v["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap();
    assert!(
        !stdout.contains(&secret()) && stdout.contains("withheld"),
        "{stdout}"
    );
}
