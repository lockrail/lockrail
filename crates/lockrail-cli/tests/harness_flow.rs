use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn lockrail_cmd(home: &Path, password: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    let shim_dir = home.join("bin");
    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(shim_dir.as_path()).chain(
            std::env::split_paths(&existing_path)
                .collect::<Vec<_>>()
                .iter()
                .map(|p| p.as_path()),
        ),
    )
    .expect("join PATH");
    cmd.env("LOCKRAIL_HOME", home)
        .env("LOCKRAIL_PASSWORD", password)
        .env("PATH", path);
    cmd
}

fn json_output(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("json output")
}

fn piped_json(home: &Path, password: &str, args: &[&str], stdin: &str) -> Value {
    let mut child = lockrail_cmd(home, password)
        .args(args)
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    json_output(child.wait_with_output().expect("wait output"))
}

fn assert_secret_absent(dir: &Path, needle: &str) {
    fn walk(path: &Path, needle: &str) {
        for entry in fs::read_dir(path).expect("read dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                walk(&path, needle);
                continue;
            }
            let bytes = fs::read(&path).expect("read file");
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(needle),
                "found forbidden plaintext in {}",
                path.display()
            );
        }
    }
    walk(dir, needle);
}

#[test]
fn setup_demo_and_status_work_from_clean_home() {
    let temp_home = tempfile::tempdir().expect("temp home");
    let home = temp_home.path();
    let password = "demo-password";

    let setup = json_output(
        lockrail_cmd(home, password)
            .args(["setup", "--json"])
            .output()
            .expect("setup"),
    );
    assert_eq!(setup["status"], "ready");
    assert!(
        setup["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .any(|tool| tool == "claude")
    );
    assert!(
        setup["shims"]["installed"]
            .as_array()
            .expect("installed")
            .len()
            >= 4
    );

    let demo = json_output(
        lockrail_cmd(home, password)
            .args(["demo", "--json"])
            .output()
            .expect("demo"),
    );
    assert!(demo.as_array().expect("demo array").len() >= 4);

    let status = json_output(
        lockrail_cmd(home, password)
            .args(["status", "--json"])
            .output()
            .expect("status"),
    );
    assert!(status["vault_encrypted"].as_bool().unwrap_or(false));
}

#[test]
fn init_protect_demo_status_and_proof_pack_work() {
    let temp_home = tempfile::tempdir().expect("temp home");
    let home = temp_home.path();
    let password = "demo-password";
    let raw_demo_secret = "sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456";

    let init = json_output(
        lockrail_cmd(home, password)
            .args(["init", "--yes", "--json"])
            .output()
            .expect("init"),
    );
    assert_eq!(init["message"], "Lockrail is ready.");

    let protect = json_output(
        lockrail_cmd(home, password)
            .args(["protect", "--tool", "all", "--yes", "--json"])
            .output()
            .expect("protect"),
    );
    assert!(
        protect["safe_handle_test"]["handle_only"]
            .as_bool()
            .unwrap_or(false)
    );

    let demo = json_output(
        lockrail_cmd(home, password)
            .args(["demo", "--json"])
            .output()
            .expect("demo"),
    );
    assert!(demo.as_array().expect("demo array").len() >= 4);

    let status = json_output(
        lockrail_cmd(home, password)
            .args(["status", "--json"])
            .output()
            .expect("status"),
    );
    assert!(status["vault_encrypted"].as_bool().unwrap_or(false));

    let proof_pack_path = home.join("lockrail-proof-pack.json");
    let proof = json_output(
        lockrail_cmd(home, password)
            .args([
                "proof",
                "pack",
                "--out",
                proof_pack_path.to_str().expect("path"),
                "--markdown",
                "--json",
            ])
            .output()
            .expect("proof pack"),
    );
    assert_eq!(
        proof["out"].as_str().expect("out path"),
        proof_pack_path.to_str().expect("path string")
    );
    let proof_contents = fs::read_to_string(&proof_pack_path).expect("proof pack file");
    assert!(!proof_contents.contains(raw_demo_secret));

    let audit = json_output(
        lockrail_cmd(home, password)
            .args(["audit", "export", "--json"])
            .output()
            .expect("audit export"),
    );
    let audit_text = serde_json::to_string(&audit).expect("audit text");
    assert!(!audit_text.contains(raw_demo_secret));

    assert_secret_absent(home, raw_demo_secret);
}

#[test]
fn env_pipe_and_harness_commands_work() {
    let temp_home = tempfile::tempdir().expect("temp home");
    let home = temp_home.path();
    let temp_files = tempfile::tempdir().expect("temp files");
    let password = "demo-password";
    let raw_secret = "OPENAI_API_KEY=sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456";

    json_output(
        lockrail_cmd(home, password)
            .args(["init", "--yes", "--json"])
            .output()
            .expect("init"),
    );

    let env_path = temp_files.path().join(".env");
    fs::write(&env_path, format!("{raw_secret}\nMODE=dev\n")).expect("write env");

    let scan = json_output(
        lockrail_cmd(home, password)
            .args(["env", "scan", env_path.to_str().expect("path"), "--json"])
            .output()
            .expect("env scan"),
    );
    assert_eq!(scan["count"], 1);

    let sealed_path = temp_files.path().join(".env.lockrail");
    let seal = json_output(
        lockrail_cmd(home, password)
            .args([
                "env",
                "seal",
                env_path.to_str().expect("path"),
                "--out",
                sealed_path.to_str().expect("path"),
                "--json",
            ])
            .output()
            .expect("env seal"),
    );
    assert!(
        seal["safe_text"]
            .as_str()
            .expect("safe_text")
            .contains("lockrail://secret/openai-key/")
    );
    let sealed_text = fs::read_to_string(&sealed_path).expect("sealed file");
    assert!(!sealed_text.contains(raw_secret));

    let env_run = json_output(
        lockrail_cmd(home, password)
            .args([
                "--json",
                "env",
                "run",
                "--file",
                sealed_path.to_str().expect("path"),
                "--",
                "sh",
                "-c",
                "printf '%s' \"$OPENAI_API_KEY\"",
            ])
            .output()
            .expect("env run"),
    );
    assert!(
        env_run["stdout"]
            .as_str()
            .expect("stdout")
            .contains("lockrail://secret/openai-key/")
    );

    let pipe = piped_json(
        home,
        password,
        &["pipe"],
        "slack token xoxb-LOCKRAILTEST-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX",
    );
    assert!(
        pipe["safe_text"]
            .as_str()
            .expect("safe_text")
            .contains("lockrail://secret/slack-bot-token/")
    );

    let harness_check = json_output(
        lockrail_cmd(home, password)
            .args(["harness", "check", "--json"])
            .output()
            .expect("harness check"),
    );
    assert!(harness_check["items"].is_array());

    let harness_test = json_output(
        lockrail_cmd(home, password)
            .args(["harness", "test", "--tool", "codex", "--json"])
            .output()
            .expect("harness test"),
    );
    assert!(harness_test["items"].is_array());

    assert_secret_absent(home, "sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456");
}
