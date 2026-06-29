use lockrail_protocol::Receipt;
use lockrail_vault::Vault;
use secrecy::SecretString;
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
        .env("PATH", path)
        .env_remove("RUST_LOG");
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
fn oss_temp_home_end_to_end() {
    let temp_home = tempfile::tempdir().expect("temp home");
    let home = temp_home.path();
    let password = "demo-password";
    let raw_secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";

    let setup = json_output(
        lockrail_cmd(home, password)
            .args(["setup", "--apply", "--json"])
            .output()
            .expect("setup"),
    );
    assert_eq!(setup["status"], "ready");

    let doctor = json_output(
        lockrail_cmd(home, password)
            .args(["doctor", "--json"])
            .output()
            .expect("doctor"),
    );
    assert!(doctor["checks"]["vault_exists"].as_bool().unwrap_or(false));
    assert!(
        doctor["checks"]["security_defaults_enabled"]
            .as_bool()
            .unwrap_or(false)
    );

    let seal = piped_json(home, password, &["seal"], &format!("Use {raw_secret}\n"));
    let safe_text = seal["safe_text"].as_str().expect("safe_text");
    assert!(safe_text.contains("lockrail://secret/openai-key/fp_"));
    assert!(!safe_text.contains(raw_secret));

    let fingerprint = seal["findings"][0]["fingerprint"]
        .as_str()
        .expect("fingerprint");
    let secret_name = format!("sealed/openai-key/{fingerprint}");
    assert_secret_absent(home, raw_secret);

    let secrets = json_output(
        lockrail_cmd(home, password)
            .args(["secret", "list", "--json"])
            .output()
            .expect("secret list"),
    );
    assert!(
        secrets
            .as_array()
            .expect("secret list array")
            .iter()
            .any(|item| item["name"] == secret_name)
    );

    let metadata = json_output(
        lockrail_cmd(home, password)
            .args(["secret", "show", &secret_name, "--metadata-only", "--json"])
            .output()
            .expect("secret show"),
    );
    assert_eq!(metadata["fingerprint"], fingerprint);

    let agent = json_output(
        lockrail_cmd(home, password)
            .args(["agent", "create", "codex", "--type", "codex", "--json"])
            .output()
            .expect("agent create"),
    );
    let agent_id = agent["agent_id"].as_str().expect("agent id").to_string();

    let agents = json_output(
        lockrail_cmd(home, password)
            .args(["agent", "list", "--json"])
            .output()
            .expect("agent list"),
    );
    assert!(
        agents
            .as_array()
            .expect("agents array")
            .iter()
            .any(|item| item["agent_id"] == agent_id)
    );

    let public = json_output(
        lockrail_cmd(home, password)
            .args(["agent", "public", &agent_id, "--json"])
            .output()
            .expect("agent public"),
    );
    assert_eq!(public["agent_id"], agent_id);

    let issued = json_output(
        lockrail_cmd(home, password)
            .args([
                "capability",
                "issue",
                &secret_name,
                "--preset",
                "openai",
                "--agent",
                &agent_id,
                "--task-id",
                "demo-task",
                "--purpose",
                "demo",
                "--json",
            ])
            .output()
            .expect("capability issue"),
    );
    let token = issued["token"].as_str().expect("token").to_string();

    let inspected = json_output(
        lockrail_cmd(home, password)
            .args(["capability", "inspect", &token, "--json"])
            .output()
            .expect("capability inspect"),
    );
    assert_eq!(inspected["key"], secret_name);
    assert_eq!(inspected["task_id"], "demo-task");
    assert_eq!(inspected["purpose"], "demo");

    let audit = json_output(
        lockrail_cmd(home, password)
            .args(["audit", "verify", "--json"])
            .output()
            .expect("audit verify"),
    );
    assert!(audit["ok"].as_bool().unwrap_or(false));

    let audit_rows = json_output(
        lockrail_cmd(home, password)
            .args(["audit", "list", "--json"])
            .output()
            .expect("audit list"),
    );
    let serialized_audit = serde_json::to_string(&audit_rows).expect("audit json");
    assert!(!serialized_audit.contains(raw_secret));

    let mut vault =
        Vault::open(home.join("vault.lockrail"), SecretString::from(password)).expect("open vault");
    let loaded_agent = vault.load_agent(&agent_id).expect("load agent");
    let agent_private_key = loaded_agent.private_key.clone();
    assert_secret_absent(home, &agent_private_key);

    let receipt = Receipt::new(
        uuid::Uuid::new_v4(),
        None,
        "https://api.openai.com/v1/chat/completions",
        200,
        &vault.signing_key().expect("signing key"),
    )
    .expect("receipt");
    receipt
        .verify(&vault.issuer_public_key().expect("issuer public"))
        .expect("receipt verify");

    assert_secret_absent(home, raw_secret);
    assert_secret_absent(home, &agent_private_key);
}

#[test]
fn cli_wrong_password_returns_vault_exit_code() {
    let temp_home = tempfile::tempdir().expect("temp home");
    let home = temp_home.path();
    let ok_password = "good-password";

    let init = lockrail_cmd(home, ok_password)
        .args(["init"])
        .output()
        .expect("init");
    assert!(init.status.success());

    let wrong = lockrail_cmd(home, "wrong-password")
        .args(["secret", "list", "--json"])
        .output()
        .expect("wrong password command");
    assert_eq!(wrong.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&wrong.stderr);
    assert!(stderr.contains("wrong password"));
}
