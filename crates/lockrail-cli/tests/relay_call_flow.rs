//! PLAN.md GATE 8 (D11): an agent-bound capability is refused without a proof, and
//! `lockrail relay call` builds a proof the relay accepts. The upstream is a host outside the
//! capability, so the request never leaves the machine; which check refuses it shows whether
//! the proof passed (proof check runs before the host check).

use serde_json::Value;
use std::path::Path;
use std::process::{Child, Command, Stdio};

fn cmd(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    c.env("LOCKRAIL_HOME", home)
        .env("LOCKRAIL_KEYSTORE", "file")
        .env_remove("LOCKRAIL_PASSWORD");
    c
}

fn run(home: &Path, args: &[&str]) -> Value {
    let out = cmd(home).args(args).arg("--json").output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

struct Relay(Child);
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn find_token(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if s.starts_with("lrap") => Some(s.clone()),
        Value::Object(m) => m.values().find_map(find_token),
        Value::Array(a) => a.iter().find_map(find_token),
        _ => None,
    }
}

#[test]
fn agent_token_needs_a_proof_and_relay_call_supplies_it() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    run(h, &["setup", "--tools", "claude"]);
    run(
        h,
        &["secret", "set", "OPENAI_KEY", "value-for-relay-test-123"],
    );
    run(h, &["agent", "create", "a1", "--type", "codex"]);
    let issued = run(
        h,
        &[
            "capability",
            "issue",
            "OPENAI_KEY",
            "--host",
            "api.openai.com",
            "--method",
            "POST",
            "--path",
            "/v1/*",
            "--agent",
            "a1",
            "--minutes",
            "5",
        ],
    );
    let token = find_token(&issued).expect("token in issue output");

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = h.join("config.json");
    let mut cfg: Value = if config.exists() {
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap()
    } else {
        serde_json::json!({})
    };
    cfg["relay_listen"] = Value::String(format!("127.0.0.1:{port}"));
    std::fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let _relay = Relay(
        cmd(h)
            .args(["relay", "start", "--addr", &format!("127.0.0.1:{port}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // No proof: refused at the proof check.
    let raw = Command::new("curl")
        .args(["-s", "-X", "POST", "-H", "content-type: application/json", "--data"])
        .arg(serde_json::json!({"capability": token, "method": "POST", "upstream": "https://evil.example.com/v1/x"}).to_string())
        .arg(format!("http://127.0.0.1:{port}/relay"))
        .output()
        .unwrap();
    let raw = String::from_utf8_lossy(&raw.stdout).to_string();
    assert!(
        raw.contains("secret not found") || raw.contains("policy denied"),
        "no-proof response: {raw}"
    );
    assert!(
        !raw.contains("host not allowed"),
        "request without proof got past the proof check: {raw}"
    );

    // relay call: the proof verifies, so the refusal comes from the later host check.
    let called = run(
        h,
        &[
            "relay",
            "call",
            "--agent",
            "a1",
            "--capability",
            &token,
            "--url",
            "https://evil.example.com/v1/x",
            "--body",
            "{\"model\":\"x\"}",
        ],
    );
    assert_eq!(called["relay_status"], 403);
    let body = called["response"].to_string();
    assert!(
        body.contains("host not allowed"),
        "relay call response: {body}"
    );
}
