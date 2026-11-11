//! PLAN.md GATE 6 (B8, m23): on a managed machine every hook first checks that the session
//! goes through the sealer. Debug build only (`LOCKRAIL_SYSTEM_DIR`).

use std::io::Write;
use std::process::{Command, Stdio};

fn hook(home: &std::path::Path, system: &std::path::Path, env: &[(&str, &str)]) -> String {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    c.args(["hook", "prompt"])
        .env("LOCKRAIL_HOME", home)
        .env("LOCKRAIL_SYSTEM_DIR", system)
        .env("LOCKRAIL_KEYSTORE", "file")
        .env_remove("LOCKRAIL_PASSWORD");
    for k in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        c.env_remove(k);
    }
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hello").unwrap();
    String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
}

#[test]
fn managed_hooks_block_a_session_that_bypasses_the_sealer() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, system) = (tmp.path().join("home"), tmp.path().join("system"));
    std::fs::create_dir_all(&system).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lockrail"))
        .args(["setup", "--tools", "claude", "--json"])
        .env("LOCKRAIL_HOME", &home)
        .env("LOCKRAIL_KEYSTORE", "file")
        .output()
        .unwrap();
    assert!(out.status.success());
    let key = tmp.path().join("org.key");
    let out = Command::new(env!("CARGO_BIN_EXE_lockrail"))
        .args(["policy", "keygen", "--out", key.to_str().unwrap(), "--json"])
        .env("LOCKRAIL_HOME", &home)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    std::fs::write(system.join("org.pub"), v["org_pub"].as_str().unwrap()).unwrap();

    let none = hook(&home, &system, &[]);
    assert!(
        none.contains(r#""decision":"block""#) && none.contains("proxy_bypass"),
        "{none}"
    );
    let bypass = hook(
        &home,
        &system,
        &[
            ("HTTPS_PROXY", "http://127.0.0.1:8789"),
            ("no_proxy", ".anthropic.com"),
        ],
    );
    assert!(bypass.contains("proxy_bypass"), "{bypass}");
    let ok = hook(&home, &system, &[("HTTPS_PROXY", "http://127.0.0.1:8789")]);
    assert!(!ok.contains("proxy_bypass"), "{ok}");
}
