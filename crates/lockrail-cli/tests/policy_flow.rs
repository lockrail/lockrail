//! PLAN.md GATE 2: signed policy, anti-rollback, last-known-good, managed defaults, and the
//! legacy vault-key migration with its rollback path. Debug builds only (`LOCKRAIL_SYSTEM_DIR`
//! and `LOCKRAIL_KEYSTORE=dir:` are ignored in release), so these never touch `/Library` or the
//! real Keychain.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;

struct Env {
    _tmp: tempfile::TempDir,
    home: std::path::PathBuf,
    system: std::path::PathBuf,
    external: std::path::PathBuf,
    work: std::path::PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    for d in ["home", "system", "external", "work"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    Env {
        home: root.join("home"),
        system: root.join("system"),
        external: root.join("external"),
        work: root.join("work"),
        _tmp: tmp,
    }
}

fn cmd(e: &Env, keystore: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    c.env("LOCKRAIL_HOME", &e.home)
        .env("LOCKRAIL_SYSTEM_DIR", &e.system)
        .env("LOCKRAIL_KEYSTORE", keystore)
        .env_remove("LOCKRAIL_PASSWORD")
        .current_dir(&e.work);
    c
}

fn run(e: &Env, keystore: &str, args: &[&str]) -> Value {
    let out = cmd(e, keystore).args(args).arg("--json").output().unwrap();
    assert!(
        out.status.success(),
        "lockrail {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| panic!("not json: {}", String::from_utf8_lossy(&out.stdout)))
}

fn file_store(e: &Env) -> String {
    let _ = e;
    "file".to_string()
}

/// Install org.pub into the system dir; returns the signing key path.
fn managed(e: &Env) -> std::path::PathBuf {
    let key = e.work.join("org.key");
    let out = run(
        e,
        "file",
        &["policy", "keygen", "--out", key.to_str().unwrap()],
    );
    fs::write(e.system.join("org.pub"), out["org_pub"].as_str().unwrap()).unwrap();
    key
}

fn install_policy(e: &Env, key: &Path, version: u64, phi: &str) {
    let staged = e.work.join("policy.json");
    fs::write(
        &staged,
        format!(
            r#"{{"version":{version},"org":"keemakr","phi_mode":"{phi}","fail_mode":"closed"}}"#
        ),
    )
    .unwrap();
    run(
        e,
        "file",
        &[
            "policy",
            "sign",
            "--key",
            key.to_str().unwrap(),
            staged.to_str().unwrap(),
        ],
    );
    fs::copy(&staged, e.system.join("policy.json")).unwrap();
    fs::copy(
        e.work.join("policy.json.sig"),
        e.system.join("policy.json.sig"),
    )
    .unwrap();
}

fn event_names(show: &Value) -> Vec<String> {
    show["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn unmanaged_machine_is_personal_and_unchanged() {
    let e = env();
    let show = run(&e, "file", &["policy", "show"]);
    assert_eq!(show["managed"], false);
    assert_eq!(show["source"], "personal");
    assert_eq!(show["phi_mode"], "off");
    assert!(event_names(&show).is_empty());
}

#[test]
fn managed_without_policy_is_strict_and_says_so() {
    let e = env();
    managed(&e);
    let show = run(&e, "file", &["policy", "show"]);
    assert_eq!(show["source"], "managed_default");
    assert_eq!(show["phi_mode"], "block");
    assert_eq!(show["fail_mode"], "closed");
    assert_eq!(event_names(&show), vec!["policy_missing"]);
    let verify = run(&e, "file", &["events", "verify"]);
    assert_eq!(verify["records"], 1);
    assert!(verify["problems"].as_array().unwrap().is_empty());
}

#[test]
fn flipped_byte_keeps_last_known_good_in_force() {
    let e = env();
    let key = managed(&e);
    install_policy(&e, &key, 3, "seal");
    let show = run(&e, "file", &["policy", "show"]);
    assert_eq!(show["source"], "signed");
    assert_eq!(show["version"], 3);
    assert_eq!(event_names(&show), vec!["policy_applied"]);

    let path = e.system.join("policy.json");
    let mut bytes = fs::read(&path).unwrap();
    let i = bytes.iter().position(|b| *b == b'k').unwrap();
    bytes[i] = b'K';
    fs::write(&path, bytes).unwrap();

    let show = run(&e, "file", &["policy", "show"]);
    assert_eq!(show["source"], "last_known_good");
    assert_eq!(show["version"], 3);
    assert_eq!(show["phi_mode"], "seal");
    assert_eq!(event_names(&show), vec!["policy_invalid"]);
    assert_eq!(show["events"][0]["reason"], "signature_mismatch");

    let verify = run(&e, "file", &["events", "verify"]);
    assert_eq!(verify["records"], 2);
}

#[test]
fn older_signed_policy_is_rejected_and_newer_stays() {
    let e = env();
    let key = managed(&e);
    install_policy(&e, &key, 5, "seal");
    run(&e, "file", &["policy", "show"]);
    install_policy(&e, &key, 4, "off");
    let show = run(&e, "file", &["policy", "show"]);
    assert_eq!(show["version"], 5);
    assert_eq!(show["phi_mode"], "seal");
    assert_eq!(event_names(&show), vec!["policy_rollback_rejected"]);
    assert_eq!(show["events"][0]["offered"], 4);
    assert_eq!(show["events"][0]["in_force"], 5);
}

#[test]
fn policy_verify_reports_tamper_with_exit_1() {
    let e = env();
    let key = managed(&e);
    install_policy(&e, &key, 1, "seal");
    let org = e.system.join("org.pub");
    let ok = run(
        &e,
        "file",
        &[
            "policy",
            "verify",
            "--org-pub",
            org.to_str().unwrap(),
            e.work.join("policy.json").to_str().unwrap(),
        ],
    );
    assert_eq!(ok["ok"], true);
    fs::write(
        e.work.join("policy.json"),
        br#"{"version":1,"org":"evil","phi_mode":"off","fail_mode":"open"}"#,
    )
    .unwrap();
    let out = cmd(&e, "file")
        .args([
            "policy",
            "verify",
            "--org-pub",
            org.to_str().unwrap(),
            e.work.join("policy.json").to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn legacy_vault_key_migrates_and_exports_back() {
    let e = env();
    // A 0.3.7-style home: vault.key next to the vault (file store).
    run(&e, &file_store(&e), &["setup", "--tools", "claude"]);
    run(
        &e,
        &file_store(&e),
        &["secret", "set", "MIGRATE_ME", "value-123"],
    );
    assert!(e.home.join("vault.key").exists());

    // Managed machine: the key moves to the external store and the file is gone.
    managed(&e);
    let ext = format!("dir:{}", e.external.display());
    let migrated = run(&e, &ext, &["keys", "migrate"]);
    assert_eq!(migrated["outcome"], "migrated");
    assert!(
        !e.home.join("vault.key").exists(),
        "vault.key still present"
    );
    let list = run(&e, &ext, &["secret", "list"]);
    assert!(
        list.to_string().contains("MIGRATE_ME"),
        "vault unreadable after migration: {list}"
    );

    // Rollback: export, then read the vault the way 0.3.7 does (vault.key only).
    // Writing the key back in plaintext needs presence: refused with no broker on a managed
    // machine, allowed once a broker approves.
    let refused = cmd(&e, &ext)
        .args(["keys", "export-legacy", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        refused.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("broker_unavailable"));
    let mut broker = cmd(&e, &ext)
        .args(["broker", "serve"])
        .env("LOCKRAIL_PRESENCE_STUB", "approve")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if std::os::unix::net::UnixStream::connect(e.home.join("broker.sock")).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let exported = cmd(&e, &ext)
        .args(["keys", "export-legacy", "--json"])
        .output()
        .unwrap();
    let _ = broker.kill();
    let _ = broker.wait();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(e.home.join("vault.key").exists());
    let list = run(&e, &file_store(&e), &["secret", "list"]);
    assert!(list.to_string().contains("MIGRATE_ME"));

    let verify = run(&e, &ext, &["events", "verify"]);
    assert!(verify["problems"].as_array().unwrap().is_empty());
}

#[test]
fn setup_on_a_managed_machine_migrates_once_and_unmanaged_does_not() {
    let e = env();
    run(&e, "file", &["setup", "--tools", "claude"]);
    run(&e, "file", &["secret", "set", "KEEP_ME", "value-456"]);
    let ext = format!("dir:{}", e.external.display());

    // Unmanaged machine, file store: setup leaves vault.key where 0.3.7 expects it.
    run(&e, "file", &["setup", "--tools", "claude"]);
    assert!(
        e.home.join("vault.key").exists(),
        "file store moved the key"
    );

    managed(&e);
    run(&e, &ext, &["setup", "--tools", "claude"]);
    assert!(
        !e.home.join("vault.key").exists(),
        "managed setup did not migrate"
    );

    // A second setup must not archive the vault (setup archives a home whose key it cannot
    // find) and must not recreate vault.key.
    run(&e, &ext, &["setup", "--tools", "claude"]);
    assert!(!e.home.join("vault.key").exists());
    let list = run(&e, &ext, &["secret", "list"]);
    assert!(
        list.to_string().contains("KEEP_ME"),
        "vault lost after setup: {list}"
    );
}
