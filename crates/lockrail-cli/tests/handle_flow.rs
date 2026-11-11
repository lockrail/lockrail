//! PLAN.md GATE 3 (handles): keyed handles differ across vaults, 0.3.7 `fp_` handles still
//! resolve, and PHI handles are never resolved into a command (B2).

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;

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
        "{args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn token() -> String {
    ["ghp_", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0Ed9Cb8"].concat()
}

#[test]
fn same_value_in_two_vaults_gets_different_keyed_handles() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    run(a.path(), &["setup", "--tools", "claude"]);
    run(b.path(), &["setup", "--tools", "claude"]);
    let text = format!("token {}", token());
    let sa = run(a.path(), &["seal", "--text", &text]);
    let sb = run(b.path(), &["seal", "--text", &text]);
    let ha = sa["safe_text"].as_str().unwrap();
    let hb = sb["safe_text"].as_str().unwrap();
    assert!(ha.contains("lockrail://secret/github-token/h_"), "{ha}");
    assert_ne!(ha, hb, "two vaults produced the same handle");
    assert!(
        !ha.contains(&lockrail_engine::seal::fingerprint(&token())),
        "unkeyed fingerprint leaked"
    );
}

#[test]
fn legacy_fp_handle_still_resolves() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    run(home.path(), &["setup", "--tools", "claude"]);
    // What 0.3.7 `env seal` stored and wrote: `env/<kind>/fp_<unkeyed>` and an fp_ handle.
    let fp = lockrail_engine::seal::fingerprint(&token());
    run(
        home.path(),
        &["secret", "set", &format!("env/github-token/{fp}"), &token()],
    );
    let env_file = work.path().join(".env.lockrail");
    fs::write(
        &env_file,
        format!("GITHUB_TOKEN=lockrail://secret/github-token/{fp}\n"),
    )
    .unwrap();
    let check = format!(
        "test \"$GITHUB_TOKEN\" = '{}' && echo resolved || echo unresolved",
        token()
    );
    let out = run(
        home.path(),
        &[
            "env",
            "run",
            "--file",
            env_file.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &check,
        ],
    );
    assert_eq!(out["stdout"].as_str().unwrap().trim(), "resolved");
}

#[test]
fn legacy_handle_resolves_through_the_index_after_reseal_under_a_keyed_name() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    run(home.path(), &["setup", "--tools", "claude"]);
    // The value now lives only under a keyed name (sealed by this version)...
    run(
        home.path(),
        &["seal", "--text", &format!("token {}", token())],
    );
    // ...and an old .env.lockrail still carries the 0.3.7 fp_ handle.
    let fp = lockrail_engine::seal::fingerprint(&token());
    let env_file = work.path().join(".env.lockrail");
    fs::write(
        &env_file,
        format!("GITHUB_TOKEN=lockrail://secret/github-token/{fp}\n"),
    )
    .unwrap();
    let check = format!(
        "test \"$GITHUB_TOKEN\" = '{}' && echo resolved || echo unresolved",
        token()
    );
    let out = run(
        home.path(),
        &[
            "env",
            "run",
            "--file",
            env_file.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &check,
        ],
    );
    assert_eq!(out["stdout"].as_str().unwrap().trim(), "resolved");
}

#[test]
fn phi_handle_is_never_resolved() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    run(home.path(), &["setup", "--tools", "claude"]);
    let phi = lockrail_engine::handle::phi_handle(
        "ssn",
        &lockrail_engine::handle::keyed_fingerprint(&[3u8; 32], "219-09-9999"),
    );
    let env_file = work.path().join(".env.lockrail");
    fs::write(&env_file, format!("PATIENT_SSN={phi}\n")).unwrap();
    let marker = work.path().join("ran");
    let out = cmd(home.path())
        .args([
            "env",
            "run",
            "--file",
            env_file.to_str().unwrap(),
            "--",
            "touch",
            marker.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("phi_handle_not_resolvable"),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !marker.exists(),
        "the command ran although a PHI handle was present"
    );
}

#[test]
fn sync_dotenv_is_written_0600_even_over_a_wider_file() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    run(home.path(), &["setup", "--tools", "claude"]);
    run(
        home.path(),
        &["secret", "set", "DOTENV_KEY", "line1\nline2"],
    );
    let out = work.path().join(".env.out");
    fs::write(&out, "old").unwrap();
    fs::set_permissions(&out, fs::Permissions::from_mode(0o644)).unwrap();
    run(
        home.path(),
        &["sync", "dotenv", "--out", out.to_str().unwrap()],
    );
    let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "dotenv mode {mode:o}");
    let text = fs::read_to_string(&out).unwrap();
    assert_eq!(
        text.lines()
            .filter(|l| l.starts_with("DOTENV_KEY="))
            .count(),
        1
    );
    assert!(
        !text.contains("line1\nline2"),
        "newline not escaped: {text:?}"
    );
}
