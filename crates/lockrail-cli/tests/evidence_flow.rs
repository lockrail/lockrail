//! PLAN.md GATE 7 (dir sink): anchors shipped in digests, tamper detection against shipped
//! anchors, and an explicit unanchored tail.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Env {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    system: PathBuf,
    sink: PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let r = tmp.path().to_path_buf();
    for d in ["home", "system", "sink"] {
        fs::create_dir_all(r.join(d)).unwrap();
    }
    Env {
        home: r.join("home"),
        system: r.join("system"),
        sink: r.join("sink"),
        _tmp: tmp,
    }
}

fn cmd(e: &Env) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    c.env("LOCKRAIL_HOME", &e.home)
        .env("LOCKRAIL_SYSTEM_DIR", &e.system)
        .env("LOCKRAIL_KEYSTORE", "file")
        .env_remove("LOCKRAIL_PASSWORD");
    c
}

fn run(e: &Env, args: &[&str]) -> (i32, Value) {
    let out = cmd(e).args(args).arg("--json").output().unwrap();
    let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap_or(-1), v)
}

fn events(e: &Env, n: usize) {
    for _ in 0..n {
        assert_eq!(run(e, &["policy", "show"]).0, 0);
    }
}

fn day_file(home: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = fs::read_dir(home.join("events"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "jsonl") && p.file_name().unwrap() != "anchors.jsonl"
        })
        .collect();
    files.sort();
    files.pop().unwrap()
}

fn drop_last(path: &Path, n: usize) {
    let lines: Vec<String> = fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    fs::write(path, lines[..lines.len() - n].join("\n") + "\n").unwrap();
}

fn ship_cycle(e: &Env) {
    assert_eq!(run(e, &["evidence", "anchor"]).0, 0);
    assert_eq!(run(e, &["evidence", "digest"]).0, 0);
    let (code, out) = run(
        e,
        &[
            "evidence",
            "ship",
            "--sink",
            "dir",
            "--dir",
            e.sink.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{out}");
}

fn verify(e: &Env) -> (i32, Value) {
    run(
        e,
        &[
            "evidence",
            "verify",
            "--sink",
            "dir",
            "--dir",
            e.sink.to_str().unwrap(),
        ],
    )
}

fn managed(e: &Env) {
    let key = e.home.join("org.key");
    let (_, out) = run(e, &["policy", "keygen", "--out", key.to_str().unwrap()]);
    fs::write(e.system.join("org.pub"), out["org_pub"].as_str().unwrap()).unwrap();
}

#[test]
fn shipped_anchor_verifies_and_catches_deletion() {
    let e = env();
    managed(&e);
    events(&e, 10);
    ship_cycle(&e);
    let (code, out) = verify(&e);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["chain"]["unanchored_tail"], 0);

    drop_last(&day_file(&e.home), 5);
    let (code, out) = verify(&e);
    assert_eq!(code, 1, "{out}");
    let problems = out["chain"]["problems"].to_string();
    assert!(
        problems.contains("truncated_before_anchor") || problems.contains("chain_mismatch"),
        "{problems}"
    );
}

#[test]
fn events_after_the_last_shipped_anchor_are_an_explicit_tail() {
    let e = env();
    managed(&e);
    events(&e, 4);
    ship_cycle(&e);
    events(&e, 5);
    let (code, out) = verify(&e);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["chain"]["unanchored_tail"], 5);
    // A second cycle anchors them and ships only the new anchor.
    ship_cycle(&e);
    let (_, out) = verify(&e);
    assert_eq!(out["chain"]["unanchored_tail"], 0);
}

#[test]
fn outbox_and_digests_hold_counters_not_values() {
    let e = env();
    managed(&e);
    events(&e, 3);
    assert_eq!(run(&e, &["evidence", "anchor"]).0, 0);
    assert_eq!(run(&e, &["evidence", "digest"]).0, 0);
    let outbox: Vec<PathBuf> = fs::read_dir(e.home.join("outbox"))
        .unwrap()
        .flatten()
        .map(|d| d.path())
        .collect();
    assert_eq!(outbox.len(), 1);
    let digest: Value = serde_json::from_slice(&fs::read(&outbox[0]).unwrap()).unwrap();
    assert_eq!(digest["counts"]["policy_missing"], 3);
    for key in digest.as_object().unwrap().keys() {
        assert!(!key.ends_with("_key") && key != "key", "{key}");
    }
}

#[test]
fn proof_pack_is_signed_and_one_changed_byte_fails() {
    let e = env();
    assert_eq!(run(&e, &["setup", "--tools", "claude"]).0, 0);
    let pack = e.home.join("pack.json");
    assert_eq!(
        run(&e, &["proof", "pack", "--out", pack.to_str().unwrap()]).0,
        0
    );
    let (code, out) = run(&e, &["proof", "verify", pack.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    let mut bytes = fs::read(&pack).unwrap();
    let i = bytes.iter().position(|b| *b == b':').unwrap();
    bytes[i + 2] ^= 1;
    fs::write(&pack, bytes).unwrap();
    let (code, out) = run(&e, &["proof", "verify", pack.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert_eq!(out["reason"], "pack_changed");
}

#[test]
fn proof_pack_resigned_by_another_key_is_not_trusted() {
    use base64ct::{Base64, Encoding};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    let e = env();
    assert_eq!(run(&e, &["setup", "--tools", "claude"]).0, 0);
    let pack = e.home.join("pack.json");
    assert_eq!(
        run(&e, &["proof", "pack", "--out", pack.to_str().unwrap()]).0,
        0
    );
    let genuine: Value =
        serde_json::from_slice(&fs::read(e.home.join("pack.json.sig.json")).unwrap()).unwrap();
    let genuine_pub = genuine["device_pub_b64"].as_str().unwrap().to_string();

    // A tampered pack, re-signed by someone else, carrying their own public key.
    let tampered = b"{\"tampered\":true}".to_vec();
    fs::write(&pack, &tampered).unwrap();
    let attacker = SigningKey::from_bytes(&[7u8; 32]);
    let sha = hex::encode(Sha256::digest(&tampered));
    let sig = attacker.sign(format!("lockrail-proof-v1\n{sha}").as_bytes());
    let attacker_pub = Base64::encode_string(attacker.verifying_key().as_bytes());
    let forged = serde_json::json!({
        "v": 1, "sha256": sha, "device_pub_b64": attacker_pub,
        "sig_b64": Base64::encode_string(&sig.to_bytes()),
    });
    fs::write(
        e.home.join("pack.json.sig.json"),
        serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();

    let (code, out) = run(&e, &["proof", "verify", pack.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert_eq!(out["reason"], "untrusted_signer");
    // Naming the right trusted key does not rescue it either.
    let (code, out) = run(
        &e,
        &[
            "proof",
            "verify",
            pack.to_str().unwrap(),
            "--device-pub",
            &genuine_pub,
        ],
    );
    assert_eq!(code, 1, "{out}");
    assert_eq!(out["reason"], "untrusted_signer");
    // An auditor who trusts that exact key can say so explicitly.
    let (code, out) = run(
        &e,
        &[
            "proof",
            "verify",
            pack.to_str().unwrap(),
            "--device-pub",
            &attacker_pub,
        ],
    );
    assert_eq!(code, 0, "{out}");
}
