//! Broker socket (PLAN.md section 3.3).
//!
//! One JSON request per connection on `<home>/broker.sock` (mode `0600`, directory `0700`):
//! - `{"op":"authorize","argv":[..],"cwd":"..","path":"..","env_file":".."|null}`: the broker
//!   computes the command fingerprint itself (it never trusts one from the client), and answers
//!   `granted: cached` from an unexpired grant or asks for presence and caches a `4 h` grant.
//! - `{"op":"presence","reason":".."}`: always asks; never cached (`secret export`, ...).
//! - `{"op":"revoke"}`: drop every grant. `{"op":"status"}`: presence kind and grant count.
//!
//! The peer must have this user's uid and, on macOS, run this same executable; anything else is
//! refused before a request is read. Failures are refusals (fail closed).

use crate::fingerprint::{self, Fingerprint, Input};
use crate::presence::{Presence, confirm_or_refuse};
use crate::{GRANT_TTL, GrantStore};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Authorize {
        argv: Vec<String>,
        cwd: PathBuf,
        path: String,
        env_file: Option<PathBuf>,
    },
    Presence {
        reason: String,
    },
    Revoke,
    Status,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl Response {
    fn ok(granted: &str) -> Self {
        Self {
            ok: true,
            granted: Some(granted.into()),
            error: None,
            detail: None,
        }
    }
    fn err(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            granted: None,
            error: Some(error.into()),
            detail: None,
        }
    }
}

pub struct Broker {
    pub grants: GrantStore,
    presence: Box<dyn Presence>,
    prompt_lock: Mutex<()>,
}

impl Broker {
    pub fn new(presence: Box<dyn Presence>) -> Self {
        Self {
            grants: GrantStore::default(),
            presence,
            prompt_lock: Mutex::new(()),
        }
    }

    pub fn handle(&self, request: Request) -> Response {
        match request {
            Request::Authorize {
                argv,
                cwd,
                path,
                env_file,
            } => {
                if argv.is_empty() {
                    return Response::err("bad_request: empty argv");
                }
                let fp = match fingerprint::compute(&Input {
                    argv: &argv,
                    cwd: &cwd,
                    path: &path,
                    env_file: env_file.as_deref(),
                }) {
                    Ok(fp) => fp,
                    Err(e) => {
                        return Response::err(format!("grant_required: fingerprint failed: {e}"));
                    }
                };
                if let Fingerprint::Exact(ref key) = fp
                    && self.grants.check(key)
                {
                    return Response::ok("cached");
                }
                let reason = format!(
                    "allow `{}` in {} to use Lockrail secrets",
                    argv.join(" "),
                    cwd.display()
                );
                let _one_prompt = self.prompt_lock.lock().expect("prompt lock");
                match confirm_or_refuse(self.presence.as_ref(), &reason) {
                    Ok(()) => {
                        if let Fingerprint::Exact(key) = fp {
                            self.grants.insert(&key, GRANT_TTL);
                            Response::ok("presence")
                        } else {
                            // Over the stat-walk cap: approved once, nothing cached.
                            Response::ok("presence_uncached")
                        }
                    }
                    Err(e) => Response::err(format!("grant_required: {e}")),
                }
            }
            Request::Presence { reason } => {
                let _one_prompt = self.prompt_lock.lock().expect("prompt lock");
                match confirm_or_refuse(self.presence.as_ref(), &reason) {
                    Ok(()) => Response::ok("presence"),
                    Err(e) => Response::err(e.to_string()),
                }
            }
            Request::Revoke => {
                let n = self.grants.revoke_all();
                Response {
                    detail: Some(serde_json::json!({"revoked": n})),
                    ..Response::ok("revoked")
                }
            }
            Request::Status => Response {
                detail: Some(serde_json::json!({
                    "presence": self.presence.kind(),
                    "grants": self.grants.len(),
                })),
                ..Response::ok("status")
            },
        }
    }
}

/// Bind `socket` with mode `0600` inside a `0700` directory, replacing a stale socket file.
pub fn bind(socket: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let dir = socket
        .parent()
        .ok_or_else(|| anyhow!("socket path has no parent"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    if socket.exists() {
        if UnixStream::connect(socket).is_ok() {
            return Err(anyhow!(
                "a broker is already running on {}",
                socket.display()
            ));
        }
        std::fs::remove_file(socket)?;
    }
    let listener =
        UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn serve(listener: UnixListener, broker: Arc<Broker>) -> Result<()> {
    screen_lock::watch(broker.clone());
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let broker = broker.clone();
        std::thread::spawn(move || {
            let _ = handle_connection(stream, &broker);
        });
    }
    Ok(())
}

fn handle_connection(mut stream: UnixStream, broker: &Broker) -> Result<()> {
    if let Err(reason) = peer::verify(&stream) {
        let reply = Response::err(format!("peer_refused: {reason}"));
        let _ = writeln!(stream, "{}", serde_json::to_string(&reply)?);
        return Ok(());
    }
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let reply = match serde_json::from_str::<Request>(&line) {
        Ok(request) => broker.handle(request),
        Err(_) => Response::err("bad_request"),
    };
    writeln!(stream, "{}", serde_json::to_string(&reply)?)?;
    Ok(())
}

/// Client side: one request, one response. The answering process must be this same lockrail
/// executable running as this user: anything else on the socket (a listener an agent put there
/// that always says yes) is refused, so presence cannot be faked by owning the socket path.
pub fn call(socket: &Path, request: &Request) -> Result<Response> {
    let mut stream =
        UnixStream::connect(socket).with_context(|| format!("connect {}", socket.display()))?;
    if let Err(reason) = peer::verify(&stream) {
        anyhow::bail!("peer_refused: the broker socket is not served by lockrail ({reason})");
    }
    writeln!(stream, "{}", serde_json::to_string(request)?)?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    serde_json::from_str(&line).context("broker response")
}

mod peer {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    /// Same uid, and on macOS the same executable as this broker. Fail closed.
    pub fn verify(stream: &UnixStream) -> Result<(), String> {
        let fd = stream.as_raw_fd();
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: fd is a connected Unix socket; uid/gid are valid out-pointers.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err("cannot read peer credentials".into());
        }
        // SAFETY: getuid has no preconditions.
        if uid != unsafe { libc::getuid() } {
            return Err(format!("peer uid {uid} is not this user"));
        }
        #[cfg(target_os = "macos")]
        {
            let pid = peer_pid(fd).ok_or("cannot read peer pid")?;
            let peer_exe = pid_path(pid).ok_or("cannot read peer executable")?;
            let own = std::env::current_exe()
                .and_then(|p| p.canonicalize())
                .map_err(|e| e.to_string())?;
            let peer_exe = std::path::Path::new(&peer_exe)
                .canonicalize()
                .map_err(|e| e.to_string())?;
            if peer_exe != own {
                return Err(format!(
                    "peer executable {} is not lockrail",
                    peer_exe.display()
                ));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn peer_pid(fd: libc::c_int) -> Option<libc::pid_t> {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SOL_LOCAL = 0, LOCAL_PEERPID = 2 (sys/un.h).
        // SAFETY: valid fd and out-pointers of the advertised size.
        let rc =
            unsafe { libc::getsockopt(fd, 0, 2, (&mut pid as *mut libc::pid_t).cast(), &mut len) };
        (rc == 0 && pid > 0).then_some(pid)
    }

    #[cfg(target_os = "macos")]
    fn pid_path(pid: libc::pid_t) -> Option<String> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: buf is writable for its full length.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
    }
}

mod screen_lock {
    use super::Broker;
    use std::sync::Arc;

    /// Drop every grant when the screen locks (polls the session state every 2 s).
    pub fn watch(broker: Arc<Broker>) {
        std::thread::spawn(move || {
            let mut was_locked = false;
            loop {
                let locked = is_locked();
                if locked && !was_locked {
                    broker.grants.revoke_all();
                }
                was_locked = locked;
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        });
    }

    #[cfg(target_os = "macos")]
    fn is_locked() -> bool {
        use core_foundation::base::{CFType, TCFType};
        use core_foundation::boolean::CFBoolean;
        use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
        use core_foundation::string::CFString;
        #[link(name = "CoreGraphics", kind = "framework")]
        unsafe extern "C" {
            fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
        }
        // SAFETY: returns a +1 dictionary or null.
        let raw = unsafe { CGSessionCopyCurrentDictionary() };
        if raw.is_null() {
            return false;
        }
        // SAFETY: raw is a valid CFDictionary we own.
        let dict: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(raw) };
        dict.find(CFString::from_static_string("CGSSessionScreenIsLocked"))
            .and_then(|v| v.downcast::<CFBoolean>())
            .is_some_and(bool::from)
    }

    #[cfg(not(target_os = "macos"))]
    fn is_locked() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::Stub;

    #[test]
    fn deny_means_grant_required_and_approve_is_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let req = || Request::Authorize {
            argv: vec!["true".into()],
            cwd: tmp.path().to_path_buf(),
            path: "/usr/bin:/bin".into(),
            env_file: None,
        };
        let denying = Broker::new(Box::new(Stub { approve: false }));
        let r = denying.handle(req());
        assert!(!r.ok && r.error.unwrap().starts_with("grant_required"));

        let approving = Broker::new(Box::new(Stub { approve: true }));
        assert_eq!(approving.handle(req()).granted.as_deref(), Some("presence"));
        assert_eq!(approving.handle(req()).granted.as_deref(), Some("cached"));
        approving.handle(Request::Revoke);
        assert_eq!(approving.handle(req()).granted.as_deref(), Some("presence"));
    }

    #[test]
    fn presence_op_is_never_cached() {
        let approving = Broker::new(Box::new(Stub { approve: true }));
        let ask = || Request::Presence {
            reason: "export".into(),
        };
        assert!(approving.handle(ask()).ok);
        assert_eq!(approving.grants.len(), 0);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod client_auth_tests {
    use super::*;

    /// Security-guidance finding: the CLI trusted whatever listened on `broker.sock`. A fake
    /// broker (here Python, any other executable) that always answers "ok" must be refused.
    #[test]
    fn a_fake_broker_on_the_socket_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let script = r#"
import socket, sys, os
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1]); s.listen(1)
print("ready", flush=True)
c, _ = s.accept()
c.recv(4096)
c.sendall(b'{"ok":true}\n')
"#;
        let mut child = std::process::Command::new("python3")
            .args(["-I", "-c", script, socket.to_str().unwrap()])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("python3");
        let mut ready = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut ready,
        )
        .unwrap();
        let err = call(&socket, &Request::Status).expect_err("fake broker accepted");
        assert!(err.to_string().starts_with("peer_refused"), "{err}");
        let _ = child.kill();
        let _ = child.wait();
    }
}
