//! User presence (PLAN.md section 3.3; M4).
//!
//! - `SecureEnclave`: signed builds only (Phase 9, owner item O-3): the vault key is wrapped by
//!   an SE key created with `userPresence`, so the OS itself demands Touch ID or the password.
//! - `Software`: development builds. A LocalAuthentication prompt (`deviceOwnerAuthentication`:
//!   Touch ID, or the login password). Reported as `presence: software` by `doctor` and in
//!   evidence, because a same-user process can bypass a gate that the OS does not enforce.
//! - `Stub`: debug builds only, for tests: `LOCKRAIL_PRESENCE_STUB=approve|deny`. Every call is
//!   appended to `LOCKRAIL_PRESENCE_STUB_LOG` when set, so tests can count prompts.

use anyhow::{Result, anyhow};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceKind {
    SecureEnclave,
    Software,
    Stub,
}

pub trait Presence: Send + Sync {
    /// Ask the user. `Ok(false)` means they cancelled or failed; `Err` means no prompt could be
    /// shown, which callers treat as a refusal (fail closed).
    fn confirm(&self, reason: &str) -> Result<bool>;
    fn kind(&self) -> PresenceKind;
}

/// The presence implementation for this build and environment.
pub fn system() -> Box<dyn Presence> {
    if cfg!(debug_assertions)
        && let Ok(mode) = std::env::var("LOCKRAIL_PRESENCE_STUB")
    {
        return Box::new(Stub {
            approve: mode == "approve",
        });
    }
    Box::new(Software)
}

pub struct Stub {
    pub approve: bool,
}

impl Presence for Stub {
    fn confirm(&self, reason: &str) -> Result<bool> {
        if let Ok(log) = std::env::var("LOCKRAIL_PRESENCE_STUB_LOG") {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log)?;
            writeln!(f, "{reason}")?;
        }
        Ok(self.approve)
    }
    fn kind(&self) -> PresenceKind {
        PresenceKind::Stub
    }
}

pub struct Software;

impl Presence for Software {
    fn confirm(&self, reason: &str) -> Result<bool> {
        local_auth::evaluate(reason)
    }
    fn kind(&self) -> PresenceKind {
        PresenceKind::Software
    }
}

#[cfg(target_os = "macos")]
mod local_auth {
    use anyhow::{Result, anyhow};
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::mpsc;
    use std::time::Duration;

    /// `deviceOwnerAuthentication`: Touch ID when enrolled, otherwise the login password.
    pub fn evaluate(reason: &str) -> Result<bool> {
        let context = unsafe { LAContext::new() };
        let reason = NSString::from_str(reason);
        let (tx, rx) = mpsc::channel::<bool>();
        let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            let _ = tx.send(success.as_bool());
        });
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &reason,
                &reply,
            );
        }
        rx.recv_timeout(Duration::from_secs(120))
            .map_err(|_| anyhow!("presence prompt timed out or could not be shown"))
    }
}

#[cfg(not(target_os = "macos"))]
mod local_auth {
    use anyhow::{Result, anyhow};

    pub fn evaluate(_reason: &str) -> Result<bool> {
        Err(anyhow!("user presence is only implemented on macOS"))
    }
}

/// Fail closed: an error showing the prompt is a refusal.
pub fn confirm_or_refuse(presence: &dyn Presence, reason: &str) -> Result<()> {
    match presence.confirm(reason) {
        Ok(true) => Ok(()),
        Ok(false) => Err(anyhow!("presence_denied: the request was not approved")),
        Err(error) => Err(anyhow!("presence_unavailable: {error}")),
    }
}
