//! Lockrail broker (PLAN.md section 3.3, Phase 4; D4, R-11, M4).
//!
//! A per-user process that holds the presence gate and the grant cache:
//! - [`fingerprint`]: what a grant covers (one exact command in one exact project state).
//! - [`GrantStore`]: grants live only in the broker's memory, `4 h` at most, and are dropped on
//!   screen lock, so no file under `~/.lockrail` can be edited to forge one.
//! - [`Presence`]: the user-presence check. Signed builds use a Secure Enclave key with
//!   `userPresence`; development builds use a LocalAuthentication prompt and say so
//!   (`presence: software`). Debug builds can use a stub for tests.
//!
//! No TTY heuristics anywhere: `script -q /dev/null` gives an agent a TTY, so presence is the
//! only gate (adv_message_1 M4).

pub mod fingerprint;
pub mod presence;
pub mod server;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Grant lifetime (R-11).
pub const GRANT_TTL: Duration = Duration::from_secs(4 * 60 * 60);

#[derive(Default)]
pub struct GrantStore {
    grants: Mutex<HashMap<String, Instant>>,
}

impl GrantStore {
    /// True when an unexpired grant covers this fingerprint.
    pub fn check(&self, fingerprint: &str) -> bool {
        let mut grants = self.grants.lock().expect("grant store lock");
        let now = Instant::now();
        grants.retain(|_, expires| *expires > now);
        grants.contains_key(fingerprint)
    }

    pub fn insert(&self, fingerprint: &str, ttl: Duration) {
        self.grants
            .lock()
            .expect("grant store lock")
            .insert(fingerprint.to_string(), Instant::now() + ttl);
    }

    /// Drop every grant (screen lock, policy change, `lockrail broker revoke`).
    pub fn revoke_all(&self) -> usize {
        let mut grants = self.grants.lock().expect("grant store lock");
        let n = grants.len();
        grants.clear();
        n
    }

    pub fn len(&self) -> usize {
        self.grants.lock().expect("grant store lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_expire_and_revoke() {
        let store = GrantStore::default();
        store.insert("a", Duration::from_millis(30));
        store.insert("b", GRANT_TTL);
        assert!(store.check("a") && store.check("b"));
        std::thread::sleep(Duration::from_millis(40));
        assert!(!store.check("a"), "expired grant still valid");
        assert!(store.check("b"));
        assert_eq!(store.revoke_all(), 1);
        assert!(!store.check("b"));
    }
}
