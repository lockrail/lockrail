//! Org policy (PLAN.md section 3.5, Phase 2B; fixes M5 and m9).
//!
//! Files, all under the system directory (`/Library/Application Support/Lockrail`):
//! - `org.pub`: the org's Ed25519 public key (base64), installed root-owned by the pkg. Its
//!   presence is what makes a machine *managed*.
//! - `policy.json` and `policy.json.sig`: the policy bytes and a base64 Ed25519 signature over
//!   exactly those bytes.
//! - `state/policy-version`: the highest version ever accepted (anti-rollback).
//! - `state/lkg.json` and `state/lkg.json.sig`: the last-known-good signed policy.
//!
//! Evaluation never refuses to start (M5): a bad signature, an unreadable file or a rollback
//! keeps the last-known-good policy in force and emits an event. A managed machine with no
//! policy and no last-known-good gets strict defaults. An unmanaged machine gets personal
//! defaults, which reproduce 0.3.7 behaviour.
//!
//! `state/` is written only when the process may write it (in production, the root daemon).
//! A user-level CLI evaluates the same way but leaves the state alone, and says so.

use anyhow::{Context, Result, anyhow};
use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use lockrail_audit::events::{Event, PolicyInvalidReason};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const SYSTEM_DIR: &str = "/Library/Application Support/Lockrail";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PhiMode {
    Block,
    Seal,
    Warn,
    Off,
}

/// P-16: withhold each PHI span (default) or refuse the whole request (`request`).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PhiBlockScope {
    #[default]
    Span,
    Request,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FailMode {
    Open,
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Detectors {
    #[serde(default = "yes")]
    pub secrets: bool,
    #[serde(default)]
    pub phi: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolPolicy {
    /// Whether a BAA covers this tool's provider. `false` everywhere until O-2 is settled.
    #[serde(default)]
    pub baa: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tools {
    #[serde(default)]
    pub claude_code: ToolPolicy,
    #[serde(default)]
    pub codex: ToolPolicy,
    #[serde(default)]
    pub cursor: ToolPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    /// Sink names (`file`, `webhook`, `keetrust`); their settings arrive with Phase 7.
    #[serde(default)]
    pub sinks: Vec<String>,
    #[serde(default = "one")]
    pub digest_interval_hours: u32,
    #[serde(default)]
    pub controls: BTreeMap<String, String>,
}

impl Default for Evidence {
    fn default() -> Self {
        Self {
            sinks: vec![],
            digest_interval_hours: 1,
            controls: BTreeMap::new(),
        }
    }
}

/// The policy document. Unknown fields are ignored on purpose: a newer signed policy must not
/// push older clients onto last-known-good just because it added a field.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub version: u64,
    pub org: String,
    /// Kill switch: `false` turns the sealer into a pass-through and the hooks into no-ops.
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_detectors")]
    pub detectors: Detectors,
    pub phi_mode: PhiMode,
    #[serde(default)]
    pub phi_block_scope: PhiBlockScope,
    #[serde(default)]
    pub tools: Tools,
    pub fail_mode: FailMode,
    #[serde(default = "default_deadline")]
    pub scan_deadline_ms: u32,
    #[serde(default)]
    pub relay_hosts: Vec<String>,
    #[serde(default)]
    pub run_path: Option<String>,
    #[serde(default)]
    pub evidence: Evidence,
    #[serde(default)]
    pub image_allow_globs: Vec<String>,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub ring: u8,
}

fn yes() -> bool {
    true
}
fn one() -> u32 {
    1
}
fn default_deadline() -> u32 {
    45
}
fn default_detectors() -> Detectors {
    Detectors {
        secrets: true,
        phi: false,
    }
}

impl Policy {
    /// Unmanaged machine: 0.3.7 behaviour (secrets only, PHI off, fail open).
    pub fn personal() -> Self {
        Self {
            version: 0,
            org: String::new(),
            enabled: true,
            detectors: default_detectors(),
            phi_mode: PhiMode::Off,
            phi_block_scope: PhiBlockScope::Span,
            tools: Tools::default(),
            fail_mode: FailMode::Open,
            scan_deadline_ms: default_deadline(),
            relay_hosts: vec![],
            run_path: None,
            evidence: Evidence::default(),
            image_allow_globs: vec![],
            allowlist: vec![],
            ring: 0,
        }
    }

    /// Managed machine with no usable policy: strict (M5).
    pub fn managed_strict() -> Self {
        Self {
            detectors: Detectors {
                secrets: true,
                phi: true,
            },
            phi_mode: PhiMode::Block,
            fail_mode: FailMode::Closed,
            ..Self::personal()
        }
    }
}

/// Where the effective policy came from.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    Personal,
    Signed { version: u64 },
    LastKnownGood { version: u64 },
    ManagedDefault,
}

#[derive(Clone, Debug, Serialize)]
pub struct Effective {
    pub managed: bool,
    pub source: Source,
    pub policy: Policy,
    /// Highest version accepted so far, from `state/policy-version`.
    pub highest_accepted: Option<u64>,
    /// Whether this evaluation could update `state/`. `false` for a user-level CLI.
    pub state_writable: bool,
}

#[derive(Clone, Debug)]
pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    /// The real system directory. Debug builds honour `LOCKRAIL_SYSTEM_DIR` so tests never
    /// touch `/Library`; release builds ignore it, so an agent cannot point the CLI at a policy
    /// and org key of its own.
    pub fn system() -> Self {
        if cfg!(debug_assertions)
            && let Ok(dir) = std::env::var("LOCKRAIL_SYSTEM_DIR")
        {
            return Self {
                dir: PathBuf::from(dir),
            };
        }
        Self {
            dir: PathBuf::from(SYSTEM_DIR),
        }
    }

    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn org_pub(&self) -> PathBuf {
        self.dir.join("org.pub")
    }
    pub fn policy(&self) -> PathBuf {
        self.dir.join("policy.json")
    }
    pub fn policy_sig(&self) -> PathBuf {
        self.dir.join("policy.json.sig")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("state")
    }
    pub fn version_file(&self) -> PathBuf {
        self.state_dir().join("policy-version")
    }
    pub fn lkg(&self) -> PathBuf {
        self.state_dir().join("lkg.json")
    }
    pub fn lkg_sig(&self) -> PathBuf {
        self.state_dir().join("lkg.json.sig")
    }

    pub fn is_managed(&self) -> bool {
        self.org_pub().exists()
    }
}

pub fn encode_public_key(key: &VerifyingKey) -> String {
    Base64::encode_string(key.as_bytes())
}

pub fn decode_public_key(text: &str) -> Result<VerifyingKey> {
    let bytes = Base64::decode_vec(text.trim()).map_err(|_| anyhow!("org.pub is not base64"))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("org.pub is not a 32-byte Ed25519 key"))?;
    VerifyingKey::from_bytes(&array).map_err(|_| anyhow!("org.pub is not a valid Ed25519 key"))
}

pub fn encode_signing_key(key: &SigningKey) -> String {
    Base64::encode_string(key.as_bytes())
}

pub fn decode_signing_key(text: &str) -> Result<SigningKey> {
    let bytes =
        Base64::decode_vec(text.trim()).map_err(|_| anyhow!("org signing key is not base64"))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("org signing key is not 32 bytes"))?;
    Ok(SigningKey::from_bytes(&array))
}

pub fn generate_org_key() -> SigningKey {
    SigningKey::generate(&mut rand_core::OsRng)
}

/// Sign the exact bytes of a policy file. The policy must parse first, so a typo is caught at
/// signing time rather than on every laptop.
pub fn sign(policy_bytes: &[u8], key: &SigningKey) -> Result<String> {
    parse(policy_bytes)?;
    Ok(Base64::encode_string(&key.sign(policy_bytes).to_bytes()))
}

pub fn parse(policy_bytes: &[u8]) -> Result<Policy> {
    serde_json::from_slice(policy_bytes).context("policy.json does not match the schema")
}

/// Verify `sig_text` over `policy_bytes`, then parse. The error carries the event reason.
pub fn verify(
    policy_bytes: &[u8],
    sig_text: &str,
    org: &VerifyingKey,
) -> std::result::Result<Policy, PolicyInvalidReason> {
    let sig_bytes =
        Base64::decode_vec(sig_text.trim()).map_err(|_| PolicyInvalidReason::SignatureMalformed)?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|_| PolicyInvalidReason::SignatureMalformed)?;
    org.verify(policy_bytes, &sig)
        .map_err(|_| PolicyInvalidReason::SignatureMismatch)?;
    parse(policy_bytes).map_err(|_| PolicyInvalidReason::PolicyMalformed)
}

fn read_signed(
    path: &Path,
    sig_path: &Path,
    org: &VerifyingKey,
) -> std::result::Result<Option<(Vec<u8>, String, Policy)>, PolicyInvalidReason> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(PolicyInvalidReason::PolicyUnreadable),
    };
    let sig = match fs::read_to_string(sig_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PolicyInvalidReason::SignatureMissing);
        }
        Err(_) => return Err(PolicyInvalidReason::SignatureMalformed),
    };
    let policy = verify(&bytes, &sig, org)?;
    Ok(Some((bytes, sig, policy)))
}

fn read_highest(paths: &Paths) -> Option<u64> {
    fs::read_to_string(paths.version_file())
        .ok()
        .and_then(|t| t.trim().parse().ok())
}

/// Evaluate the effective policy and report every event the evaluation produced.
pub fn evaluate(paths: &Paths) -> (Effective, Vec<Event>) {
    let mut events = Vec::new();
    if !paths.is_managed() {
        return (
            Effective {
                managed: false,
                source: Source::Personal,
                policy: Policy::personal(),
                highest_accepted: None,
                state_writable: false,
            },
            events,
        );
    }
    let highest = read_highest(paths);
    let writable = state_writable(paths);

    let org = match fs::read_to_string(paths.org_pub())
        .map_err(|e| anyhow!(e))
        .and_then(|t| decode_public_key(&t))
    {
        Ok(key) => key,
        Err(_) => {
            events.push(Event::PolicyInvalid {
                reason: PolicyInvalidReason::OrgKeyUnreadable,
                fallback_version: None,
            });
            return (
                Effective {
                    managed: true,
                    source: Source::ManagedDefault,
                    policy: Policy::managed_strict(),
                    highest_accepted: highest,
                    state_writable: writable,
                },
                events,
            );
        }
    };

    let lkg = match read_signed(&paths.lkg(), &paths.lkg_sig(), &org) {
        Ok(found) => found,
        Err(_) => {
            events.push(Event::PolicyInvalid {
                reason: PolicyInvalidReason::LastKnownGoodInvalid,
                fallback_version: None,
            });
            None
        }
    };
    let fallback = || -> Effective {
        match &lkg {
            Some((_, _, policy)) => Effective {
                managed: true,
                source: Source::LastKnownGood {
                    version: policy.version,
                },
                policy: policy.clone(),
                highest_accepted: highest,
                state_writable: writable,
            },
            None => Effective {
                managed: true,
                source: Source::ManagedDefault,
                policy: Policy::managed_strict(),
                highest_accepted: highest,
                state_writable: writable,
            },
        }
    };
    let lkg_version = lkg.as_ref().map(|(_, _, p)| p.version);

    match read_signed(&paths.policy(), &paths.policy_sig(), &org) {
        Ok(None) => {
            events.push(Event::PolicyMissing {
                fallback_version: lkg_version,
            });
            let effective = fallback();
            (effective, events)
        }
        Err(reason) => {
            events.push(Event::PolicyInvalid {
                reason,
                fallback_version: lkg_version,
            });
            let effective = fallback();
            (effective, events)
        }
        Ok(Some((bytes, sig, policy))) => {
            let floor = highest.max(lkg_version);
            if let Some(floor) = floor
                && policy.version < floor
            {
                events.push(Event::PolicyRollbackRejected {
                    offered: policy.version,
                    in_force: floor,
                });
                let effective = fallback();
                return (effective, events);
            }
            let is_new = floor.is_none_or(|f| policy.version > f) || lkg.is_none();
            if writable && is_new && persist(paths, &bytes, &sig, policy.version).is_ok() {
                events.push(Event::PolicyApplied {
                    version: policy.version,
                });
            }
            let highest_now = if writable && is_new {
                Some(policy.version.max(highest.unwrap_or(0)))
            } else {
                highest
            };
            (
                Effective {
                    managed: true,
                    source: Source::Signed {
                        version: policy.version,
                    },
                    policy,
                    highest_accepted: highest_now,
                    state_writable: writable,
                },
                events,
            )
        }
    }
}

fn state_writable(paths: &Paths) -> bool {
    let dir = paths.state_dir();
    if fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".probe-{}", std::process::id()));
    match fs::write(&probe, b"") {
        Ok(()) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow!("no parent"))?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("state"),
        std::process::id()
    ));
    fs::write(&tmp, bytes)?;
    fs::File::open(&tmp)?.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Record `version` as accepted and keep this signed policy as last-known-good. The version
/// file is written last: a crash in between leaves an LKG at least as new as the floor.
fn persist(paths: &Paths, bytes: &[u8], sig: &str, version: u64) -> Result<()> {
    fs::create_dir_all(paths.state_dir())?;
    write_atomic(&paths.lkg(), bytes)?;
    write_atomic(&paths.lkg_sig(), sig.as_bytes())?;
    let current = read_highest(paths).unwrap_or(0);
    write_atomic(
        &paths.version_file(),
        version.max(current).to_string().as_bytes(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _tmp: tempfile::TempDir,
        paths: Paths,
        key: SigningKey,
    }

    fn managed() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::at(tmp.path());
        let key = generate_org_key();
        fs::write(paths.org_pub(), encode_public_key(&key.verifying_key())).unwrap();
        Fixture {
            _tmp: tmp,
            paths,
            key,
        }
    }

    fn policy_bytes(version: u64, phi: &str) -> Vec<u8> {
        format!(
            r#"{{"version":{version},"org":"keemakr","phi_mode":"{phi}","fail_mode":"closed","tools":{{"claude_code":{{"baa":false}}}}}}"#
        )
        .into_bytes()
    }

    fn install(f: &Fixture, version: u64, phi: &str) {
        let bytes = policy_bytes(version, phi);
        fs::write(f.paths.policy(), &bytes).unwrap();
        fs::write(f.paths.policy_sig(), sign(&bytes, &f.key).unwrap()).unwrap();
    }

    #[test]
    fn unmanaged_is_personal_and_emits_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (eff, events) = evaluate(&Paths::at(tmp.path()));
        assert_eq!(eff.source, Source::Personal);
        assert_eq!(eff.policy, Policy::personal());
        assert!(events.is_empty());
    }

    #[test]
    fn managed_without_policy_is_strict() {
        let f = managed();
        let (eff, events) = evaluate(&f.paths);
        assert_eq!(eff.source, Source::ManagedDefault);
        assert_eq!(eff.policy.phi_mode, PhiMode::Block);
        assert_eq!(eff.policy.fail_mode, FailMode::Closed);
        assert_eq!(
            events,
            vec![Event::PolicyMissing {
                fallback_version: None
            }]
        );
    }

    #[test]
    fn valid_policy_applies_and_becomes_lkg() {
        let f = managed();
        install(&f, 3, "seal");
        let (eff, events) = evaluate(&f.paths);
        assert_eq!(eff.source, Source::Signed { version: 3 });
        assert_eq!(events, vec![Event::PolicyApplied { version: 3 }]);
        assert_eq!(read_highest(&f.paths), Some(3));
        // Second evaluation: same version, nothing new.
        let (_, events) = evaluate(&f.paths);
        assert!(events.is_empty());
    }

    #[test]
    fn flipped_byte_keeps_last_known_good() {
        let f = managed();
        install(&f, 3, "seal");
        evaluate(&f.paths);
        let mut bytes = fs::read(f.paths.policy()).unwrap();
        let i = bytes.iter().position(|b| *b == b's').unwrap();
        bytes[i] = b'S';
        fs::write(f.paths.policy(), bytes).unwrap();
        let (eff, events) = evaluate(&f.paths);
        assert_eq!(eff.source, Source::LastKnownGood { version: 3 });
        assert_eq!(eff.policy.phi_mode, PhiMode::Seal);
        assert_eq!(
            events,
            vec![Event::PolicyInvalid {
                reason: PolicyInvalidReason::SignatureMismatch,
                fallback_version: Some(3)
            }]
        );
    }

    #[test]
    fn older_validly_signed_policy_is_rejected() {
        let f = managed();
        install(&f, 5, "seal");
        evaluate(&f.paths);
        install(&f, 4, "off");
        let (eff, events) = evaluate(&f.paths);
        assert_eq!(eff.source, Source::LastKnownGood { version: 5 });
        assert_eq!(eff.policy.phi_mode, PhiMode::Seal);
        assert_eq!(
            events,
            vec![Event::PolicyRollbackRejected {
                offered: 4,
                in_force: 5
            }]
        );
        assert_eq!(read_highest(&f.paths), Some(5));
    }

    #[test]
    fn rollback_is_rejected_even_if_lkg_was_deleted() {
        let f = managed();
        install(&f, 5, "seal");
        evaluate(&f.paths);
        fs::remove_file(f.paths.lkg()).unwrap();
        install(&f, 4, "off");
        let (eff, events) = evaluate(&f.paths);
        assert_eq!(eff.source, Source::ManagedDefault);
        assert!(events.contains(&Event::PolicyRollbackRejected {
            offered: 4,
            in_force: 5
        }));
    }

    #[test]
    fn policy_signed_by_another_key_is_refused() {
        let f = managed();
        let other = generate_org_key();
        let bytes = policy_bytes(9, "off");
        fs::write(f.paths.policy(), &bytes).unwrap();
        fs::write(f.paths.policy_sig(), sign(&bytes, &other).unwrap()).unwrap();
        let (eff, events) = evaluate(&f.paths);
        assert_eq!(eff.source, Source::ManagedDefault);
        assert!(matches!(
            events[0],
            Event::PolicyInvalid {
                reason: PolicyInvalidReason::SignatureMismatch,
                ..
            }
        ));
    }

    #[test]
    fn missing_signature_and_unknown_fields() {
        let f = managed();
        fs::write(f.paths.policy(), policy_bytes(1, "seal")).unwrap();
        let (_, events) = evaluate(&f.paths);
        assert!(matches!(
            events[0],
            Event::PolicyInvalid {
                reason: PolicyInvalidReason::SignatureMissing,
                ..
            }
        ));
        // A newer schema field is ignored, not fatal.
        let bytes = br#"{"version":2,"org":"k","phi_mode":"seal","fail_mode":"open","future_field":{"x":1}}"#;
        fs::write(f.paths.policy(), bytes).unwrap();
        fs::write(f.paths.policy_sig(), sign(bytes, &f.key).unwrap()).unwrap();
        let (eff, _) = evaluate(&f.paths);
        assert_eq!(eff.source, Source::Signed { version: 2 });
    }

    #[test]
    fn kill_switch_parses() {
        let p = parse(
            br#"{"version":1,"org":"k","enabled":false,"phi_mode":"off","fail_mode":"open"}"#,
        )
        .unwrap();
        assert!(!p.enabled);
    }

    #[test]
    fn signing_refuses_a_policy_that_does_not_parse() {
        let key = generate_org_key();
        assert!(sign(b"{\"version\":1}", &key).is_err());
    }
}
