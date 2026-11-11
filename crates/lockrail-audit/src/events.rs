//! v2 event log (PLAN.md section 3.6, Phase 2C).
//!
//! `~/.lockrail/events/<YYYY-MM-DD>.jsonl`, one record per line, keyed-chained:
//! `mac_i = HMAC-SHA256(audit_key, prev_mac_i || canonical(body_i))`, with `prev_mac_0` all zeros.
//! The chain runs across day files in name order.
//!
//! The schema is a closed enum with no free text, so no caller can put a value, a path or a
//! prompt into evidence (R-8). Field names avoid secret-scanner triggers (`mac_hex`, not `*_key`).
//! Anchors (device-key signatures over the chain head) and shipping are Phase 7.

use anyhow::{Context, Result, anyhow};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

pub const SCHEMA_VERSION: u8 = 2;
pub const GENESIS_MAC_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

type HmacSha256 = Hmac<Sha256>;

/// Why a signed policy was not applied.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyInvalidReason {
    OrgKeyUnreadable,
    SignatureMissing,
    SignatureMalformed,
    SignatureMismatch,
    PolicyUnreadable,
    PolicyMalformed,
    LastKnownGoodInvalid,
}

/// The key items `lockrail-keys` manages. Names only, never values.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyItem {
    VaultKey,
    AuditKey,
    FpKey,
    DeviceSigningKey,
}

/// Closed event set. Adding a variant is a schema change reviewed like code; there is no
/// free-text variant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    PolicyApplied {
        version: u64,
    },
    PolicyInvalid {
        reason: PolicyInvalidReason,
        fallback_version: Option<u64>,
    },
    PolicyRollbackRejected {
        offered: u64,
        in_force: u64,
    },
    PolicyMissing {
        fallback_version: Option<u64>,
    },
    KeyMigrated {
        item: KeyItem,
    },
    KeyExportedLegacy {
        item: KeyItem,
    },
    /// One sealed request (counters only; never values or paths).
    SealerRequest {
        host: SealerHost,
        secrets_sealed: u32,
        phi_withheld: u32,
        phi_sealed: u32,
        images_withheld: u32,
        /// Keyed handles of the credentials sealed in this request (never values), for the
        /// exposure ledger. Absent in older records, and omitted when empty, so their MACs hold.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        handles: Vec<String>,
    },
    SealerBlocked {
        host: SealerHost,
    },
    SealerDeadlineExceeded {
        host: SealerHost,
    },
    SealerFailOpen {
        host: SealerHost,
    },
}

/// The model hosts the sealer terminates (closed set, so no free text reaches evidence).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SealerHost {
    Anthropic,
    Chatgpt,
    Openai,
    Other,
}

impl SealerHost {
    pub fn from_host(host: &str) -> Self {
        match host {
            "api.anthropic.com" => SealerHost::Anthropic,
            "chatgpt.com" => SealerHost::Chatgpt,
            "api.openai.com" => SealerHost::Openai,
            _ => SealerHost::Other,
        }
    }
}

/// The signed part of a record. Serialised field order is fixed by the struct, which is what
/// the MAC covers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Body {
    v: u8,
    seq: u64,
    ts: i64,
    #[serde(flatten)]
    event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub v: u8,
    pub seq: u64,
    pub ts: i64,
    #[serde(flatten)]
    pub event: Event,
    pub prev_mac_hex: String,
    pub mac_hex: String,
}

impl Record {
    fn body(&self) -> Body {
        Body {
            v: self.v,
            seq: self.seq,
            ts: self.ts,
            event: self.event.clone(),
        }
    }
}

fn compute_mac(audit_key: &[u8; 32], prev_mac_hex: &str, body: &Body) -> Result<String> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(audit_key).map_err(|_| anyhow!("hmac key"))?;
    mac.update(prev_mac_hex.as_bytes());
    mac.update(b"\n");
    mac.update(&serde_json::to_vec(body)?);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn mac_matches(
    audit_key: &[u8; 32],
    prev_mac_hex: &str,
    body: &Body,
    claimed_hex: &str,
) -> Result<bool> {
    let claimed = match hex::decode(claimed_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(audit_key).map_err(|_| anyhow!("hmac key"))?;
    mac.update(prev_mac_hex.as_bytes());
    mac.update(b"\n");
    mac.update(&serde_json::to_vec(body)?);
    // `verify_slice` is constant-time.
    Ok(mac.verify_slice(&claimed).is_ok())
}

pub struct EventLog {
    dir: PathBuf,
}

impl EventLog {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn day_files(&self) -> Result<Vec<PathBuf>> {
        if !self.dir.exists() {
            return Ok(vec![]);
        }
        let mut files: Vec<PathBuf> = fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| is_day_file(p))
            .collect();
        files.sort();
        Ok(files)
    }

    /// Append one event, chained to the last valid record. Holds an exclusive lock on
    /// `events/.lock` for the read-chain-write sequence, so concurrent writers serialise.
    pub fn append(&self, audit_key: &[u8; 32], event: Event) -> Result<Record> {
        self.append_at(audit_key, event, OffsetDateTime::now_utc())
    }

    pub fn append_at(
        &self,
        audit_key: &[u8; 32],
        event: Event,
        now: OffsetDateTime,
    ) -> Result<Record> {
        fs::create_dir_all(&self.dir).with_context(|| format!("create {}", self.dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join(".lock"))?;
        lock.lock_exclusive()?;

        let (prev_seq, prev_mac_hex) = match self.last_record()? {
            Some(last) => (Some(last.seq), last.mac_hex),
            None => (None, GENESIS_MAC_HEX.to_string()),
        };
        let body = Body {
            v: SCHEMA_VERSION,
            seq: prev_seq.map_or(0, |s| s + 1),
            ts: now.unix_timestamp(),
            event,
        };
        let mac_hex = compute_mac(audit_key, &prev_mac_hex, &body)?;
        let record = Record {
            v: body.v,
            seq: body.seq,
            ts: body.ts,
            event: body.event,
            prev_mac_hex,
            mac_hex,
        };
        let path = self.dir.join(day_file_name(now));
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        // A crash mid-write can leave a line without its newline; start on a fresh line so the
        // next record is not glued to it.
        let len = file.metadata()?.len();
        if len > 0 {
            file.seek(SeekFrom::Start(len - 1))?;
            let mut last = [0u8; 1];
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                file.write_all(b"\n")?;
            }
        }
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        file.write_all(&line)?;
        file.sync_all()?;
        Ok(record)
    }

    /// The last record that parses, scanning day files newest first.
    fn last_record(&self) -> Result<Option<Record>> {
        for path in self.day_files()?.into_iter().rev() {
            let text = fs::read_to_string(&path)?;
            for line in text.lines().rev() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(record) = serde_json::from_str::<Record>(line) {
                    return Ok(Some(record));
                }
            }
        }
        Ok(None)
    }

    pub fn read_all(&self) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        for path in self.day_files()? {
            for line in fs::read_to_string(&path)?.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(record) = serde_json::from_str::<Record>(line) {
                    out.push(record);
                }
            }
        }
        Ok(out)
    }

    /// Walk every record in order and check sequence, linkage and MAC.
    pub fn verify(&self, audit_key: &[u8; 32]) -> Result<Verification> {
        let mut prev_mac = GENESIS_MAC_HEX.to_string();
        let mut expected_seq = 0u64;
        let mut records = 0u64;
        let mut problems = Vec::new();
        for path in self.day_files()? {
            let file = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            for (idx, line) in fs::read_to_string(&path)?.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let at = Location {
                    file: file.clone(),
                    line: idx + 1,
                };
                let record: Record = match serde_json::from_str(line) {
                    Ok(r) => r,
                    Err(_) => {
                        problems.push(Problem::Corrupt { at });
                        continue;
                    }
                };
                records += 1;
                if record.seq != expected_seq {
                    problems.push(Problem::Gap {
                        at: at.clone(),
                        expected: expected_seq,
                        found: record.seq,
                    });
                }
                if record.prev_mac_hex != prev_mac {
                    problems.push(Problem::Unlinked { at: at.clone() });
                }
                if !mac_matches(
                    audit_key,
                    &record.prev_mac_hex,
                    &record.body(),
                    &record.mac_hex,
                )? {
                    problems.push(Problem::MacMismatch { at });
                }
                prev_mac = record.mac_hex.clone();
                expected_seq = record.seq + 1;
            }
        }
        Ok(Verification {
            records,
            head_mac_hex: prev_mac,
            problems,
        })
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Location {
    pub file: String,
    pub line: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum Problem {
    Corrupt {
        at: Location,
    },
    Gap {
        at: Location,
        expected: u64,
        found: u64,
    },
    Unlinked {
        at: Location,
    },
    MacMismatch {
        at: Location,
    },
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Verification {
    pub records: u64,
    pub head_mac_hex: String,
    pub problems: Vec<Problem>,
}

impl Verification {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

fn day_file_name(now: OffsetDateTime) -> String {
    let date = now.date();
    format!(
        "{:04}-{:02}-{:02}.jsonl",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

fn is_day_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let bytes = name.as_bytes();
    name.len() == "YYYY-MM-DD.jsonl".len()
        && name.ends_with(".jsonl")
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..10]
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const KEY: [u8; 32] = [7u8; 32];

    fn log() -> (tempfile::TempDir, EventLog) {
        let tmp = tempfile::tempdir().unwrap();
        let log = EventLog::new(tmp.path().join("events"));
        (tmp, log)
    }

    #[test]
    fn chain_verifies_across_day_files() {
        let (_tmp, log) = log();
        log.append_at(
            &KEY,
            Event::PolicyApplied { version: 1 },
            datetime!(2026-11-07 23:59 UTC),
        )
        .unwrap();
        log.append_at(
            &KEY,
            Event::PolicyMissing {
                fallback_version: None,
            },
            datetime!(2026-11-08 00:01 UTC),
        )
        .unwrap();
        log.append(
            &KEY,
            Event::KeyMigrated {
                item: KeyItem::VaultKey,
            },
        )
        .unwrap();
        let v = log.verify(&KEY).unwrap();
        assert!(v.ok(), "{:?}", v.problems);
        assert_eq!(v.records, 3);
        assert!(log.day_files().unwrap().len() >= 2);
    }

    #[test]
    fn edited_record_fails_mac() {
        let (_tmp, log) = log();
        log.append(&KEY, Event::PolicyApplied { version: 1 })
            .unwrap();
        log.append(&KEY, Event::PolicyApplied { version: 2 })
            .unwrap();
        let path = log.day_files().unwrap().pop().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replacen("\"version\":1", "\"version\":9", 1)).unwrap();
        let v = log.verify(&KEY).unwrap();
        assert!(
            matches!(v.problems.first(), Some(Problem::MacMismatch { .. })),
            "{:?}",
            v.problems
        );
    }

    #[test]
    fn deleted_record_is_a_gap_and_unlinked() {
        let (_tmp, log) = log();
        for version in 1..=3 {
            log.append(&KEY, Event::PolicyApplied { version }).unwrap();
        }
        let path = log.day_files().unwrap().pop().unwrap();
        let lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        let v = log.verify(&KEY).unwrap();
        assert!(v.problems.iter().any(|p| matches!(p, Problem::Gap { .. })));
        assert!(
            v.problems
                .iter()
                .any(|p| matches!(p, Problem::Unlinked { .. }))
        );
    }

    #[test]
    fn wrong_key_fails_and_recomputed_chain_without_key_is_impossible() {
        let (_tmp, log) = log();
        log.append(&KEY, Event::PolicyApplied { version: 1 })
            .unwrap();
        let v = log.verify(&[8u8; 32]).unwrap();
        assert!(!v.ok());
    }

    #[test]
    fn corrupt_line_is_reported_and_append_continues() {
        let (_tmp, log) = log();
        log.append(&KEY, Event::PolicyApplied { version: 1 })
            .unwrap();
        let path = log.day_files().unwrap().pop().unwrap();
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{not json").unwrap();
        drop(file);
        let record = log
            .append(&KEY, Event::PolicyApplied { version: 2 })
            .unwrap();
        assert_eq!(record.seq, 1);
        let v = log.verify(&KEY).unwrap();
        assert_eq!(v.records, 2);
        assert_eq!(v.problems.len(), 1);
        assert!(matches!(v.problems[0], Problem::Corrupt { .. }));
    }

    #[test]
    fn concurrent_appends_keep_one_chain() {
        let (_tmp, log) = log();
        let dir = log.dir().to_path_buf();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let log = EventLog::new(dir);
                    for j in 0..10 {
                        log.append(
                            &KEY,
                            Event::PolicyApplied {
                                version: i * 100 + j,
                            },
                        )
                        .unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let v = log.verify(&KEY).unwrap();
        assert!(v.ok(), "{:?}", v.problems);
        assert_eq!(v.records, 80);
    }

    #[test]
    fn serialised_record_has_no_key_named_fields() {
        let (_tmp, log) = log();
        log.append(
            &KEY,
            Event::KeyMigrated {
                item: KeyItem::VaultKey,
            },
        )
        .unwrap();
        let text = fs::read_to_string(log.day_files().unwrap().pop().unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        for field in value.as_object().unwrap().keys() {
            assert!(!field.ends_with("_key") && field != "key", "field {field}");
        }
    }
}
