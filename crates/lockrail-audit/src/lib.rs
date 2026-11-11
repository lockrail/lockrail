pub mod events;
pub mod evidence;

use anyhow::Result;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use time::OffsetDateTime;

pub const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Lines that failed to parse: 1-based line number and the raw text.
pub type CorruptLines = Vec<(usize, String)>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub timestamp: i64,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub metadata: serde_json::Value,
    pub previous_hash: String,
    pub event_hash: String,
}

#[derive(Clone, Debug)]
pub struct AuditLog {
    pub path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn read_all(&self) -> Result<Vec<AuditEvent>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let text = fs::read_to_string(&self.path)?;
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| Ok(serde_json::from_str(l)?))
            .collect()
    }

    /// Read every line, separating parseable events from corrupt lines (1-based line number and
    /// raw text). Used by `append` and `verify` so one bad line can never wedge the log (D9).
    pub fn read_lenient(&self) -> Result<(Vec<AuditEvent>, CorruptLines)> {
        if !self.path.exists() {
            return Ok((vec![], vec![]));
        }
        let bytes = fs::read(&self.path)?;
        let text = String::from_utf8_lossy(&bytes);
        let mut events = Vec::new();
        let mut corrupt = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEvent>(line) {
                Ok(event) => events.push(event),
                Err(_) => corrupt.push((idx + 1, line.to_string())),
            }
        }
        Ok((events, corrupt))
    }

    pub fn quarantine_path(&self) -> PathBuf {
        self.path.with_extension("quarantine.jsonl")
    }

    fn write_quarantine(&self, corrupt: &[(usize, String)]) -> Result<()> {
        let body: String = corrupt
            .iter()
            .map(|(line, raw)| serde_json::json!({"line": line, "raw": raw}).to_string() + "\n")
            .collect();
        let path = self.quarantine_path();
        fs::write(&path, body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn event_hash(event: &AuditEvent) -> Result<String> {
        let value = serde_json::json!({
            "sequence": event.sequence,
            "timestamp": event.timestamp,
            "actor": event.actor,
            "action": event.action,
            "resource": event.resource,
            "metadata": event.metadata,
            "previous_hash": event.previous_hash,
        });
        let mut h = Sha256::new();
        h.update(serde_json::to_vec(&value)?);
        Ok(format!("sha256:{}", hex::encode(h.finalize())))
    }

    pub fn append(
        &self,
        action: impl Into<String>,
        resource: impl Into<String>,
        metadata: serde_json::Value,
    ) -> Result<AuditEvent> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        let lock_path = self.path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.lock_exclusive()?;
        // A corrupt line (crash mid-write, disk error, tampering) must not make every later append
        // fail (D9). Continue the chain from the last valid event, copy the bad lines to the
        // quarantine file, and leave them in place so `verify` still reports them.
        let (rows, corrupt) = self.read_lenient()?;
        if !corrupt.is_empty() {
            self.write_quarantine(&corrupt)?;
        }
        let previous_hash = rows
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let mut event = AuditEvent {
            sequence: rows.last().map(|e| e.sequence).unwrap_or(0) + 1,
            timestamp: OffsetDateTime::now_utc().unix_timestamp(),
            actor: "local-user".into(),
            action: action.into(),
            resource: resource.into(),
            metadata,
            previous_hash,
            event_hash: String::new(),
        };
        event.event_hash = Self::event_hash(&event)?;
        let mut f = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        // If a previous writer died mid-line, start on a fresh line so this event is not glued
        // onto the partial one and lost.
        let len = f.metadata()?.len();
        if len > 0 {
            let mut last = [0u8; 1];
            f.seek(SeekFrom::Start(len - 1))?;
            f.read_exact(&mut last)?;
            if last[0] != b'\n' {
                f.write_all(b"\n")?;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        writeln!(f, "{}", serde_json::to_string(&event)?)?;
        f.sync_all()?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(event)
    }

    pub fn verify(&self) -> Result<(bool, String)> {
        let (rows, corrupt) = self.read_lenient()?;
        if let Some((line, _)) = corrupt.first() {
            return Ok((
                false,
                format!(
                    "corrupt line {line} ({} corrupt line(s), copied to {})",
                    corrupt.len(),
                    self.quarantine_path().display()
                ),
            ));
        }
        let mut prev = GENESIS_HASH.to_string();
        for (idx, e) in rows.iter().enumerate() {
            let seq = idx as u64 + 1;
            if e.sequence != seq {
                return Ok((false, format!("sequence mismatch at row {}", seq)));
            }
            if e.previous_hash != prev {
                return Ok((false, format!("previous_hash mismatch at row {}", seq)));
            }
            let expected = Self::event_hash(e)?;
            if e.event_hash != expected {
                return Ok((false, format!("event_hash mismatch at row {}", seq)));
            }
            prev = e.event_hash.clone();
        }
        Ok((true, format!("ok: {} events", rows.len())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// D9: one corrupt line used to make every later append fail, wedging hooks and the relay.
    #[test]
    fn append_survives_corrupt_line_and_verify_reports_it() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let log = AuditLog::new(&p);
        log.append("one", "r", serde_json::json!({})).unwrap();
        // Simulate a crash mid-write: a partial JSON line with no trailing newline.
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"sequence\":2,\"timest").unwrap();
        drop(f);

        let event = log.append("two", "r", serde_json::json!({})).unwrap();
        assert_eq!(event.sequence, 2);
        let (events, corrupt) = log.read_lenient().unwrap();
        assert_eq!(
            events.len(),
            2,
            "the new event must not be glued onto the partial line"
        );
        assert_eq!(corrupt.len(), 1);
        assert!(log.quarantine_path().exists());
        let (ok, msg) = log.verify().unwrap();
        assert!(!ok);
        assert!(msg.contains("corrupt line 2"), "{msg}");
    }

    #[test]
    fn detects_tamper() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("audit.jsonl");
        let log = AuditLog::new(&p);
        log.append("one", "r", serde_json::json!({})).unwrap();
        log.append("two", "r", serde_json::json!({})).unwrap();
        assert!(log.verify().unwrap().0);
        let mut rows = log.read_all().unwrap();
        rows[0].action = "evil".into();
        fs::write(
            &p,
            rows.into_iter()
                .map(|e| serde_json::to_string(&e).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();
        assert!(!log.verify().unwrap().0);
    }

    #[test]
    fn detects_deleted_and_reordered_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        log.append("one", "r", serde_json::json!({})).unwrap();
        log.append("two", "r", serde_json::json!({})).unwrap();
        log.append("three", "r", serde_json::json!({})).unwrap();

        let mut rows = log.read_all().unwrap();
        rows.remove(1);
        fs::write(
            &path,
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();
        assert!(!log.verify().unwrap().0);

        let log = AuditLog::new(&path);
        log.append("one", "r", serde_json::json!({})).unwrap();
        log.append("two", "r", serde_json::json!({})).unwrap();
        log.append("three", "r", serde_json::json!({})).unwrap();
        let mut rows = log.read_all().unwrap();
        rows.swap(0, 1);
        fs::write(
            &path,
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();
        assert!(!log.verify().unwrap().0);
    }
}
