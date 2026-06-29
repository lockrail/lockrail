use anyhow::Result;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use time::OffsetDateTime;

pub const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

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
        let rows = self.read_all()?;
        let previous_hash = rows
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let mut event = AuditEvent {
            sequence: rows.len() as u64 + 1,
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
            .append(true)
            .open(&self.path)?;
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
        let rows = self.read_all()?;
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
