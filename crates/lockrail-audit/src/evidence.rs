//! Evidence (PLAN.md section 3.6, Phase 7A/7C; M6, M7, D9).
//!
//! - **Anchors**: the device key signs `(through_seq, head_mac_hex, ts)` for the v2 event chain.
//!   Every anchor is shipped in the next digest, so tampering is detectable back to the last
//!   shipped anchor. Events after it are the *unanchored tail*, reported with its length, never
//!   hidden ("any tampering" is not claimed).
//! - **Digests**: counters per event kind plus the anchors since the previous digest. No values,
//!   paths or prompts: the event schema is closed. Keys are never integer-like (T8: `JSON.parse`
//!   would reorder them and break KeeTrust hash read-back).
//! - **Verify**: the local chain against shipped anchors.

use crate::events::{EventLog, Record};
use anyhow::{Result, anyhow};
use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Anchor {
    pub v: u8,
    pub through_seq: u64,
    pub head_mac_hex: String,
    pub ts: i64,
    /// Device verifying key, base64 (named to avoid secret-scanner triggers).
    pub device_pub_b64: String,
    pub sig_b64: String,
}

fn anchor_message(through_seq: u64, head_mac_hex: &str, ts: i64) -> Vec<u8> {
    format!("lockrail-anchor-v1\n{through_seq}\n{head_mac_hex}\n{ts}").into_bytes()
}

impl Anchor {
    pub fn sign(device: &SigningKey, through_seq: u64, head_mac_hex: &str, ts: i64) -> Self {
        let sig = device.sign(&anchor_message(through_seq, head_mac_hex, ts));
        Self {
            v: 1,
            through_seq,
            head_mac_hex: head_mac_hex.to_string(),
            ts,
            device_pub_b64: Base64::encode_string(device.verifying_key().as_bytes()),
            sig_b64: Base64::encode_string(&sig.to_bytes()),
        }
    }

    /// Signature check against `expected` (the device key enrolled for this machine).
    pub fn verify(&self, expected: &VerifyingKey) -> bool {
        let Ok(sig) = Base64::decode_vec(&self.sig_b64) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&sig) else {
            return false;
        };
        Base64::encode_string(expected.as_bytes()) == self.device_pub_b64
            && expected
                .verify(
                    &anchor_message(self.through_seq, &self.head_mac_hex, self.ts),
                    &sig,
                )
                .is_ok()
    }
}

/// Anchor the current chain head (verifying the chain first). `None` for an empty log.
pub fn anchor_now(
    log: &EventLog,
    audit_key: &[u8; 32],
    device: &SigningKey,
    ts: i64,
) -> Result<Option<Anchor>> {
    let report = log.verify(audit_key)?;
    if !report.ok() {
        return Err(anyhow!(
            "event chain does not verify; refusing to anchor it: {:?}",
            report.problems
        ));
    }
    let Some(last) = log.read_all()?.pop() else {
        return Ok(None);
    };
    Ok(Some(Anchor::sign(device, last.seq, &last.mac_hex, ts)))
}

pub fn append_anchor(path: &Path, anchor: &Anchor) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}", serde_json::to_string(anchor)?)?;
    f.sync_all()?;
    Ok(())
}

pub fn read_anchors(path: &Path) -> Result<Vec<Anchor>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    fs::read_to_string(path)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| Ok(serde_json::from_str(l)?))
        .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest {
    pub v: u8,
    pub device_pub_b64: String,
    pub from_seq: u64,
    pub through_seq: u64,
    pub period_start: i64,
    pub period_end: i64,
    /// Event kind -> count. Kinds are snake_case names, never integer-like.
    pub counts: BTreeMap<String, u64>,
    /// Summed sealer counters for the period.
    pub sealer: BTreeMap<String, u64>,
    pub anchors: Vec<Anchor>,
}

/// Build a digest over records with `seq >= from_seq`, carrying `anchors`.
pub fn build_digest(
    records: &[Record],
    from_seq: u64,
    anchors: Vec<Anchor>,
    device: &VerifyingKey,
) -> Digest {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut sealer: BTreeMap<String, u64> = BTreeMap::new();
    let mut through = from_seq.saturating_sub(1);
    let (mut start, mut end) = (i64::MAX, i64::MIN);
    for r in records.iter().filter(|r| r.seq >= from_seq) {
        let value = serde_json::to_value(&r.event).unwrap_or_default();
        let kind = value
            .get("event")
            .and_then(|k| k.as_str())
            .unwrap_or("unknown")
            .to_string();
        *counts.entry(kind).or_default() += 1;
        if let Some(obj) = value.as_object() {
            for (k, v) in obj {
                if let Some(n) = v.as_u64()
                    && k != "seq"
                {
                    *sealer.entry(k.clone()).or_default() += n;
                }
            }
        }
        through = through.max(r.seq);
        start = start.min(r.ts);
        end = end.max(r.ts);
    }
    if start == i64::MAX {
        start = 0;
        end = 0;
    }
    Digest {
        v: 2,
        device_pub_b64: Base64::encode_string(device.as_bytes()),
        from_seq,
        through_seq: through,
        period_start: start,
        period_end: end,
        counts,
        sealer,
        anchors,
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum VerifyProblem {
    /// A shipped anchor covers events that are no longer in the local log.
    TruncatedBeforeAnchor { through_seq: u64 },
    /// The local chain at an anchored sequence does not match the shipped head.
    ChainMismatch { through_seq: u64 },
    /// A shipped anchor's signature does not verify against the device key.
    AnchorSignatureInvalid { through_seq: u64 },
    /// The local chain itself does not verify (gap, unlinked, MAC, corrupt line).
    LocalChain { detail: String },
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VerifyReport {
    pub ok: bool,
    pub records: u64,
    pub anchors_checked: usize,
    /// Events after the newest shipped anchor: tampering there is not detectable yet.
    pub unanchored_tail: u64,
    pub problems: Vec<VerifyProblem>,
}

pub fn verify_against_anchors(
    log: &EventLog,
    audit_key: &[u8; 32],
    device: &VerifyingKey,
    shipped: &[Anchor],
) -> Result<VerifyReport> {
    let chain = log.verify(audit_key)?;
    let records = log.read_all()?;
    let by_seq: BTreeMap<u64, &Record> = records.iter().map(|r| (r.seq, r)).collect();
    let mut problems: Vec<VerifyProblem> = chain
        .problems
        .iter()
        .map(|p| VerifyProblem::LocalChain {
            detail: serde_json::to_string(p).unwrap_or_default(),
        })
        .collect();
    let mut newest_anchor: Option<u64> = None;
    for anchor in shipped {
        if !anchor.verify(device) {
            problems.push(VerifyProblem::AnchorSignatureInvalid {
                through_seq: anchor.through_seq,
            });
            continue;
        }
        newest_anchor = newest_anchor.max(Some(anchor.through_seq));
        match by_seq.get(&anchor.through_seq) {
            None => problems.push(VerifyProblem::TruncatedBeforeAnchor {
                through_seq: anchor.through_seq,
            }),
            Some(r) if r.mac_hex != anchor.head_mac_hex => {
                problems.push(VerifyProblem::ChainMismatch {
                    through_seq: anchor.through_seq,
                })
            }
            Some(_) => {}
        }
    }
    let last_seq = records.last().map(|r| r.seq);
    let unanchored_tail = match (last_seq, newest_anchor) {
        (Some(last), Some(anchored)) if last > anchored => last - anchored,
        (Some(_), Some(_)) => 0,
        (Some(_), None) => records.len() as u64,
        (None, _) => 0,
    };
    Ok(VerifyReport {
        ok: problems.is_empty(),
        records: records.len() as u64,
        anchors_checked: shipped.len(),
        unanchored_tail,
        problems,
    })
}

/// KeeTrust `POST /api/v1/evidence/push` (PLAN.md section 0.4; T3, T7, T8).
///
/// The request carries exactly the `PushInput` keys (`.strict()`: an extra key is a 400). The
/// payload KeeTrust hashes is built server-side as
/// `{kind:"external_push", title, description ?? null, source, pushed_by, controls, data}` with
/// zod-trimmed strings and de-duplicated controls; [`KeeTrustPush::expected_sha256`] rebuilds the
/// same string in the same key order so the hash read back from `GET /api/v1/evidence` can be
/// checked (KeeTrust returns hashes, never payloads).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeeTrustPush {
    pub controls: Vec<String>,
    pub title: String,
    pub description: Option<String>,
    pub source: String,
    /// Must be a JSON object whose keys are never integer-like (T8).
    pub data: serde_json::Value,
    pub valid_days: u32,
}

impl KeeTrustPush {
    pub fn from_digest(digest: &Digest, controls: &[String]) -> Self {
        Self {
            controls: controls.to_vec(),
            title: format!(
                "Lockrail digest seq {}-{}",
                digest.from_seq, digest.through_seq
            ),
            description: Some(
                "Signed counters from the Lockrail event chain; anchors cover the period.".into(),
            ),
            source: "lockrail".into(),
            data: serde_json::to_value(digest).expect("digest serialises"),
            valid_days: 90,
        }
    }

    /// The exact request body (`PushInput` keys only).
    pub fn request_json(&self) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        body.insert("controls".into(), serde_json::json!(self.controls));
        body.insert("title".into(), serde_json::json!(self.title));
        if let Some(d) = &self.description {
            body.insert("description".into(), serde_json::json!(d));
        }
        body.insert("source".into(), serde_json::json!(self.source));
        body.insert("data".into(), self.data.clone());
        body.insert("valid_days".into(), serde_json::json!(self.valid_days));
        serde_json::Value::Object(body)
    }

    /// `sha256(JSON.stringify(payload))` as KeeTrust computes it for a token named `token_name`.
    pub fn expected_sha256(&self, token_name: &str) -> String {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(self.payload_string(token_name).as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The payload string in JavaScript's key order. Strings are trimmed as zod does; controls
    /// keep first-seen order (`[...new Set(...)]`); `data` is passed through as parsed (its
    /// keys are already in serialisation order and never integer-like).
    pub fn payload_string(&self, token_name: &str) -> String {
        let js = |v: &str| serde_json::to_string(v.trim()).expect("string");
        let mut seen = Vec::new();
        for c in &self.controls {
            let c = c.trim().to_string();
            if !seen.contains(&c) {
                seen.push(c);
            }
        }
        let description = match &self.description {
            Some(d) => js(d),
            None => "null".into(),
        };
        format!(
            r#"{{"kind":"external_push","title":{},"description":{},"source":{},"pushed_by":{},"controls":{},"data":{}}}"#,
            js(&self.title),
            description,
            js(&self.source),
            serde_json::to_string(token_name).expect("string"),
            serde_json::to_string(&seen).expect("controls"),
            serde_json::to_string(&self.data).expect("data"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Event;

    const KEY: [u8; 32] = [3u8; 32];

    fn setup(n: u64) -> (tempfile::TempDir, EventLog, SigningKey) {
        let tmp = tempfile::tempdir().unwrap();
        let log = EventLog::new(tmp.path().join("events"));
        for v in 0..n {
            log.append(&KEY, Event::PolicyApplied { version: v })
                .unwrap();
        }
        (tmp, log, SigningKey::from_bytes(&[9u8; 32]))
    }

    fn rewrite_without_last(log: &EventLog, drop: usize) {
        let dir = log.dir();
        let mut files: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        let path = files.pop().unwrap();
        let lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        let keep = &lines[..lines.len() - drop];
        fs::write(&path, keep.join("\n") + "\n").unwrap();
    }

    #[test]
    fn deleting_anchored_events_is_detected() {
        let (_tmp, log, device) = setup(10);
        let anchor = anchor_now(&log, &KEY, &device, 1).unwrap().unwrap();
        rewrite_without_last(&log, 5);
        let r = verify_against_anchors(&log, &KEY, &device.verifying_key(), &[anchor]).unwrap();
        assert!(!r.ok);
        assert!(
            r.problems
                .iter()
                .any(|p| matches!(p, VerifyProblem::TruncatedBeforeAnchor { .. })),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn unanchored_tail_is_reported_not_hidden() {
        let (_tmp, log, device) = setup(10);
        let anchor = anchor_now(&log, &KEY, &device, 1).unwrap().unwrap();
        for v in 0..5 {
            log.append(&KEY, Event::PolicyApplied { version: 100 + v })
                .unwrap();
        }
        let r = verify_against_anchors(
            &log,
            &KEY,
            &device.verifying_key(),
            std::slice::from_ref(&anchor),
        )
        .unwrap();
        assert!(r.ok);
        assert_eq!(r.unanchored_tail, 5);
        // Deleting those 5 cannot be detected; the report says so by showing the tail shrink.
        rewrite_without_last(&log, 5);
        let r = verify_against_anchors(&log, &KEY, &device.verifying_key(), &[anchor]).unwrap();
        assert!(r.ok && r.unanchored_tail == 0);
    }

    #[test]
    fn rewritten_history_with_the_audit_key_still_breaks_the_anchor() {
        // An attacker holding audit_key can rebuild a valid local chain, but not the shipped anchor.
        let (_tmp, log, device) = setup(4);
        let anchor = anchor_now(&log, &KEY, &device, 1).unwrap().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();
        let forged = EventLog::new(tmp2.path().join("events"));
        for v in 0..4 {
            forged
                .append(&KEY, Event::PolicyApplied { version: v + 50 })
                .unwrap();
        }
        let r = verify_against_anchors(&forged, &KEY, &device.verifying_key(), &[anchor]).unwrap();
        assert!(
            r.problems
                .iter()
                .any(|p| matches!(p, VerifyProblem::ChainMismatch { .. }))
        );
    }

    #[test]
    fn forged_anchor_signature_is_rejected() {
        let (_tmp, log, device) = setup(3);
        let mut anchor = anchor_now(&log, &KEY, &device, 1).unwrap().unwrap();
        anchor.through_seq = 1;
        let r = verify_against_anchors(&log, &KEY, &device.verifying_key(), &[anchor]).unwrap();
        assert!(
            r.problems
                .iter()
                .any(|p| matches!(p, VerifyProblem::AnchorSignatureInvalid { .. }))
        );
    }

    #[test]
    fn digest_has_counts_and_no_integer_like_keys() {
        let (_tmp, log, device) = setup(3);
        log.append(
            &KEY,
            Event::SealerRequest {
                host: crate::events::SealerHost::Anthropic,
                secrets_sealed: 2,
                phi_withheld: 1,
                phi_sealed: 0,
                images_withheld: 0,
                handles: vec![
                    "lockrail://secret/github-token/h_00000000000000000000000000000001".into(),
                ],
            },
        )
        .unwrap();
        let anchor = anchor_now(&log, &KEY, &device, 7).unwrap().unwrap();
        let d = build_digest(
            &log.read_all().unwrap(),
            0,
            vec![anchor],
            &device.verifying_key(),
        );
        assert_eq!(d.counts["policy_applied"], 3);
        assert_eq!(d.sealer["secrets_sealed"], 2);
        let text = serde_json::to_string(&d).unwrap();
        // The digest ships off the device: counters only, never credential handles.
        assert!(!text.contains("lockrail://"), "{text}");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        fn no_int_keys(v: &serde_json::Value) {
            if let Some(o) = v.as_object() {
                for (k, v) in o {
                    assert!(k.parse::<u64>().is_err(), "integer-like key {k}");
                    no_int_keys(v);
                }
            } else if let Some(a) = v.as_array() {
                a.iter().for_each(no_int_keys);
            }
        }
        no_int_keys(&v);
    }

    /// T8: the Rust payload hash equals Node's `sha256(JSON.stringify(payload))` for the payload
    /// KeeTrust builds. Skipped when `node` is not installed.
    #[test]
    fn keetrust_payload_hash_matches_node() {
        if std::process::Command::new("node")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("node not installed; skipping");
            return;
        }
        let (_tmp, log, device) = setup(3);
        let anchor = anchor_now(&log, &KEY, &device, 7).unwrap().unwrap();
        let d = build_digest(
            &log.read_all().unwrap(),
            0,
            vec![anchor],
            &device.verifying_key(),
        );
        let mut push =
            KeeTrustPush::from_digest(&d, &["CC6.1 ".into(), "CC7.2".into(), "CC6.1".into()]);
        push.title = "  Lockrail digest \u{e9} \"quoted\" \n line  ".into();
        let body = serde_json::to_string(&push.request_json()).unwrap();
        let script = r#"
            const crypto = require("node:crypto");
            const input = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
            const t = (s) => s.trim();
            const payload = {
              kind: "external_push",
              title: t(input.title),
              description: input.description === undefined ? null : t(input.description),
              source: t(input.source),
              pushed_by: "lockrail-laptop",
              controls: [...new Set(input.controls.map(t))],
              data: input.data,
            };
            process.stdout.write(crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex"));
        "#;
        let mut child = std::process::Command::new("node")
            .args(["-e", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let node_hash = String::from_utf8(out.stdout).unwrap();
        assert_eq!(push.expected_sha256("lockrail-laptop"), node_hash);
        // Strict keys only.
        let keys: Vec<String> = push
            .request_json()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for k in &keys {
            assert!(
                [
                    "controls",
                    "title",
                    "description",
                    "source",
                    "data",
                    "valid_days"
                ]
                .contains(&k.as_str()),
                "{k}"
            );
        }
    }
}
