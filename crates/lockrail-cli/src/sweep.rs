//! `lockrail sweep`: find secrets and PHI that already reached AI-tool transcripts before Lockrail
//! was installed (competitors/A-agent-secret-tools.md idea 5, from numbat).
//!
//! Read-only. The report carries file paths, line numbers, detector kinds and keyed handles, never
//! values, so it can go to a security team. A handle can be matched against `lockrail secret`
//! entries on this machine (same `fp_key`) to tell which stored secret leaked, and when.
//!
//! Transcript locations (each checked on this machine, 2026-11-08):
//! - Claude Code: `~/.claude/projects/<project>/<session>.jsonl`
//! - Codex: `~/.codex/sessions/<yyyy>/<mm>/<dd>/*.jsonl`

use lockrail_engine::handle::{keyed_fingerprint, secret_handle};
use lockrail_engine::phi::{PhiOptions, scan_phi};
use lockrail_engine::seal::{ScanOptions, scan_text};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};

/// One line holding at least one finding.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Hit {
    pub line: usize,
    pub secrets: Vec<String>,
    pub phi: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct FileReport {
    pub path: PathBuf,
    pub lines_scanned: usize,
    pub hits: Vec<Hit>,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub files_with_findings: Vec<FileReport>,
    pub secrets_by_kind: BTreeMap<String, usize>,
    pub phi_by_kind: BTreeMap<String, usize>,
    /// Files that could not be read (permissions, not UTF-8 lines are skipped per line).
    pub unreadable: Vec<PathBuf>,
}

/// Lines longer than this are scanned in their first part only: transcript lines carry whole
/// tool outputs, and one pathological line must not stall the sweep. Reported per file.
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Every `*.jsonl` under `root`, depth-first, without following symlinks.
pub fn transcript_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() && path.extension().is_some_and(|e| e == "jsonl") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn collect_strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        serde_json::Value::Object(m) => m.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

/// Scan one file line by line.
pub fn sweep_file(path: &Path, fp_key: &[u8; 32], phi: bool, report: &mut Report) {
    let Ok(file) = std::fs::File::open(path) else {
        report.unreadable.push(path.to_path_buf());
        return;
    };
    report.files_scanned += 1;
    let reader = std::io::BufReader::new(file);
    let mut file_report = FileReport {
        path: path.to_path_buf(),
        lines_scanned: 0,
        hits: Vec::new(),
    };
    for (index, line) in reader.split(b'\n').enumerate() {
        let Ok(bytes) = line else { break };
        report.bytes_scanned += bytes.len() as u64 + 1;
        file_report.lines_scanned += 1;
        let cut = &bytes[..bytes.len().min(MAX_LINE_BYTES)];
        // Transcript lines are JSON: scan the decoded strings, so escaped text (`\r` in an HL7
        // message, `\"` in code) reads as it did in the session (hostile review: 6 identifiers
        // in plain text, 0 inside a transcript line). A line that is not JSON is scanned raw.
        let text = match serde_json::from_slice::<serde_json::Value>(cut) {
            Ok(v) => {
                let mut strings = Vec::new();
                collect_strings(&v, &mut strings);
                std::borrow::Cow::Owned(strings.join("\n"))
            }
            Err(_) => String::from_utf8_lossy(cut),
        };
        let options = ScanOptions {
            aggressive: false,
            protection_mode: true,
        };
        let secrets: Vec<String> = scan_text(&text, options)
            .into_iter()
            .filter(|f| f.should_seal)
            .map(|f| {
                *report
                    .secrets_by_kind
                    .entry(f.kind.to_string())
                    .or_default() += 1;
                secret_handle(&f.kind, &keyed_fingerprint(fp_key, &f.value))
            })
            .collect();
        let mut phi_counts = BTreeMap::new();
        if phi {
            for f in scan_phi(&text, PhiOptions::default()) {
                *phi_counts.entry(f.kind.to_string()).or_default() += 1;
                *report.phi_by_kind.entry(f.kind.to_string()).or_default() += 1;
            }
        }
        if !secrets.is_empty() || !phi_counts.is_empty() {
            file_report.hits.push(Hit {
                line: index + 1,
                secrets,
                phi: phi_counts,
            });
        }
    }
    if !file_report.hits.is_empty() {
        report.files_with_findings.push(file_report);
    }
}

pub fn sweep(roots: &[PathBuf], fp_key: &[u8; 32], phi: bool) -> Report {
    let mut report = Report::default();
    for root in roots {
        let files = if root.is_file() {
            vec![root.clone()]
        } else {
            transcript_files(root)
        };
        for file in files {
            sweep_file(&file, fp_key, phi, &mut report);
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> String {
        ["ghp_", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0Ed9Cb8"].concat()
    }

    #[test]
    fn finds_leaks_in_transcripts_and_reports_no_values() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("projects").join("-Users-x-app");
        std::fs::create_dir_all(&project).unwrap();
        let session = project.join("abc.jsonl");
        let lines = [
            serde_json::json!({"type":"user","message":{"content":"hello"}}).to_string(),
            serde_json::json!({"type":"user","message":{"content":format!("deploy with {}", secret())}}).to_string(),
            serde_json::json!({"type":"tool_result","content":"Patient MRN: 00482913 DOB: 03/14/1962"}).to_string(),
        ];
        std::fs::write(&session, lines.join("\n")).unwrap();
        std::fs::write(project.join("notes.txt"), secret()).unwrap();
        let report = sweep(&[dir.path().to_path_buf()], &[7u8; 32], true);
        assert_eq!(report.files_scanned, 1, "only .jsonl transcripts");
        assert_eq!(report.files_with_findings.len(), 1);
        let hits = &report.files_with_findings[0].hits;
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].line, 2);
        assert!(hits[0].secrets[0].starts_with("lockrail://secret/github-token/h_"));
        assert_eq!(hits[1].phi.get("mrn"), Some(&1));
        assert_eq!(hits[1].phi.get("dob"), Some(&1));
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(&secret()) && !json.contains("00482913"));
        // The handle matches what Lockrail would produce for the same value on this machine.
        assert_eq!(
            hits[0].secrets[0],
            secret_handle("github-token", &keyed_fingerprint(&[7u8; 32], &secret()))
        );
    }

    /// Hostile review: structured PHI inside a JSON transcript line was missed because the
    /// HL7 segment separators were JSON-escaped.
    #[test]
    fn structured_phi_inside_a_transcript_line_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let hl7 = "MSH|^~\\&|EPIC|HOSP|||202411081200||ADT^A01|1|P|2.5\rPID|1||00482913^^^HOSP^MR||ROE^JANE||19620314|F\r";
        std::fs::write(
            dir.path().join("t.jsonl"),
            serde_json::json!({"type":"tool_result","content": hl7}).to_string(),
        )
        .unwrap();
        let report = sweep(&[dir.path().to_path_buf()], &[7u8; 32], true);
        assert_eq!(
            report.phi_by_kind.get("mrn"),
            Some(&1),
            "{:?}",
            report.phi_by_kind
        );
        assert_eq!(report.phi_by_kind.get("dob"), Some(&1));
    }
}
