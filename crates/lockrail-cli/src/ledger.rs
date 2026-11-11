//! The credential exposure ledger: for each credential Lockrail has seen, how often it was
//! stopped before reaching a model, by which tool, when, and whether it was already sitting in
//! AI transcripts before Lockrail (from `lockrail sweep`).
//!
//! Built from the audit log only. Credentials are identified by keyed handles
//! (`lockrail://secret/<kind>/h_<HMAC>`), so the ledger never holds a value, and a handle confirms
//! nothing without this machine's `fp_key`. This is the per-employee view an admin console
//! aggregates (counts and handles, never values).

use lockrail_audit::AuditEvent;
use lockrail_audit::events::{Event, Record};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Most handles one audit event records; the counters stay exact beyond it.
pub const MAX_HANDLES_PER_EVENT: usize = 64;

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Credential {
    pub handle: String,
    pub kind: String,
    /// Times a hook or the sealer replaced it before a model saw it.
    pub stopped: usize,
    /// Prompts refused because they carried it.
    pub prompts_blocked: usize,
    /// Found by `lockrail sweep` in a transcript: it reached a model before Lockrail.
    pub found_in_transcripts: bool,
    pub by_tool: BTreeMap<String, usize>,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Default, Serialize)]
pub struct Ledger {
    pub credentials: Vec<Credential>,
    pub total_stops: usize,
    pub prompts_blocked: usize,
    pub tool_calls_guarded: usize,
    pub guard_denials: BTreeMap<String, usize>,
}

fn kind_of(handle: &str) -> String {
    handle
        .strip_prefix("lockrail://secret/")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("unknown")
        .to_string()
}

fn handles(meta: &Value) -> Vec<&str> {
    meta.get("handles")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// One credential is one keyed fingerprint, whatever kind label a handle carried (a value first
/// found by a detector and later matched as a vault value is still one credential). The most
/// specific kind seen wins over `vault-value`.
fn touch<'a>(
    by_fp: &'a mut BTreeMap<String, Credential>,
    handle: &str,
    at: i64,
) -> &'a mut Credential {
    let fp = handle.rsplit('/').next().unwrap_or(handle).to_string();
    let kind = kind_of(handle);
    let c = by_fp.entry(fp).or_insert_with(|| Credential {
        handle: handle.to_string(),
        kind: kind.clone(),
        first_seen: at,
        last_seen: at,
        ..Credential::default()
    });
    if c.kind == "vault-value" && kind != "vault-value" {
        c.kind = kind;
        c.handle = handle.to_string();
    }
    c.first_seen = c.first_seen.min(at);
    c.last_seen = c.last_seen.max(at);
    c
}

/// Build the ledger from the audit log (hooks, sweep) and the keyed event chain (the sealer,
/// which records what it sealed on the wire, labelled by model host).
pub fn build(events: &[AuditEvent], sealer: &[Record]) -> Ledger {
    let mut by_handle: BTreeMap<String, Credential> = BTreeMap::new();
    let mut ledger = Ledger::default();
    for e in events {
        let meta = &e.metadata;
        match e.action.as_str() {
            "hook.post_tool_use.sealed" => {
                let tool = meta
                    .get("tool")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                ledger.total_stops += meta.get("secrets").and_then(Value::as_u64).unwrap_or(0)
                    as usize
                    + meta
                        .get("known_values")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as usize;
                for h in handles(meta) {
                    let c = touch(&mut by_handle, h, e.timestamp);
                    c.stopped += 1;
                    *c.by_tool.entry(tool.clone()).or_default() += 1;
                }
            }
            "hook.prompt.blocked" => {
                ledger.prompts_blocked += 1;
                for h in handles(meta) {
                    touch(&mut by_handle, h, e.timestamp).prompts_blocked += 1;
                }
            }
            "hook.pre_tool_use.denied" => {
                ledger.tool_calls_guarded += 1;
                let rule = meta
                    .get("rule")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                *ledger.guard_denials.entry(rule).or_default() += 1;
            }
            "hook.pre_tool_use.resolved" => ledger.tool_calls_guarded += 1,
            "sweep.completed" => {
                for h in handles(meta) {
                    touch(&mut by_handle, h, e.timestamp).found_in_transcripts = true;
                }
            }
            _ => {}
        }
    }
    for r in sealer {
        if let Event::SealerRequest {
            host,
            secrets_sealed,
            handles,
            ..
        } = &r.event
        {
            ledger.total_stops += *secrets_sealed as usize;
            let label = format!(
                "sealer: {}",
                serde_json::to_value(host)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| "model".into())
            );
            for h in handles {
                let c = touch(&mut by_handle, h, r.ts);
                c.stopped += 1;
                *c.by_tool.entry(label.clone()).or_default() += 1;
            }
        }
    }
    let mut credentials: Vec<Credential> = by_handle.into_values().collect();
    // Already-leaked credentials first (rotate these), then the most frequently stopped.
    credentials.sort_by(|a, b| {
        b.found_in_transcripts
            .cmp(&a.found_in_transcripts)
            .then(b.stopped.cmp(&a.stopped))
            .then(a.handle.cmp(&b.handle))
    });
    ledger.credentials = credentials;
    ledger
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64, ts: i64, action: &str, meta: Value) -> AuditEvent {
        AuditEvent {
            sequence: seq,
            timestamp: ts,
            actor: "local".into(),
            action: action.into(),
            resource: String::new(),
            metadata: meta,
            previous_hash: String::new(),
            event_hash: String::new(),
        }
    }

    #[test]
    fn ledger_counts_stops_tools_blocks_and_prior_exposure() {
        let gh = "lockrail://secret/github-token/h_00000000000000000000000000000001";
        let aws = "lockrail://secret/aws-access-key-id/h_00000000000000000000000000000002";
        let events = vec![
            event(
                1,
                100,
                "hook.post_tool_use.sealed",
                serde_json::json!({"tool":"Bash","secrets":1,"known_values":0,"handles":[gh]}),
            ),
            event(
                2,
                200,
                "hook.post_tool_use.sealed",
                serde_json::json!({"tool":"Read","secrets":2,"known_values":0,"handles":[gh, aws]}),
            ),
            event(
                3,
                300,
                "hook.prompt.blocked",
                serde_json::json!({"rule":"lockrail_secret_in_prompt","handles":[aws]}),
            ),
            event(
                4,
                400,
                "hook.pre_tool_use.denied",
                serde_json::json!({"rule":"lockrail_guard_path"}),
            ),
            event(
                5,
                500,
                "sweep.completed",
                serde_json::json!({"handles":[aws]}),
            ),
        ];
        let l = build(&events, &[]);
        assert_eq!(l.total_stops, 3);
        assert_eq!(l.prompts_blocked, 1);
        assert_eq!(l.tool_calls_guarded, 1);
        assert_eq!(l.guard_denials.get("lockrail_guard_path"), Some(&1));
        // The leaked credential sorts first.
        assert_eq!(l.credentials[0].handle, aws);
        assert!(l.credentials[0].found_in_transcripts);
        assert_eq!(l.credentials[0].prompts_blocked, 1);
        assert_eq!(
            (l.credentials[0].first_seen, l.credentials[0].last_seen),
            (200, 500)
        );
        let g = &l.credentials[1];
        assert_eq!((g.kind.as_str(), g.stopped), ("github-token", 2));
        assert_eq!(g.by_tool.get("Bash"), Some(&1));
        assert_eq!(g.by_tool.get("Read"), Some(&1));
    }

    #[test]
    fn one_credential_under_two_labels_is_one_row() {
        let fp = "h_0000000000000000000000000000000a";
        let events = vec![
            event(
                1,
                1,
                "hook.post_tool_use.sealed",
                serde_json::json!({"tool":"Bash","secrets":1,"handles":[format!("lockrail://secret/vault-value/{fp}")]}),
            ),
            event(
                2,
                2,
                "hook.post_tool_use.sealed",
                serde_json::json!({"tool":"Read","secrets":1,"handles":[format!("lockrail://secret/openai-key/{fp}")]}),
            ),
        ];
        let l = build(&events, &[]);
        assert_eq!(l.credentials.len(), 1);
        assert_eq!(l.credentials[0].kind, "openai-key");
        assert_eq!(l.credentials[0].stopped, 2);
    }

    #[test]
    fn wire_sealed_credentials_join_the_same_row() {
        let h = "lockrail://secret/github-token/h_0000000000000000000000000000000b";
        let hook = vec![event(
            1,
            10,
            "hook.post_tool_use.sealed",
            serde_json::json!({"tool":"Bash","secrets":1,"handles":[h]}),
        )];
        let wire = vec![Record {
            v: 2,
            seq: 0,
            ts: 20,
            event: Event::SealerRequest {
                host: lockrail_audit::events::SealerHost::Anthropic,
                secrets_sealed: 1,
                phi_withheld: 0,
                phi_sealed: 0,
                images_withheld: 0,
                handles: vec![h.to_string()],
            },
            prev_mac_hex: String::new(),
            mac_hex: String::new(),
        }];
        let l = build(&hook, &wire);
        assert_eq!(l.credentials.len(), 1);
        let c = &l.credentials[0];
        assert_eq!(c.stopped, 2);
        assert_eq!(c.by_tool.get("sealer: anthropic"), Some(&1));
        assert_eq!((c.first_seen, c.last_seen), (10, 20));
        assert_eq!(l.total_stops, 2);
    }
}
