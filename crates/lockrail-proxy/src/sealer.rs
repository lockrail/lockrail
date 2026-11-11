//! Sealer core (PLAN.md section 3.1, Phase 5a/5b): decide what happens to one request on a
//! model host, without any networking, so every rule is unit-testable.
//!
//! - Path classes: inference paths are rewritten; an exact, versioned pass-list is forwarded
//!   unchanged (its bodies are still scanned for the detection event); any other path is scanned
//!   (decoded JSON leaves) and blocked (403) on a finding, never forwarded (m20). Paths with dot
//!   segments, `//`, `;`, backslashes or encoded `.`/`/` are refused (400).
//! - Bodies are decoded by `Content-Encoding` (gzip, deflate, br, zstd; at most 64 MiB inflated).
//!   An undecodable body goes to fail mode. A rewritten body is sent uncompressed.
//! - JSON is rewritten **in place**: a tokenizer maps every value to its byte span, and only the
//!   spans that change are spliced. Untouched bytes (signed `thinking` blocks included) are
//!   forwarded byte-identical (M1). Duplicate keys, or an edit that cannot be placed, go to fail
//!   mode.
//! - Coverage is by default, not by list (review C1, C2, C5): **secrets** are sealed in every
//!   string leaf of the body except exact structural positions (a typed block's `type`, `id`,
//!   `signature`, base64 `source.data`, the top-level `model`) and signed thinking blocks. **PHI**
//!   is withheld only in client-originated subtrees. Images and documents are withheld wherever
//!   they appear when PHI mode is on.
//! - Leaves are memoised as soon as they are scanned (M20); the deadline bounds scan work (M3).

use lockrail_engine::handle::{keyed_fingerprint, phi_handle, secret_handle};
use lockrail_engine::phi::{PhiOptions, scan_phi};
use lockrail_engine::seal::{ScanOptions, scan_text};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hosts whose TLS the sealer terminates. Every other CONNECT is a blind tunnel.
/// Model API hosts the sealer opens (every other CONNECT is a blind tunnel). Beyond Anthropic and
/// OpenAI: OpenAI-compatible providers (xAI/Grok, OpenRouter, Groq, Mistral, DeepSeek, Together,
/// Fireworks) and Google's Gemini endpoints (API key and Code Assist, used by Gemini CLI).
pub const SEALER_MITM_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "chatgpt.com",
    "api.openai.com",
    "api.x.ai",
    "openrouter.ai",
    "api.groq.com",
    "api.mistral.ai",
    "api.deepseek.com",
    "api.together.xyz",
    "api.fireworks.ai",
    "generativelanguage.googleapis.com",
    "cloudcode-pa.googleapis.com",
];

/// Versioned pass-list (m15): exact paths or `prefix/` segment matches for auth, token refresh,
/// profile, policy and flags. Forwarded unchanged (a credential in a sign-in body is never sealed),
/// but scanned so a finding produces a detection event. Verified against live clients in GATE 6
/// (A-1). v2: exact matching; `/backend-api/wham/` removed (Codex Cloud tasks carry prompts).
pub const PASS_LIST_VERSION: u32 = 3;
const PASS_LIST_EXACT: &[&str] = &[
    "/v1/oauth/token",
    "/api/hello",
    "/backend-api/me",
    "/api/claude_cli_profile",
];
const PASS_LIST_SEGMENT_PREFIXES: &[&str] = &[
    "/v1/oauth/",
    "/oauth/",
    "/api/auth/",
    "/api/event_logging/",
    "/backend-api/accounts/",
    "/backend-api/settings/",
];

pub const MAX_INFLATED_BYTES: usize = 64 * 1024 * 1024;
/// Upper bound on string leaves in one body; beyond it the request goes to fail mode.
pub const MAX_LEAVES: usize = 1_000_000;
/// Largest single string value scanned (N5).
pub const MAX_LEAF_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathClass {
    Inference(Api),
    PassList,
    Other,
    /// Not in normal form (dot segments, `//`, `;`, backslash, encoded `.`/`/`): refused.
    Abnormal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Api {
    AnthropicMessages,
    Responses,
    /// OpenAI-compatible `/chat/completions` (any base path).
    ChatCompletions,
    /// Gemini `:generateContent` / `:streamGenerateContent`.
    Gemini,
}

pub fn classify(path_and_query: &str) -> PathClass {
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    let lower = path.to_ascii_lowercase();
    if !path.starts_with('/')
        || path.contains("//")
        || path.contains(';')
        || path.contains('\\')
        || path.split('/').any(|seg| seg == "." || seg == "..")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return PathClass::Abnormal;
    }
    match path {
        "/v1/messages" | "/v1/messages/count_tokens" => {
            PathClass::Inference(Api::AnthropicMessages)
        }
        "/backend-api/codex/responses"
        | "/backend-api/codex/responses/compact"
        | "/v1/responses"
        | "/v1/responses/compact" => PathClass::Inference(Api::Responses),
        _ if path.ends_with("/chat/completions") => PathClass::Inference(Api::ChatCompletions),
        _ if path.ends_with(":generateContent") || path.ends_with(":streamGenerateContent") => {
            PathClass::Inference(Api::Gemini)
        }
        _ if PASS_LIST_EXACT.contains(&path) => PathClass::PassList,
        _ if PASS_LIST_SEGMENT_PREFIXES
            .iter()
            .any(|p| path.starts_with(p) && path.len() > p.len()) =>
        {
            PathClass::PassList
        }
        _ => PathClass::Other,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhiMode {
    Off,
    Warn,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailMode {
    Open,
    Closed,
}

#[derive(Clone)]
pub struct SealerConfig {
    pub enabled: bool,
    pub fp_key: [u8; 32],
    pub phi_mode: PhiMode,
    /// A BAA covers this tool's provider (R-10): PHI is sealed as handles instead of withheld.
    pub baa: bool,
    /// `phi_block_scope: request`: refuse the whole request (400) instead of withholding spans.
    pub phi_block_request: bool,
    pub fail_mode: FailMode,
    pub deadline: Duration,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Forward the original bytes and headers unchanged.
    Unchanged,
    /// Forward this uncompressed body (drop `Content-Encoding`, recompute `Content-Length`).
    Rewritten(Vec<u8>),
    /// Answer the client directly.
    Respond {
        status: u16,
        body: String,
        retry: bool,
    },
}

/// Counters for evidence (no values, ever).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub secrets_sealed: usize,
    pub phi_withheld: usize,
    pub phi_sealed: usize,
    pub images_withheld: usize,
    pub leaves_scanned: usize,
    pub memo_hits: usize,
    pub deadline_exceeded: bool,
    pub fail_open: bool,
    pub blocked: bool,
    /// A pass-listed body carried a finding (forwarded unchanged; event only).
    pub passlist_findings: bool,
    /// Keyed handles newly put into this request (distinct, at most 64), for the ledger.
    pub handles: Vec<String>,
}

/// Most handles one request's report keeps; the counters stay exact beyond it.
const MAX_REPORT_HANDLES: usize = 64;

/// Handles in `new` that were not already in `old` (conversation history carries earlier
/// handles, which must not be counted again), added to `out` without duplicates.
fn note_new_handles(old: &str, new: &str, out: &mut Vec<String>) {
    const PREFIX: &str = "lockrail://secret/";
    let mut offset = 0;
    while out.len() < MAX_REPORT_HANDLES
        && let Some(pos) = new[offset..].find(PREFIX)
    {
        let start = offset + pos;
        let end = new[start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '_' | '-')))
            .map_or(new.len(), |e| start + e);
        let handle = &new[start..end];
        if !old.contains(handle) && !out.iter().any(|h| h == handle) {
            out.push(handle.to_string());
        }
        offset = end.max(start + 1);
    }
}

// ---------------------------------------------------------------------------------------------
// Memo: a true LRU with per-entry cost (review C4)
// ---------------------------------------------------------------------------------------------

pub struct Memo {
    inner: Mutex<MemoInner>,
    budget: usize,
}

struct MemoInner {
    /// key -> (value, cost, generation of its newest position in `order`)
    map: HashMap<[u8; 32], (Option<String>, LeafCounts, usize, u64)>,
    /// Recency queue; entries whose generation is stale are skipped on eviction.
    order: VecDeque<([u8; 32], u64)>,
    bytes: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LeafCounts {
    secrets: usize,
    phi_withheld: usize,
    phi_sealed: usize,
}

impl Memo {
    pub fn new(budget: usize) -> Self {
        Self {
            inner: Mutex::new(MemoInner {
                map: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
                generation: 0,
            }),
            budget,
        }
    }

    fn get(&self, key: &[u8; 32]) -> Option<(Option<String>, LeafCounts)> {
        let mut inner = self.inner.lock().expect("memo");
        inner.generation += 1;
        let generation = inner.generation;
        let hit = inner.map.get_mut(key).map(|entry| {
            entry.3 = generation;
            (entry.0.clone(), entry.1)
        });
        if hit.is_some() {
            inner.order.push_back((*key, generation));
            compact_order(&mut inner);
        }
        hit
    }

    fn put(&self, key: [u8; 32], value: (Option<String>, LeafCounts), text_len: usize) {
        // The cost covers the key text and any stored replacement.
        let cost = 96 + text_len + value.0.as_ref().map_or(0, String::len);
        // N5: an entry this large would evict everything and never stay; do not cache it.
        if cost > self.budget / 8 {
            return;
        }
        let mut inner = self.inner.lock().expect("memo");
        inner.generation += 1;
        let generation = inner.generation;
        if let Some(old) = inner.map.insert(key, (value.0, value.1, cost, generation)) {
            inner.bytes = inner.bytes.saturating_sub(old.2);
        }
        inner.bytes += cost;
        inner.order.push_back((key, generation));
        while inner.bytes > self.budget {
            let Some((old_key, old_gen)) = inner.order.pop_front() else {
                break;
            };
            let current = inner.map.get(&old_key).map(|e| e.3);
            if current == Some(old_gen)
                && let Some(evicted) = inner.map.remove(&old_key)
            {
                inner.bytes = inner.bytes.saturating_sub(evicted.2);
            }
        }
        compact_order(&mut inner);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("memo").map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bytes(&self) -> usize {
        self.inner.lock().expect("memo").bytes
    }
}

/// Keep the recency queue bounded: drop stale positions when it grows past 2x the map.
fn compact_order(inner: &mut MemoInner) {
    if inner.order.len() > 2 * inner.map.len() + 1024 {
        let map = &inner.map;
        inner
            .order
            .retain(|(k, g)| map.get(k).is_some_and(|e| e.3 == *g));
    }
}

// ---------------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------------

/// Decode a body by its `Content-Encoding` (comma-separated, applied in order). Capped at
/// [`MAX_INFLATED_BYTES`]: a decompression bomb is an error, not an allocation.
pub fn decode_body(content_encoding: Option<&str>, body: &[u8]) -> Result<Vec<u8>, String> {
    let Some(encodings) = content_encoding else {
        return Ok(body.to_vec());
    };
    let mut data = body.to_vec();
    for enc in encodings
        .split(',')
        .map(|e| e.trim().to_ascii_lowercase())
        .rev()
    {
        data = match enc.as_str() {
            "" | "identity" => data,
            "gzip" | "x-gzip" => read_capped(flate2::read::GzDecoder::new(&data[..]))?,
            "deflate" => read_capped(flate2::read::ZlibDecoder::new(&data[..]))?,
            "br" => read_capped(brotli_decompressor::Decompressor::new(&data[..], 4096))?,
            "zstd" => {
                let decoder = ruzstd::decoding::StreamingDecoder::new(&data[..])
                    .map_err(|e| format!("zstd: {e}"))?;
                read_capped(decoder)?
            }
            other => return Err(format!("unsupported content-encoding {other}")),
        };
    }
    Ok(data)
}

fn read_capped(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let read = reader
        .take(MAX_INFLATED_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("decode: {e}"))?;
    if read > MAX_INFLATED_BYTES {
        return Err("decompressed body exceeds 64 MiB".into());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// JSON span tokenizer
// ---------------------------------------------------------------------------------------------

/// Byte spans of every JSON value, keyed by JSON Pointer. Assumes valid JSON (checked first by
/// `serde_json`); strings are spanned including their quotes. `Err` on a duplicate key in any
/// object: serde keeps the last one, but the first one's bytes would still be forwarded (C8).
fn value_spans(src: &[u8]) -> Result<HashMap<String, (usize, usize)>, &'static str> {
    let mut spans = HashMap::new();
    let mut i = 0;
    let mut duplicate = false;
    parse_value(src, &mut i, &mut String::new(), &mut spans, &mut duplicate);
    if duplicate {
        return Err("duplicate JSON key");
    }
    Ok(spans)
}

fn ws(src: &[u8], i: &mut usize) {
    while *i < src.len() && src[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

fn parse_value(
    src: &[u8],
    i: &mut usize,
    ptr: &mut String,
    spans: &mut HashMap<String, (usize, usize)>,
    duplicate: &mut bool,
) {
    ws(src, i);
    let start = *i;
    match src.get(*i) {
        Some(b'{') => {
            *i += 1;
            let mut seen = std::collections::HashSet::new();
            loop {
                ws(src, i);
                if src.get(*i) == Some(&b'}') {
                    *i += 1;
                    break;
                }
                let key_start = *i;
                skip_string(src, i);
                let key: String = serde_json::from_slice(&src[key_start..*i]).unwrap_or_default();
                if !seen.insert(key.clone()) {
                    *duplicate = true;
                }
                ws(src, i);
                *i += 1; // ':'
                let len = ptr.len();
                ptr.push('/');
                ptr.push_str(&key.replace('~', "~0").replace('/', "~1"));
                parse_value(src, i, ptr, spans, duplicate);
                ptr.truncate(len);
                ws(src, i);
                match src.get(*i) {
                    Some(b',') => *i += 1,
                    _ => {
                        *i += 1; // '}'
                        break;
                    }
                }
            }
        }
        Some(b'[') => {
            *i += 1;
            let mut index = 0usize;
            loop {
                ws(src, i);
                if src.get(*i) == Some(&b']') {
                    *i += 1;
                    break;
                }
                let len = ptr.len();
                ptr.push('/');
                ptr.push_str(&index.to_string());
                parse_value(src, i, ptr, spans, duplicate);
                ptr.truncate(len);
                index += 1;
                ws(src, i);
                match src.get(*i) {
                    Some(b',') => *i += 1,
                    _ => {
                        *i += 1; // ']'
                        break;
                    }
                }
            }
        }
        Some(b'"') => skip_string(src, i),
        Some(_) => {
            while *i < src.len()
                && !matches!(src[*i], b',' | b'}' | b']')
                && !src[*i].is_ascii_whitespace()
            {
                *i += 1;
            }
        }
        None => return,
    }
    spans.insert(ptr.clone(), (start, *i));
}

fn skip_string(src: &[u8], i: &mut usize) {
    *i += 1; // opening quote
    while *i < src.len() {
        match src[*i] {
            b'\\' => *i += 2,
            b'"' => {
                *i += 1;
                return;
            }
            _ => *i += 1,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Planning: coverage by default (review C1, C2, C5)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scope {
    secrets: bool,
    phi: bool,
}

enum Edit {
    Leaf {
        ptr: String,
        text: String,
        scope: Scope,
    },
    ReplaceWith {
        ptr: String,
        json: String,
    },
}

/// Content types that are withheld whole when PHI mode is on (R-12).
fn is_media(obj: &serde_json::Map<String, Value>) -> bool {
    matches!(
        obj.get("type").and_then(Value::as_str),
        Some(
            "image"
                | "document"
                | "input_image"
                | "input_file"
                | "file"
                | "container_upload"
                | "computer_screenshot"
                | "image_url"
                | "input_audio"
        )
    ) || ["inlineData", "inline_data", "fileData", "file_data"]
        .iter()
        .any(|k| obj.contains_key(*k))
}

/// Replacement text block in the dialect of the containing API.
fn withheld_block(api: Api, item_level: bool) -> String {
    const TEXT: &str = "[image withheld by Lockrail: PHI mode]";
    match (api, item_level) {
        (Api::AnthropicMessages, _) => format!(r#"{{"type":"text","text":"{TEXT}"}}"#),
        (Api::Responses, false) => format!(r#"{{"type":"input_text","text":"{TEXT}"}}"#),
        (Api::Responses, true) => {
            format!(
                r#"{{"type":"message","role":"user","content":[{{"type":"input_text","text":"{TEXT}"}}]}}"#
            )
        }
        (Api::ChatCompletions, false) => format!(r#"{{"type":"text","text":"{TEXT}"}}"#),
        (Api::ChatCompletions, true) => format!(r#"{{"role":"user","content":"{TEXT}"}}"#),
        (Api::Gemini, false) => format!(r#"{{"text":"{TEXT}"}}"#),
        (Api::Gemini, true) => format!(r#"{{"role":"user","parts":[{{"text":"{TEXT}"}}]}}"#),
    }
}

/// The leaf's key names an image or file payload.
fn is_media_position(ptr: &str) -> bool {
    matches!(
        ptr.rsplit('/').next(),
        Some("url" | "image_url" | "file_data")
    )
}

/// `data:<type>/<subtype>[;param]*;base64,<base64>` with nothing else: no whitespace, only the
/// base64 alphabet after the comma, at most two `=` of padding.
fn is_strict_data_url(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("data:") else {
        return false;
    };
    let Some((header, payload)) = rest.split_once(";base64,") else {
        return false;
    };
    // Only binary media is opaque: a `text/*` or JSON data URL is text an agent can read, and
    // its base64 payload is scanned like any other (hostile review: a secret hid in
    // `data:text/plain;base64,...` under a `url` key).
    let media = header.split(';').next().unwrap_or("").to_ascii_lowercase();
    let binary = ["image/", "audio/", "video/"]
        .iter()
        .any(|p| media.starts_with(p))
        || matches!(
            media.as_str(),
            "application/pdf" | "application/octet-stream" | "application/zip"
        );
    if !binary {
        return false;
    }
    let header_ok = header.split(';').enumerate().all(|(i, part)| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'+' | b'-' | b'='))
            && (i > 0 || part.contains('/'))
    });
    let body = payload.trim_end_matches('=');
    header_ok
        && payload.len() - body.len() <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
}

struct Planner<'a> {
    api: Api,
    cfg: &'a SealerConfig,
    edits: Vec<Edit>,
    leaves: usize,
    key_secret: bool,
}

/// Block and item types of the Anthropic Messages and OpenAI Responses APIs whose structural
/// fields (`type`, `id`, `signature`, ...) are API metadata, not user data.
fn known_block_type(kind: &str) -> bool {
    matches!(
        kind,
        "text"
            | "image"
            | "document"
            | "tool_use"
            | "tool_result"
            | "thinking"
            | "redacted_thinking"
            | "server_tool_use"
            | "web_search_tool_result"
            | "web_fetch_tool_result"
            | "mcp_tool_use"
            | "mcp_tool_result"
            | "container_upload"
            | "search_result"
            | "base64"
            | "url"
            | "file"
            | "message"
            | "input_text"
            | "input_image"
            | "input_file"
            | "output_text"
            | "refusal"
            | "function_call"
            | "function_call_output"
            | "custom_tool_call"
            | "custom_tool_call_output"
            | "local_shell_call"
            | "local_shell_call_output"
            | "shell_call"
            | "shell_call_output"
            | "apply_patch_call"
            | "apply_patch_call_output"
            | "computer_call"
            | "computer_call_output"
            | "computer_screenshot"
            | "reasoning"
            | "file_search_call"
            | "web_search_call"
            | "image_generation_call"
            | "code_interpreter_call"
            | "mcp_call"
            | "mcp_list_tools"
            | "mcp_approval_request"
            | "mcp_approval_response"
            | "item_reference"
            | "compaction"
            | "ephemeral"
            | "enabled"
            | "disabled"
            | "auto"
            | "any"
            | "tool"
            | "none"
            | "web_search_result"
            | "web_fetch_result"
    )
}

impl Planner<'_> {
    fn phi_on(&self) -> bool {
        self.cfg.phi_mode != PhiMode::Off
    }

    /// Walk `value`. `typed_block` is true when the object is an API block (it has a `type`), in
    /// which case its structural fields are left alone; nested user data is always scanned.
    fn walk(&mut self, value: &Value, ptr: &str, scope: Scope, item_level: bool, raw: bool) {
        match value {
            // A data URL's payload is bytes, not text: scanning it corrupts images and files
            // (the header before `;base64,` carries nothing secret).
            // Only a strict data URL (no spaces, base64 payload only) in an image or file
            // position (`url`, `image_url`, `file_data`); any other string is scanned, so text
            // cannot hide behind a `data:...;base64,` prefix (security-guidance finding).
            Value::String(s) if is_media_position(ptr) && is_strict_data_url(s) => {}
            Value::String(s) => {
                self.leaves += 1;
                self.edits.push(Edit::Leaf {
                    ptr: ptr.to_string(),
                    text: s.clone(),
                    scope,
                });
            }
            Value::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    self.walk(v, &format!("{ptr}/{i}"), scope, item_level, raw);
                }
            }
            Value::Object(map) => {
                let kind = map.get("type").and_then(Value::as_str);
                // Signed: never touched in either scope (M1). In raw tool arguments a `type`
                // value is the tool's own data, so these API rules do not apply there.
                if !raw && matches!(kind, Some("thinking" | "redacted_thinking" | "reasoning")) {
                    return;
                }
                if !raw && self.phi_on() && is_media(map) {
                    self.edits.push(Edit::ReplaceWith {
                        ptr: ptr.to_string(),
                        json: withheld_block(self.api, item_level),
                    });
                    return;
                }
                // A message or a Responses `*_output` item from the client: PHI scope applies below.
                let role = map.get("role").and_then(Value::as_str);
                // `tool`/`function` messages (chat completions) carry tool output: client data.
                let client_item = matches!(
                    role,
                    Some("user" | "developer" | "system" | "tool" | "function")
                ) || kind
                    .is_some_and(|k| k.ends_with("_output") || k == "tool_result");
                // Gemini names the assistant `model`.
                let model_item = matches!(role, Some("assistant" | "model"))
                    || matches!(
                        kind,
                        Some(
                            "tool_use"
                                | "server_tool_use"
                                | "function_call"
                                | "custom_tool_call"
                                | "local_shell_call"
                                | "mcp_tool_use"
                                | "mcp_call"
                                | "computer_call"
                                | "shell_call"
                                | "apply_patch_call"
                        )
                    );
                let child_scope = Scope {
                    secrets: true,
                    phi: if client_item {
                        self.phi_on()
                    } else if model_item {
                        false
                    } else {
                        scope.phi
                    },
                };
                // Tool arguments are the tool's data, not API structure: nothing is skipped there.
                // Structural keys are skipped only on known API block/item types, and on message
                // objects in a `messages`/`input` position; any other object is user data (N3).
                let typed_block =
                    !raw && (kind.is_some_and(known_block_type) || (item_level && role.is_some()));
                for (k, v) in map {
                    // A secret used as an object key cannot be rewritten in place: fail closed.
                    if scan_text(k, ScanOptions::default())
                        .iter()
                        .any(|f| f.should_seal)
                    {
                        self.key_secret = true;
                    }
                    // Provider-encrypted state is opaque (rewriting it breaks decryption), but only
                    // on the item types that carry it; elsewhere the key is user data and scanned.
                    // `reasoning` items are skipped whole above.
                    if !raw
                        && kind == Some("compaction")
                        && matches!(k.as_str(), "encrypted_content" | "encrypted_index")
                    {
                        continue;
                    }
                    let structural = typed_block
                        && matches!(
                            k.as_str(),
                            "type"
                                | "role"
                                | "id"
                                | "tool_use_id"
                                | "call_id"
                                | "signature"
                                | "cache_control"
                                | "status"
                        );
                    // Base64 payloads are not text (and are withheld whole in PHI mode).
                    let base64_data = !raw
                        && k == "data"
                        && map.get("type").and_then(Value::as_str) == Some("base64");
                    if structural || base64_data {
                        continue;
                    }
                    let child = format!("{ptr}/{}", k.replace('~', "~0").replace('/', "~1"));
                    let child_raw = raw
                        || (model_item && matches!(k.as_str(), "input" | "arguments" | "action"))
                        || k == "args";
                    self.walk(v, &child, child_scope, false, child_raw);
                }
            }
            _ => {}
        }
    }
}

fn plan(api: Api, body: &Value, cfg: &SealerConfig) -> Result<Vec<Edit>, &'static str> {
    let mut p = Planner {
        api,
        cfg,
        edits: Vec::new(),
        leaves: 0,
        key_secret: false,
    };
    let phi = cfg.phi_mode != PhiMode::Off;
    let Some(map) = body.as_object() else {
        return Err("request body is not a JSON object");
    };
    for (k, v) in map {
        let ptr = format!("/{}", k.replace('~', "~0").replace('/', "~1"));
        match (api, k.as_str()) {
            (_, "model") => {}
            // Messages: each element is a message position (its role decides PHI scope).
            // Message positions in every chat-shaped API: the role decides PHI scope.
            (Api::AnthropicMessages | Api::ChatCompletions, "messages")
            | (Api::Gemini, "contents") => match v {
                Value::Array(items) => {
                    for (i, item) in items.iter().enumerate() {
                        let scope = Scope {
                            secrets: true,
                            phi: false,
                        };
                        p.walk(item, &format!("{ptr}/{i}"), scope, true, false);
                    }
                }
                other => p.walk(
                    other,
                    &ptr,
                    Scope {
                        secrets: true,
                        phi: false,
                    },
                    false,
                    false,
                ),
            },
            // Client-originated at the top level: system prompt, instructions, prompt variables.
            (Api::AnthropicMessages, "system")
            | (Api::Responses, "instructions" | "prompt")
            | (Api::ChatCompletions, "prompt")
            | (Api::Gemini, "systemInstruction" | "system_instruction") => {
                p.walk(v, &ptr, Scope { secrets: true, phi }, false, false)
            }
            (Api::Responses, "input") => match v {
                Value::Array(items) => {
                    for (i, item) in items.iter().enumerate() {
                        // An item with no role or type is a user message in the short form.
                        let scope = Scope { secrets: true, phi };
                        p.walk(item, &format!("{ptr}/{i}"), scope, true, false);
                    }
                }
                other => p.walk(other, &ptr, Scope { secrets: true, phi }, false, false),
            },
            // Messages, tools, metadata, prompt variables, MCP server definitions, anything else:
            // secrets everywhere; PHI decided by role/type inside.
            _ => p.walk(
                v,
                &ptr,
                Scope {
                    secrets: true,
                    phi: false,
                },
                false,
                false,
            ),
        }
        if p.leaves > MAX_LEAVES {
            return Err("too many string values in one request");
        }
        if p.key_secret {
            return Err("a secret is used as a JSON object key");
        }
    }
    Ok(p.edits)
}

// ---------------------------------------------------------------------------------------------
// Leaf transformation
// ---------------------------------------------------------------------------------------------

/// New text for one leaf, or `None` when nothing changes. Secrets become keyed handles; PHI
/// becomes `[PHI withheld]` (no fingerprint, P-16) or, under a BAA, a `lockrail://phi/` handle.
fn transform_leaf(text: &str, scope: Scope, cfg: &SealerConfig) -> (Option<String>, LeafCounts) {
    let mut spans: Vec<(usize, usize, String, u8)> = Vec::new(); // (start, end, replacement, kind)
    if scope.secrets {
        for f in scan_text(text, ScanOptions::default())
            .into_iter()
            .filter(|f| f.should_seal)
        {
            let handle = secret_handle(&f.kind, &keyed_fingerprint(&cfg.fp_key, &f.value));
            spans.push((f.start, f.end, handle, 0));
        }
    }
    if scope.phi && cfg.phi_mode == PhiMode::Block {
        for f in scan_phi(text, PhiOptions::default()) {
            let overlaps = spans.iter().any(|(s, e, _, _)| f.start < *e && *s < f.end);
            if overlaps {
                continue; // secret sealing wins on overlap
            }
            if cfg.baa {
                let handle = phi_handle(f.kind, &keyed_fingerprint(&cfg.fp_key, f.value(text)));
                spans.push((f.start, f.end, handle, 2));
            } else {
                spans.push((f.start, f.end, "[PHI withheld]".to_string(), 1));
            }
        }
    }
    if spans.is_empty() {
        return (None, LeafCounts::default());
    }
    spans.sort_by_key(|s| s.0);
    let mut counts = LeafCounts::default();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end, replacement, kind) in spans {
        if start < cursor {
            continue;
        }
        out.push_str(&text[cursor..start]);
        out.push_str(&replacement);
        cursor = end;
        match kind {
            0 => counts.secrets += 1,
            1 => counts.phi_withheld += 1,
            _ => counts.phi_sealed += 1,
        }
    }
    out.push_str(&text[cursor..]);
    (Some(out), counts)
}

fn memo_key(text: &str, scope: Scope, cfg: &SealerConfig) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([
        u8::from(scope.secrets),
        u8::from(scope.phi),
        cfg.phi_mode as u8,
        u8::from(cfg.baa),
    ]);
    h.update(cfg.fp_key);
    h.update(text.as_bytes());
    h.finalize().into()
}

// ---------------------------------------------------------------------------------------------
// The decision for one request
// ---------------------------------------------------------------------------------------------

pub struct Request<'a> {
    pub method: &'a str,
    /// `Content-Type`, used to withhold media uploads on non-inference paths in PHI mode.
    pub content_type: Option<&'a str>,
    pub path_and_query: &'a str,
    pub content_encoding: Option<&'a str>,
    pub websocket_upgrade: bool,
    pub body: &'a [u8],
}

/// Fail mode for a body we could decode but not rewrite structurally. Closed: 503. Open: the raw
/// text is redacted as text (secrets to handles, PHI withheld), never forwarded unchanged.
fn fail_redacting(
    cfg: &SealerConfig,
    report: &mut Report,
    reason: &str,
    retry: bool,
    body: &[u8],
) -> Outcome {
    match cfg.fail_mode {
        FailMode::Closed => fail(cfg, report, reason, retry),
        FailMode::Open => {
            report.fail_open = true;
            let text = String::from_utf8_lossy(body);
            let scope = Scope {
                secrets: true,
                phi: cfg.phi_mode != PhiMode::Off,
            };
            match transform_leaf(&text, scope, cfg) {
                (Some(redacted), counts) => {
                    note_new_handles(&text, &redacted, &mut report.handles);
                    report.secrets_sealed += counts.secrets;
                    report.phi_withheld += counts.phi_withheld;
                    Outcome::Rewritten(redacted.into_bytes())
                }
                (None, _) => Outcome::Unchanged,
            }
        }
    }
}

fn fail(cfg: &SealerConfig, report: &mut Report, reason: &str, retry: bool) -> Outcome {
    match cfg.fail_mode {
        FailMode::Open => {
            report.fail_open = true;
            Outcome::Unchanged
        }
        FailMode::Closed => Outcome::Respond {
            status: 503,
            body: serde_json::json!({"error": {"type": "lockrail_unavailable", "message": reason}})
                .to_string(),
            retry,
        },
    }
}

fn respond(status: u16, kind: &str, message: &str) -> Outcome {
    Outcome::Respond {
        status,
        body: serde_json::json!({"error": {"type": kind, "message": message}}).to_string(),
        retry: false,
    }
}

/// Any secret or (in PHI mode) any PHI or media in the decoded body. JSON bodies are scanned
/// leaf by leaf after decoding, so `\u` escapes cannot hide a value (C6).
fn has_finding(body: &[u8], cfg: &SealerConfig) -> bool {
    let phi = cfg.phi_mode == PhiMode::Block;
    let scan = |text: &str| {
        scan_text(text, ScanOptions::default())
            .iter()
            .any(|f| f.should_seal)
            || (phi && !scan_phi(text, PhiOptions::default()).is_empty())
    };
    match serde_json::from_slice::<Value>(body) {
        Ok(json) => {
            // N2: a duplicate key hides the first value from serde; treat it as a finding.
            if value_spans(body).is_err() {
                return true;
            }
            fn any(v: &Value, phi: bool, scan: &dyn Fn(&str) -> bool) -> bool {
                match v {
                    Value::String(s) => scan(s),
                    Value::Array(a) => a.iter().any(|x| any(x, phi, scan)),
                    Value::Object(m) => {
                        (phi && is_media(m)) || m.iter().any(|(k, x)| scan(k) || any(x, phi, scan))
                    }
                    _ => false,
                }
            }
            any(&json, phi, &scan)
        }
        Err(_) => {
            // N2: scan the raw text and its percent-decoded form (form bodies, query strings).
            let raw = String::from_utf8_lossy(body);
            scan(&raw) || scan(&percent_decode(&raw))
        }
    }
}

/// `application/x-www-form-urlencoded` decoding: `+` is a space, `%XX` a byte.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn decide(req: &Request<'_>, cfg: &SealerConfig, memo: &Memo) -> (Outcome, Report) {
    let mut report = Report::default();
    if !cfg.enabled {
        return (Outcome::Unchanged, report); // kill switch: pure tunnel
    }
    if req.websocket_upgrade {
        return (
            respond(
                426,
                "lockrail_websocket_refused",
                "use HTTP; WebSocket bodies cannot be scanned",
            ),
            report,
        );
    }
    let class = classify(req.path_and_query);
    if class == PathClass::Abnormal {
        return (
            respond(
                400,
                "lockrail_path_refused",
                "request path is not in normal form",
            ),
            report,
        );
    }
    if req.body.is_empty() {
        return (Outcome::Unchanged, report);
    }
    let body = match decode_body(req.content_encoding, req.body) {
        Ok(b) => b,
        Err(e) => {
            let o = fail(cfg, &mut report, &format!("undecodable body: {e}"), false);
            return (o, report);
        }
    };
    match class {
        PathClass::Abnormal => unreachable!("handled above"),
        PathClass::PassList => {
            // Forwarded unchanged so sign-in keeps working; a finding is an event (m15).
            report.passlist_findings = has_finding(&body, cfg);
            (Outcome::Unchanged, report)
        }
        PathClass::Other => {
            // R-12 / U-A: uploads of images, PDFs or opaque files are withheld in PHI mode.
            let media_upload = req.content_type.is_some_and(|ct| {
                let ct = ct.to_ascii_lowercase();
                ct.starts_with("multipart/")
                    || ct.starts_with("image/")
                    || ct.starts_with("application/pdf")
                    || ct.starts_with("application/octet-stream")
                    || ct.starts_with("application/zip")
                    || ct.starts_with("application/vnd.")
                    || ct.starts_with("audio/")
                    || ct.starts_with("video/")
            });
            if cfg.phi_mode == PhiMode::Block && media_upload {
                report.blocked = true;
                report.images_withheld += 1;
                return (
                    respond(
                        403,
                        "lockrail_blocked",
                        "file and image uploads are withheld in PHI mode",
                    ),
                    report,
                );
            }
            if has_finding(&body, cfg) {
                report.blocked = true;
                return (
                    respond(
                        403,
                        "lockrail_blocked",
                        "this request carries a secret or PHI on a path Lockrail does not rewrite",
                    ),
                    report,
                );
            }
            (Outcome::Unchanged, report)
        }
        PathClass::Inference(api) => rewrite_inference(api, &body, cfg, memo, report),
    }
}

fn rewrite_inference(
    api: Api,
    body: &[u8],
    cfg: &SealerConfig,
    memo: &Memo,
    mut report: Report,
) -> (Outcome, Report) {
    // The deadline bounds scan work (M3): time spent scanning leaves not yet in the memo. Memo
    // hits and parsing are linear and not counted, so a retry whose leaves are all memoised always
    // completes, and each retry scans at least one new leaf: a cold resume converges (M20).
    let mut scan_time = Duration::ZERO;
    let Ok(json) = serde_json::from_slice::<Value>(body) else {
        let o = fail_redacting(cfg, &mut report, "request body is not JSON", false, body);
        return (o, report);
    };
    // Duplicate keys are refused before anything else: serde keeps the last, but the raw bytes
    // of the first would be forwarded whether or not anything is edited (C8).
    let spans = match value_spans(body) {
        Ok(s) => s,
        Err(reason) => {
            let o = fail_redacting(cfg, &mut report, reason, false, body);
            return (o, report);
        }
    };
    let edits = match plan(api, &json, cfg) {
        Ok(e) => e,
        Err(reason) => {
            let o = fail_redacting(cfg, &mut report, reason, false, body);
            return (o, report);
        }
    };
    let mut replacements: Vec<(String, String)> = Vec::new();
    for edit in edits {
        match edit {
            Edit::ReplaceWith { ptr, json } => {
                report.images_withheld += 1;
                replacements.push((ptr, json));
            }
            Edit::Leaf { ptr, text, scope } => {
                // N5: one value this large can never be scanned inside the deadline; refuse it
                // plainly instead of a retry loop.
                if text.len() > MAX_LEAF_BYTES {
                    return (
                        respond(
                            413,
                            "lockrail_value_too_large",
                            "a single text value exceeds 8 MiB",
                        ),
                        report,
                    );
                }
                let key = memo_key(&text, scope, cfg);
                let (new_text, counts) = match memo.get(&key) {
                    Some(hit) => {
                        report.memo_hits += 1;
                        hit
                    }
                    None => {
                        report.leaves_scanned += 1;
                        let leaf_started = Instant::now();
                        let result = transform_leaf(&text, scope, cfg);
                        scan_time += leaf_started.elapsed();
                        // Memoised immediately, even if the deadline is about to hit (M20).
                        memo.put(key, result.clone(), text.len());
                        result
                    }
                };
                report.secrets_sealed += counts.secrets;
                report.phi_withheld += counts.phi_withheld;
                report.phi_sealed += counts.phi_sealed;
                if let Some(t) = &new_text {
                    note_new_handles(&text, t, &mut report.handles);
                }
                if let Some(t) = new_text {
                    replacements.push((ptr, serde_json::to_string(&t).expect("string")));
                }
                if scan_time > cfg.deadline {
                    report.deadline_exceeded = true;
                    let o = fail_redacting(
                        cfg,
                        &mut report,
                        "scan deadline exceeded; retry",
                        true,
                        body,
                    );
                    return (o, report);
                }
            }
        }
    }
    if report.phi_withheld > 0 && cfg.phi_block_request && !cfg.baa {
        return (
            respond(
                400,
                "lockrail_phi_blocked",
                "this request contains PHI and this tool has no BAA",
            ),
            report,
        );
    }
    if replacements.is_empty() {
        return (Outcome::Unchanged, report);
    }
    let mut placed: Vec<(usize, usize, String)> = Vec::with_capacity(replacements.len());
    for (ptr, text) in replacements {
        match spans.get(&ptr) {
            Some((s, e)) => placed.push((*s, *e, text)),
            // An edit that cannot be placed would forward the original value (C8).
            None => {
                let o = fail(
                    cfg,
                    &mut report,
                    "internal: an edit could not be placed",
                    false,
                );
                return (o, report);
            }
        }
    }
    placed.sort_by_key(|p| p.0);
    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for (start, end, text) in placed {
        if start < cursor {
            // Nested replacement (a withheld block containing a sealed leaf): the outer one wins.
            continue;
        }
        out.extend_from_slice(&body[cursor..start]);
        out.extend_from_slice(text.as_bytes());
        cursor = end;
    }
    out.extend_from_slice(&body[cursor..]);
    (Outcome::Rewritten(out), report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn cfg() -> SealerConfig {
        SealerConfig {
            enabled: true,
            fp_key: [5u8; 32],
            phi_mode: PhiMode::Block,
            baa: false,
            phi_block_request: false,
            fail_mode: FailMode::Closed,
            deadline: Duration::from_millis(45),
        }
    }

    fn canary() -> String {
        ["AKIA", "Q7ZK3M9B2N4P6R8T"].concat()
    }

    fn req<'a>(path: &'a str, enc: Option<&'a str>, body: &'a [u8]) -> Request<'a> {
        Request {
            method: "POST",
            content_type: None,
            path_and_query: path,
            content_encoding: enc,
            websocket_upgrade: false,
            body,
        }
    }

    fn rewritten(o: &Outcome) -> String {
        match o {
            Outcome::Rewritten(b) => String::from_utf8(b.clone()).unwrap(),
            other => panic!("expected a rewrite, got {other:?}"),
        }
    }

    fn messages_body() -> String {
        serde_json::json!({
            "model": "claude-x",
            "messages": [{"role": "user", "content": [{"type": "text", "text": format!("my key {}", canary())}]}]
        })
        .to_string()
    }

    #[test]
    fn inference_paths_and_encodings_are_sealed() {
        let body = messages_body();
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(body.as_bytes()).unwrap();
            e.finish().unwrap()
        };
        let br = {
            let mut out = Vec::new();
            brotli::BrotliCompress(&mut body.as_bytes(), &mut out, &Default::default()).unwrap();
            out
        };
        let zs = ruzstd::encoding::compress_to_vec(
            body.as_bytes(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        for path in ["/v1/messages?beta=true", "/v1/messages/count_tokens"] {
            for (enc, bytes) in [
                (None, body.as_bytes().to_vec()),
                (Some("gzip"), gz.clone()),
                (Some("br"), br.clone()),
                (Some("zstd"), zs.clone()),
            ] {
                let memo = Memo::new(1 << 20);
                let (o, r) = decide(&req(path, enc, &bytes), &cfg(), &memo);
                let out = rewritten(&o);
                assert!(!out.contains(&canary()), "{path} {enc:?}");
                assert!(out.contains("lockrail://secret/aws-access-key-id/h_"));
                assert_eq!(r.secrets_sealed, 1);
            }
        }
        // Positive control: sealing off forwards the canary.
        let mut off = cfg();
        off.enabled = false;
        assert_eq!(
            decide(
                &req("/v1/messages", None, body.as_bytes()),
                &off,
                &Memo::new(1)
            )
            .0,
            Outcome::Unchanged
        );
    }

    #[test]
    fn responses_api_is_sealed() {
        let body = serde_json::json!({
            "model": "gpt-x",
            "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("use {}", canary())}]}]
        }).to_string();
        let (o, _) = decide(
            &req("/backend-api/codex/responses", None, body.as_bytes()),
            &cfg(),
            &Memo::new(1 << 20),
        );
        assert!(!rewritten(&o).contains(&canary()));
    }

    /// OpenAI-compatible chat completions (xAI, OpenRouter, Groq, Mistral, DeepSeek, Gemini's
    /// OpenAI endpoint, local servers): user, system, tool and assistant messages are sealed,
    /// tool-call arguments too, and PHI is withheld from client messages only.
    #[test]
    fn chat_completions_are_sealed() {
        for path in [
            "/v1/chat/completions",
            "/api/v1/chat/completions",
            "/openai/v1/chat/completions",
            "/v1beta/openai/chat/completions",
            "/chat/completions",
        ] {
            assert_eq!(
                classify(path),
                PathClass::Inference(Api::ChatCompletions),
                "{path}"
            );
        }
        let body = serde_json::json!({
            "model": "grok-x",
            "messages": [
                {"role": "system", "content": format!("deploy key {}", canary())},
                {"role": "user", "content": [{"type": "text", "text": format!("use {} for Patient MRN: 00482913", canary())}]},
                {"role": "assistant", "content": null, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "sh", "arguments": format!("{{\"cmd\":\"curl -H 'x: {}'\"}}", canary())}}]},
                {"role": "tool", "tool_call_id": "c1", "content": format!("TOKEN={} MRN: 00482913", canary())}
            ],
            "tools": [{"type": "function", "function": {"name": "sh", "description": "run", "parameters": {"type": "object"}}}]
        })
        .to_string();
        let (o, report) = decide(
            &req("/v1/chat/completions", None, body.as_bytes()),
            &cfg(),
            &Memo::new(1 << 20),
        );
        let out = rewritten(&o);
        assert!(!out.contains(&canary()), "{out}");
        assert!(
            !out.contains("00482913"),
            "PHI in user or tool message: {out}"
        );
        assert!(report.secrets_sealed >= 4, "{report:?}");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["messages"][2]["tool_calls"][0]["id"], "c1",
            "structure kept"
        );
        assert_eq!(v["messages"][3]["role"], "tool");
    }

    #[test]
    fn chat_completions_images_are_withheld_in_phi_mode() {
        let body = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "look"},
                {"type": "image_url", "image_url": {"url": "https://example.test/scan.png"}}
            ]}]
        })
        .to_string();
        let (o, report) = decide(
            &req("/v1/chat/completions", None, body.as_bytes()),
            &cfg(),
            &Memo::new(1 << 20),
        );
        let out = rewritten(&o);
        assert!(!out.contains("scan.png"), "{out}");
        assert_eq!(report.images_withheld, 1);
    }

    /// Gemini native API (Gemini CLI): `contents[].parts[]`, `systemInstruction`, inline media.
    #[test]
    fn gemini_generate_content_is_sealed() {
        for path in [
            "/v1beta/models/gemini-x:generateContent",
            "/v1beta/models/gemini-x:streamGenerateContent",
            "/v1internal:generateContent",
        ] {
            assert_eq!(classify(path), PathClass::Inference(Api::Gemini), "{path}");
        }
        let body = serde_json::json!({
            "systemInstruction": {"parts": [{"text": format!("key {}", canary())}]},
            "contents": [
                {"role": "user", "parts": [{"text": format!("use {} Patient MRN: 00482913", canary())}, {"inlineData": {"mimeType": "image/png", "data": "iVBORw0KGgo="}}]},
                {"role": "model", "parts": [{"functionCall": {"name": "sh", "args": {"cmd": format!("echo {}", canary())}}}]}
            ]
        })
        .to_string();
        let (o, report) = decide(
            &req(
                "/v1beta/models/gemini-x:generateContent",
                None,
                body.as_bytes(),
            ),
            &cfg(),
            &Memo::new(1 << 20),
        );
        let out = rewritten(&o);
        assert!(!out.contains(&canary()), "{out}");
        assert!(
            !out.contains("00482913") && !out.contains("iVBORw0KGgo="),
            "{out}"
        );
        assert_eq!(report.images_withheld, 1);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["contents"][1]["role"], "model");
    }

    /// Security-guidance finding: a leaf was skipped whenever it started with `data:` and held
    /// `;base64,`, and `encrypted_content` was opaque anywhere, so text could hide behind either.
    #[test]
    fn data_url_and_encrypted_content_skips_cannot_hide_secrets() {
        let fake_data_url = format!("data:text/plain;base64, the key is {}", canary());
        let encoded = {
            use base64ct::{Base64, Encoding};
            Base64::encode_string(format!("TOKEN={}", canary()).as_bytes())
        };
        let bodies = [
            serde_json::json!({"model":"m","messages":[{"role":"user","content": fake_data_url}]}),
            serde_json::json!({"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url": format!("data:image/png;base64,AAAA {}", canary())}}]}]}),
            serde_json::json!({"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}],"encrypted_content": canary()}]}),
            // A well-formed text data URL in an image position: text, so scanned and decoded.
            serde_json::json!({"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url": format!("data:text/plain;base64,{encoded}")}}]}]}),
        ];
        let mut off = cfg();
        off.phi_mode = PhiMode::Off;
        for b in bodies {
            let (o, _) = decide(
                &req("/v1/chat/completions", None, b.to_string().as_bytes()),
                &off,
                &Memo::new(1 << 20),
            );
            assert!(!rewritten(&o).contains(&canary()), "{b}");
        }
        // A real image data URL in an image position is still left byte-identical.
        let png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
        let body = serde_json::json!({"model":"m","messages":[{"role":"user","content":[{"type":"text","text":format!("k {}", canary())},{"type":"image_url","image_url":{"url": png}}]}]}).to_string();
        let (o, _) = decide(
            &req("/v1/chat/completions", None, body.as_bytes()),
            &off,
            &Memo::new(1 << 20),
        );
        assert!(rewritten(&o).contains(png));
    }

    #[test]
    fn signed_thinking_block_is_byte_identical() {
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"assistant","content":[{{"type":"thinking","thinking":"email jane@x.test {}","signature":"sig=="}}]}},{{"role":"user","content":"key {}"}}]}}"#,
            canary(),
            canary()
        );
        let (o, _) = decide(
            &req("/v1/messages", None, body.as_bytes()),
            &cfg(),
            &Memo::new(1 << 20),
        );
        let out = rewritten(&o);
        let thinking = format!(
            r#"{{"type":"thinking","thinking":"email jane@x.test {}","signature":"sig=="}}"#,
            canary()
        );
        assert!(out.contains(&thinking), "thinking block changed: {out}");
        assert!(out.ends_with(&format!(
            r#""content":"key lockrail://secret/aws-access-key-id/{}"}}]}}"#,
            keyed_fingerprint(&[5u8; 32], &canary())
        )));
    }

    #[test]
    fn phi_in_tool_result_withheld_or_sealed_by_baa_and_assistant_untouched() {
        let ssn = "219-09-9999";
        let body = serde_json::json!({"model":"m","messages":[
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":format!("patient SSN {ssn}")}]},
            {"role":"assistant","content":[{"type":"text","text":format!("SSN {ssn}")}]}
        ]}).to_string();
        let (o, r) = decide(
            &req("/v1/messages", None, body.as_bytes()),
            &cfg(),
            &Memo::new(1 << 20),
        );
        let out = rewritten(&o);
        assert!(out.contains("patient SSN [PHI withheld]"));
        assert!(
            out.contains(&format!("\"SSN {ssn}\"")),
            "assistant text changed"
        );
        assert_eq!(r.phi_withheld, 1);
        let mut baa = cfg();
        baa.baa = true;
        let (o, _) = decide(
            &req("/v1/messages", None, body.as_bytes()),
            &baa,
            &Memo::new(1 << 20),
        );
        assert!(rewritten(&o).contains("lockrail://phi/ssn/h_"));
    }

    #[test]
    fn images_and_documents_withheld_in_phi_mode() {
        let body = r#"{"model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}},{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"BBBB"}}]}]}"#;
        let (o, r) = decide(
            &req("/v1/messages", None, body.as_bytes()),
            &cfg(),
            &Memo::new(1 << 20),
        );
        let out = rewritten(&o);
        assert_eq!(
            out.matches("[image withheld by Lockrail: PHI mode]")
                .count(),
            2
        );
        assert_eq!(r.images_withheld, 2);
        serde_json::from_str::<Value>(&out).expect("still valid JSON");
    }

    #[test]
    fn git_log_emails_pass_without_clinical_context() {
        let log: String = (0..20)
            .map(|i| format!("Author: Dev {i} <dev{i}@corp.test>\n"))
            .collect();
        let body = serde_json::json!({"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":log}]}]}).to_string();
        let (o, _) = decide(
            &req("/v1/messages", None, body.as_bytes()),
            &cfg(),
            &Memo::new(1 << 20),
        );
        assert_eq!(o, Outcome::Unchanged);
        let with_context = body.replace("Author: Dev 0", "patient MRN: 00482913 Author: Dev 0");
        let (o, _) = decide(
            &req("/v1/messages", None, with_context.as_bytes()),
            &cfg(),
            &Memo::new(1 << 20),
        );
        assert!(rewritten(&o).contains("[PHI withheld]"));
    }

    #[test]
    fn other_paths_block_on_findings_and_pass_list_is_untouched() {
        let body = format!(r#"{{"note":"{}"}}"#, canary());
        let (o, _) = decide(
            &req("/v1/files", None, body.as_bytes()),
            &cfg(),
            &Memo::new(1),
        );
        assert!(matches!(o, Outcome::Respond { status: 403, .. }));
        let refresh = format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{}"}}"#,
            ["sk-ant-ort01-", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0"].concat()
        );
        let (o, _) = decide(
            &req("/v1/oauth/token", None, refresh.as_bytes()),
            &cfg(),
            &Memo::new(1),
        );
        assert_eq!(o, Outcome::Unchanged);
        let (o, _) = decide(
            &req("/v1/files", None, br#"{"note":"hello"}"#),
            &cfg(),
            &Memo::new(1),
        );
        assert_eq!(o, Outcome::Unchanged);
    }

    #[test]
    fn websocket_refused_and_bomb_capped_and_garbage_fails_closed() {
        let mut ws = req("/backend-api/codex/responses", None, b"");
        ws.websocket_upgrade = true;
        assert!(matches!(
            decide(&ws, &cfg(), &Memo::new(1)).0,
            Outcome::Respond { status: 426, .. }
        ));
        let bomb = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            let zeros = vec![0u8; 1 << 20];
            for _ in 0..70 {
                e.write_all(&zeros).unwrap();
            }
            e.finish().unwrap()
        };
        assert!(
            decode_body(Some("gzip"), &bomb)
                .unwrap_err()
                .contains("64 MiB")
        );
        let (o, _) = decide(
            &req("/v1/messages", Some("gzip"), b"not gzip"),
            &cfg(),
            &Memo::new(1),
        );
        assert!(matches!(o, Outcome::Respond { status: 503, .. }));
    }

    #[test]
    fn deadline_fails_closed_with_retry_and_memo_makes_the_retry_progress() {
        let leaves: Vec<Value> = (0..400)
            .map(|i| serde_json::json!({"type":"text","text": format!("{} block {i} {}", "word ".repeat(400), canary())}))
            .collect();
        let body = serde_json::json!({"model":"m","messages":[{"role":"user","content":leaves}]})
            .to_string();
        let mut tight = cfg();
        tight.deadline = Duration::from_millis(1);
        let memo = Memo::new(64 << 20);
        let mut attempts = 0;
        loop {
            attempts += 1;
            let (o, r) = decide(&req("/v1/messages", None, body.as_bytes()), &tight, &memo);
            match o {
                Outcome::Respond {
                    status: 503,
                    retry: true,
                    ..
                } => assert!(r.deadline_exceeded),
                Outcome::Rewritten(b) => {
                    assert!(!String::from_utf8(b).unwrap().contains(&canary()));
                    break;
                }
                other => panic!("{other:?}"),
            }
            assert!(attempts < 1000, "retries never converge");
        }
        assert!(attempts > 1, "the deadline never fired");
    }

    #[test]
    fn memo_hit_on_identical_second_turn() {
        let body = messages_body();
        let memo = Memo::new(64 << 20);
        let _ = decide(&req("/v1/messages", None, body.as_bytes()), &cfg(), &memo);
        let (_, r) = decide(&req("/v1/messages", None, body.as_bytes()), &cfg(), &memo);
        assert_eq!(r.leaves_scanned, 0);
        assert!(r.memo_hits >= 1);
    }

    #[test]
    fn span_tokenizer_matches_serde_pointers() {
        let src = r#" {"a" : [1, {"b":"x\"y"}, true], "c~/d": null, "e":{"f":[[]]}} "#;
        let spans = value_spans(src.as_bytes()).unwrap();
        let v: Value = serde_json::from_str(src).unwrap();
        for ptr in [
            "/a", "/a/0", "/a/1", "/a/1/b", "/a/2", "/c~0~1d", "/e", "/e/f", "/e/f/0",
        ] {
            let (s, e) = spans[ptr];
            let piece: Value = serde_json::from_str(&src[s..e]).unwrap();
            assert_eq!(&piece, v.pointer(ptr).unwrap(), "{ptr}");
        }
    }

    // ---- Regression tests for the GATE 5 adversarial review (C1..C8, U1, U2, U4) ----

    fn sealed(path: &str, body: &str) -> (Outcome, Report) {
        decide(
            &req(path, None, body.as_bytes()),
            &cfg(),
            &Memo::new(64 << 20),
        )
    }

    fn assert_no_canary(o: &Outcome, what: &str) {
        match o {
            Outcome::Rewritten(b) => assert!(
                !String::from_utf8_lossy(b).contains(&canary()),
                "{what}: canary forwarded"
            ),
            Outcome::Respond { .. } => {}
            Outcome::Unchanged => panic!("{what}: forwarded unchanged"),
        }
    }

    #[test]
    fn c1_responses_string_content_is_scanned() {
        let body = serde_json::json!({"model":"m","input":[{"role":"user","content":format!("key {} patient SSN 219-09-9999", canary())}]}).to_string();
        let (o, r) = sealed("/v1/responses", &body);
        let out = rewritten(&o);
        assert!(!out.contains(&canary()) && out.contains("[PHI withheld]"));
        assert_eq!((r.secrets_sealed, r.phi_withheld), (1, 1));
    }

    #[test]
    fn c2_user_data_under_structural_key_names_is_sealed() {
        for body in [
            serde_json::json!({"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"mcp","input":{"url":"x","data":format!("key {}", canary())}}]}]}),
            serde_json::json!({"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"mcp","input":{"type":"x","id":canary()}}]}]}),
            serde_json::json!({"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"metadata":{"items":[{"name":canary(),"status":canary()}]}}),
        ] {
            let (o, _) = sealed("/v1/messages", &body.to_string());
            assert_no_canary(&o, &body.to_string());
        }
        // A text-source document with PHI mode off: its text is scanned.
        let mut off = cfg();
        off.phi_mode = PhiMode::Off;
        let body = serde_json::json!({"model":"m","messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":format!("key {}", canary())}}]}]}).to_string();
        let (o, _) = decide(
            &req("/v1/messages", None, body.as_bytes()),
            &off,
            &Memo::new(1 << 20),
        );
        assert_no_canary(&o, "text document");
    }

    #[test]
    fn c3_pass_list_is_exact_and_scanned() {
        assert_eq!(classify("/backend-api/memories"), PathClass::Other);
        assert_eq!(classify("/backend-api/wham/tasks"), PathClass::Other);
        assert_eq!(classify("/backend-api/me"), PathClass::PassList);
        let (o, _) = sealed(
            "/backend-api/memories",
            &format!(r#"{{"m":"{}"}}"#, canary()),
        );
        assert!(matches!(o, Outcome::Respond { status: 403, .. }));
        let (o, r) = sealed(
            "/v1/oauth/token",
            &format!(r#"{{"refresh_token":"{}"}}"#, canary()),
        );
        assert_eq!(o, Outcome::Unchanged);
        assert!(
            r.passlist_findings,
            "pass-listed finding must still be reported"
        );
    }

    #[test]
    fn c4_memo_respects_its_budget_and_retries_converge_after_large_leaves() {
        let memo = Memo::new(10_000);
        for i in 0..100 {
            memo.put([i as u8; 32], (None, LeafCounts::default()), 10);
        }
        for i in 0..60u8 {
            let mut k = [0u8; 32];
            k[0] = 200;
            k[1] = i;
            memo.put(k, (Some("x".repeat(3000)), LeafCounts::default()), 3000);
        }
        assert!(
            memo.bytes() <= 10_000,
            "memo holds {} bytes over a 10000 budget",
            memo.bytes()
        );
        // Big leaves first, then a normal history under a tight deadline still converges.
        let big = Memo::new(4 << 20);
        for i in 0..9 {
            let body = serde_json::json!({"model":"m","messages":[{"role":"user","content":format!("{i}{}", "z".repeat(500_000))}]}).to_string();
            let _ = decide(&req("/v1/messages", None, body.as_bytes()), &cfg(), &big);
        }
        let leaves: Vec<Value> = (0..300)
            .map(|i| serde_json::json!({"type":"text","text":format!("{} {i}", "w ".repeat(200))}))
            .collect();
        let body = serde_json::json!({"model":"m","messages":[{"role":"user","content":leaves}]})
            .to_string();
        let mut tight = cfg();
        tight.deadline = Duration::from_millis(1);
        let mut tries = 0;
        loop {
            tries += 1;
            match decide(&req("/v1/messages", None, body.as_bytes()), &tight, &big).0 {
                Outcome::Respond { status: 503, .. } => assert!(tries < 400, "never converged"),
                _ => break,
            }
        }
    }

    #[test]
    fn c5_responses_items_are_covered_by_default() {
        let bodies = [
            serde_json::json!({"model":"m","input":[{"type":"local_shell_call","call_id":"c","action":{"type":"exec","command":["ls"],"env":{"AWS":canary()}}}]}),
            serde_json::json!({"model":"m","input":[{"type":"message","role":"user","content":"hi"}],"tools":[{"type":"mcp","server_url":"https://x","headers":{"Authorization":format!("Bearer {}", canary())}}]}),
            serde_json::json!({"model":"m","input":"hi","prompt":{"id":"p","variables":{"k":canary()}}}),
        ];
        for b in bodies {
            let (o, _) = sealed("/v1/responses", &b.to_string());
            assert_no_canary(&o, &b.to_string());
        }
        let shell = serde_json::json!({"model":"m","input":[{"type":"shell_call_output","call_id":"c","output":"patient SSN 219-09-9999"}]}).to_string();
        assert!(rewritten(&sealed("/v1/responses", &shell).0).contains("[PHI withheld]"));
        let nested_image = serde_json::json!({"model":"m","input":[{"type":"function_call_output","call_id":"c","output":[{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}]}).to_string();
        let out = rewritten(&sealed("/v1/responses", &nested_image).0);
        assert!(
            out.contains(
                r#"{"type":"input_text","text":"[image withheld by Lockrail: PHI mode]"}"#
            ),
            "{out}"
        );
    }

    #[test]
    fn c6_escaped_values_on_other_paths_are_decoded_before_scanning() {
        let ssn = r#"{"messages":[{"role":"user","content":"patient 219-09-9999"}]}"#;
        assert!(matches!(
            sealed("/v1/embeddings", ssn).0,
            Outcome::Respond { status: 403, .. }
        ));
        let escaped: String = canary()
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect();
        let key = format!(r#"{{"x":"key {escaped}"}}"#);
        assert!(matches!(
            sealed("/v1/embeddings", &key).0,
            Outcome::Respond { status: 403, .. }
        ));
    }

    #[test]
    fn c8_duplicate_keys_fail_closed() {
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"key {}","content":"clean"}}]}}"#,
            canary()
        );
        let (o, _) = sealed("/v1/messages", &body);
        assert!(matches!(o, Outcome::Respond { status: 503, .. }), "{o:?}");
    }

    #[test]
    fn u1_responses_item_level_image_becomes_a_user_message() {
        let body =
            serde_json::json!({"model":"m","input":[{"type":"input_image","image_url":"data:,x"}]})
                .to_string();
        let out = rewritten(&sealed("/v1/responses", &body).0);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["input"][0]["type"], "message");
        assert_eq!(v["input"][0]["content"][0]["type"], "input_text");
    }

    #[test]
    fn u2_compaction_is_inference_and_u4_abnormal_paths_are_refused() {
        assert_eq!(
            classify("/backend-api/codex/responses/compact"),
            PathClass::Inference(Api::Responses)
        );
        for p in [
            "/api/oauth/../../v1/messages",
            "//v1/messages",
            "/v1/messages;x",
            "/v1/%2e%2e/messages",
            "/v1\\messages",
        ] {
            assert_eq!(classify(p), PathClass::Abnormal, "{p}");
            assert!(
                matches!(sealed(p, "{}").0, Outcome::Respond { status: 400, .. }),
                "{p}"
            );
        }
    }

    // ---- Round-2 review regressions (N2..N5, U-A) ----

    #[test]
    fn n2_duplicates_and_form_bodies_on_other_and_pass_list_paths() {
        let dup = format!(r#"{{"x":"key {}","x":"clean"}}"#, canary());
        assert!(matches!(
            sealed("/v1/files", &dup).0,
            Outcome::Respond { status: 403, .. }
        ));
        let (o, r) = sealed("/api/event_logging/batch", &dup);
        assert_eq!(o, Outcome::Unchanged);
        assert!(r.passlist_findings);
        let form = format!("note={}", canary().replace('Q', "%51"));
        assert!(matches!(
            sealed("/v1/files", &form).0,
            Outcome::Respond { status: 403, .. }
        ));
    }

    #[test]
    fn n3_structural_skip_only_on_known_types() {
        for body in [
            serde_json::json!({"model":"m","input":"hi","metadata":{"type":"ticket","id":canary()}}),
            serde_json::json!({"model":"m","messages":[{"role":"user","content":"hi"}],"metadata":{"role":"x","status":canary()}}),
            serde_json::json!({"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"name":"t","input_schema":{"type":"object","id":canary()}}]}),
            serde_json::json!({"model":"m","messages":[{"role":"assistant","content":[{"type":"mcp_tool_use","id":"t","name":"q","server_name":"s","input":{"type":"q","id":canary()}}]}]}),
            serde_json::json!({"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"q","input":{"type":"reasoning","x":canary()}}]}]}),
            serde_json::json!({"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"q","input":{"type":"base64","data":canary()}}]}]}),
        ] {
            let path = if body.get("input").is_some() {
                "/v1/responses"
            } else {
                "/v1/messages"
            };
            let (o, _) = sealed(path, &body.to_string());
            assert_no_canary(&o, &body.to_string());
        }
        let key_secret = serde_json::json!({"model":"m","messages":[{"role":"user","content":"hi"}],"metadata":{canary(): 1}}).to_string();
        assert!(matches!(
            sealed("/v1/messages", &key_secret).0,
            Outcome::Respond { status: 503, .. }
        ));
    }

    #[test]
    fn n4_prompt_variables_are_client_data_and_screenshots_are_media() {
        let body = serde_json::json!({"model":"m","input":"hi","prompt":{"id":"p","variables":{"note":"patient SSN 219-09-9999"}}}).to_string();
        assert!(rewritten(&sealed("/v1/responses", &body).0).contains("[PHI withheld]"));
        let shot = serde_json::json!({"model":"m","input":[{"type":"computer_call_output","call_id":"c","output":{"type":"computer_screenshot","image_url":"data:image/png;base64,AAAA"}}]}).to_string();
        assert!(
            rewritten(&sealed("/v1/responses", &shot).0)
                .contains("[image withheld by Lockrail: PHI mode]")
        );
    }

    #[test]
    fn n5_one_huge_value_is_refused_plainly() {
        let body = serde_json::json!({"model":"m","messages":[{"role":"user","content":"a".repeat(MAX_LEAF_BYTES + 1)}]}).to_string();
        assert!(matches!(
            sealed("/v1/messages", &body).0,
            Outcome::Respond {
                status: 413,
                retry: false,
                ..
            }
        ));
        let memo = Memo::new(1000);
        memo.put([1; 32], (Some("x".repeat(500)), LeafCounts::default()), 500);
        assert!(memo.is_empty(), "an entry over budget/8 must not be cached");
    }

    #[test]
    fn u_a_media_uploads_on_other_paths_are_withheld_in_phi_mode() {
        let mut r = req(
            "/api/oauth/file_upload",
            None,
            b"--x\r\nContent-Type: image/png\r\n\r\n\x89PNG",
        );
        r.content_type = Some("multipart/form-data; boundary=x");
        assert!(matches!(
            decide(&r, &cfg(), &Memo::new(1)).0,
            Outcome::Respond { status: 403, .. }
        ));
    }

    // ---- Round-3 review regressions ----

    #[test]
    fn r3_encrypted_content_and_data_urls_are_opaque() {
        let blob = [
            "gAAAAAB",
            "hf_Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1",
            "+",
            "AKIA",
            "Q7ZK3M9B2N4P6R8T",
            "==",
        ]
        .concat();
        let body = serde_json::json!({"model":"m","input":[{"type":"compaction","encrypted_content":blob},{"role":"user","content":"hi"}]}).to_string();
        assert_eq!(
            sealed("/backend-api/codex/responses", &body).0,
            Outcome::Unchanged
        );
        let mut off = cfg();
        off.phi_mode = PhiMode::Off;
        let url = format!(
            "data:image/png;base64,{}{}",
            // Valid standard base64 (data URLs use it) that happens to hold a key-like run.
            ["iVBOR", "w0KGgo", "AKIA", "Q7ZK3M9B2N4P6R8T"].concat(),
            "A".repeat(9 << 20)
        );
        let body = serde_json::json!({"model":"m","input":[{"role":"user","content":[{"type":"input_image","image_url":url}]}]}).to_string();
        let (o, _) = decide(
            &req("/v1/responses", None, body.as_bytes()),
            &off,
            &Memo::new(1 << 20),
        );
        assert_eq!(o, Outcome::Unchanged);
    }

    #[test]
    fn r3_fail_open_redacts_instead_of_forwarding_raw() {
        let mut open = cfg();
        open.fail_mode = FailMode::Open;
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"key {} out \ud83d"}}]}}"#,
            canary()
        );
        let (o, r) = decide(
            &req("/v1/messages", None, body.as_bytes()),
            &open,
            &Memo::new(1 << 20),
        );
        assert!(r.fail_open);
        assert!(!rewritten(&o).contains(&canary()));
    }
}
