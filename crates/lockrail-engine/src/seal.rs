use core::fmt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum SecretConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanOptions {
    pub aggressive: bool,
    pub protection_mode: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            aggressive: false,
            protection_mode: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealOptions {
    pub aggressive: bool,
    pub protection_mode: bool,
}

impl Default for SealOptions {
    fn default() -> Self {
        Self {
            aggressive: false,
            protection_mode: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretFinding {
    /// Detector kind. Static for the built-in rules (no allocation per finding); owned for
    /// derived kinds such as `base64-github-token`.
    pub kind: std::borrow::Cow<'static, str>,
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub fingerprint: String,
    pub confidence: SecretConfidence,
    pub should_seal: bool,
    pub preview: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealResult {
    pub safe_text: String,
    pub findings: Vec<SecretFinding>,
}

impl fmt::Debug for SecretFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretFinding")
            .field("kind", &self.kind)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("value", &"[REDACTED]")
            .field("fingerprint", &self.fingerprint)
            .field("confidence", &self.confidence)
            .field("should_seal", &self.should_seal)
            .field("preview", &self.preview)
            .finish()
    }
}

impl fmt::Debug for SealResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealResult")
            .field("safe_text", &self.safe_text)
            .field("findings", &self.findings)
            .finish()
    }
}

pub fn fingerprint(secret: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(19);
    out.push_str("fp_");
    for b in &digest[..8] {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0xf)] as char);
    }
    out
}

fn redacted_preview(value: &str) -> String {
    // Same output as before (first 4 and last 4 chars around `***`), without collecting every
    // char of the value.
    let mut chars = value.char_indices();
    let Some(head_end) = chars.nth(4).map(|(i, _)| i) else {
        return if value.is_empty() {
            String::new()
        } else {
            "***".to_string()
        };
    };
    let tail_start = value
        .char_indices()
        .rev()
        .nth(3)
        .map(|(i, _)| i)
        .unwrap_or(0);
    if value[head_end..].chars().count() < 5 {
        // 5..=8 chars in total.
        return "***".to_string();
    }
    let mut out = String::with_capacity(head_end + 3 + (value.len() - tail_start));
    out.push_str(&value[..head_end]);
    out.push_str("***");
    out.push_str(&value[tail_start..]);
    out
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '+' | '=' | ':' | '~')
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_high_entropy(s: &str) -> bool {
    s.len() >= 24 && shannon_entropy(s) >= 3.6
}

fn context_suggests_secret(input: &str, start: usize) -> bool {
    // Byte offsets can land inside a multibyte char; round down to a char boundary so the slice
    // can never panic (D2). `start` itself is always an ASCII token start.
    let window_start = input.floor_char_boundary(start.saturating_sub(48));
    let lower = input[window_start..start].to_ascii_lowercase();
    [
        "api",
        "token",
        "secret",
        "password",
        "bearer",
        "auth",
        "client",
        "key",
        "credential",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn should_seal(confidence: SecretConfidence, options: ScanOptions) -> bool {
    match confidence {
        SecretConfidence::High => true,
        SecretConfidence::Medium => options.protection_mode,
        SecretConfidence::Low => options.aggressive,
    }
}

fn push_finding(
    out: &mut Vec<SecretFinding>,
    kind: impl Into<std::borrow::Cow<'static, str>>,
    start: usize,
    end: usize,
    value: String,
    confidence: SecretConfidence,
    options: ScanOptions,
) {
    if is_allowlisted(&value) {
        return;
    }
    out.push(SecretFinding {
        kind: kind.into(),
        start,
        end,
        // Filled in after overlap resolution, for surviving findings only.
        fingerprint: String::new(),
        preview: String::new(),
        should_seal: should_seal(confidence, options),
        confidence,
        value,
    });
}

/// The 0.3.7 per-rule scanner, kept as the reference that [`scan_prefix_rules`] is tested
/// against (`prefix_automaton_matches_per_rule_scanning`).
#[cfg(test)]
fn scan_prefixed(
    input: &str,
    prefix: &str,
    kind: &'static str,
    min_len: usize,
    confidence: SecretConfidence,
    out: &mut Vec<SecretFinding>,
    options: ScanOptions,
) {
    let mut offset = 0;
    while let Some(pos) = input[offset..].find(prefix) {
        let start = offset + pos;
        if prefix_inside_token(input, start) {
            offset = start + prefix.len();
            continue;
        }
        let mut end = start;
        for (idx, ch) in input[start..].char_indices() {
            if idx == 0 || is_token_char(ch) {
                end = start + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        if end > start && end - start >= min_len {
            let value = input[start..end].to_string();
            push_finding(out, kind, start, end, value, confidence, options);
        }
        offset = end.max(start + prefix.len());
    }
}

fn scan_bearer(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let lower = input.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(pos) = lower[offset..].find("bearer ") {
        let start = offset + pos + 7;
        let mut end = start;
        for (idx, ch) in input[start..].char_indices() {
            if is_token_char(ch) {
                end = start + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        if end - start >= 16 {
            let value = input[start..end].to_string();
            push_finding(
                out,
                "bearer-token",
                start,
                end,
                value,
                SecretConfidence::High,
                options,
            );
        }
        // `start` is already past the matched "bearer " (so this always makes progress) and is a
        // char boundary; `start + 1` could run past the end or into a multibyte char.
        offset = end.max(start);
    }
}

fn scan_jwt(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let mut offset = 0;
    while let Some(pos) = input[offset..].find("eyJ") {
        let start = offset + pos;
        let mut end = start;
        for (idx, ch) in input[start..].char_indices() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                end = start + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        let value = &input[start..end];
        if value.matches('.').count() == 2 && value.len() >= 40 {
            push_finding(
                out,
                "jwt",
                start,
                end,
                value.to_string(),
                SecretConfidence::Medium,
                options,
            );
        }
        offset = end.max(start + 3);
    }
}

/// Largest PEM block searched for an END marker. A 4096-bit RSA key is about 3.3 KiB; bounding the
/// search keeps the scan linear when an input holds many BEGIN lines and no END (D20).
const MAX_PEM_BLOCK_BYTES: usize = 16 * 1024;
/// How far after an assignment keyword the separator may appear (D20).
const MAX_ASSIGNMENT_SEPARATOR_BYTES: usize = 256;

/// End of a bounded window starting at `start`, rounded down to a char boundary.
fn window_end(input: &str, start: usize, len: usize) -> usize {
    input.floor_char_boundary(start.saturating_add(len).min(input.len()))
}

fn scan_private_key_blocks(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let begin = "-----BEGIN ";
    let end_marker = "-----END ";
    let mut offset = 0;
    // Two-pointer END search (D20): BEGIN hits arrive in increasing order, so the next END at or
    // after a BEGIN is the cached one or lies beyond `end_scanned`.
    let mut next_end: Option<usize> = None;
    let mut end_scanned = 0usize;
    while let Some(pos) = input[offset..].find(begin) {
        let start = offset + pos;
        if next_end.is_none_or(|e| e < start) {
            let from = end_scanned.max(start);
            next_end = input[from..].find(end_marker).map(|i| from + i);
            end_scanned = next_end.unwrap_or(input.len());
        }
        if let Some(maybe_end) = next_end.filter(|e| e - start <= MAX_PEM_BLOCK_BYTES) {
            let after_end = maybe_end + end_marker.len();
            let close_window = &input[after_end..window_end(input, after_end, 128)];
            if let Some(close) = close_window.find("-----") {
                let end = maybe_end + end_marker.len() + close + 5;
                let value = input[start..end].to_string();
                // Decide on the BEGIN label only: `PRIVATE KEY` (PKCS8, RSA, EC, DSA, OPENSSH,
                // ENCRYPTED) or `PGP PRIVATE KEY BLOCK`. Public keys, certificates and PGP
                // signatures are not secrets.
                if pem_label_is_private(&value) {
                    // A block with no key material (`...`, `<your key here>`) is documentation
                    // (class E): Low, so it is sealed only in aggressive and log redaction,
                    // where 0.3.7 removed every PRIVATE KEY block.
                    let confidence = if pem_has_key_material(&value) {
                        SecretConfidence::High
                    } else {
                        SecretConfidence::Low
                    };
                    push_finding(
                        out,
                        "private-key-block",
                        start,
                        end,
                        value,
                        confidence,
                        options,
                    );
                }
                offset = end;
                continue;
            }
        }
        offset = start + begin.len();
    }
}

/// A real key body holds base64 lines; a documentation block holds `...`, `<your key here>`
/// or `[redacted N bytes]` (class E). Requires a run of at least 40 base64 characters.
fn pem_has_key_material(block: &str) -> bool {
    let mut run = 0usize;
    for b in block.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') {
            run += 1;
            if run >= 40 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn pem_label_is_private(block: &str) -> bool {
    let Some(rest) = block.strip_prefix("-----BEGIN ") else {
        return false;
    };
    let label = rest[..window_end(rest, 0, 64)]
        .split("-----")
        .next()
        .unwrap_or("");
    label.ends_with("PRIVATE KEY") || label.ends_with("PRIVATE KEY BLOCK")
}

/// The URL carries a real password: the authority (up to the first `/`, `?` or `#`) has
/// `user:password@`, and the password is not empty, a variable or a placeholder.
fn url_has_password(url: &str) -> bool {
    let Some((_, after_scheme)) = url.split_once("://") else {
        return false;
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let Some((userinfo, _host)) = authority.rsplit_once('@') else {
        return false;
    };
    let Some((_user, password)) = userinfo.split_once(':') else {
        return false;
    };
    let lower = password.to_ascii_lowercase();
    !password.is_empty()
        && !password.starts_with(['$', '<', '{', '%', '*'])
        && !matches!(
            lower.as_str(),
            "password"
                | "pass"
                | "passwd"
                | "secret"
                | "changeme"
                | "pwd"
                | "user"
                | "xxx"
                | "xxxx"
        )
        && !password.chars().all(|c| c == 'x' || c == 'X' || c == '*')
}

/// Database and queue schemes: the whole URL becomes one handle (0.3.7 behaviour, which
/// `lockrail env run` resolves back into a working connection string).
const DATABASE_SCHEMES: &[&str] = &[
    "postgresql",
    "postgres",
    "mysql",
    "mongodb+srv",
    "mongodb",
    "redis",
    "rediss",
    "amqp",
    "amqps",
];

/// Credentials in a URL of any scheme (teardown C: only database schemes were checked, so
/// `https://user:pass@`, `ftp://`, `smtps://` and `https://<token>@host` leaked). One pass over
/// `://`; the scheme is read backwards (at most 32 bytes), so the scan stays linear.
fn scan_urls(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let bytes = input.as_bytes();
    let mut offset = 0;
    while let Some(pos) = input[offset..].find("://") {
        let sep = offset + pos;
        offset = sep + 3;
        let mut scheme_start = sep;
        while scheme_start > 0
            && sep - scheme_start < 32
            && (bytes[scheme_start - 1].is_ascii_alphanumeric()
                || matches!(bytes[scheme_start - 1], b'+' | b'.' | b'-'))
        {
            scheme_start -= 1;
        }
        // Schemes start with a letter; `jdbc:postgresql://` reads as `postgresql`.
        while scheme_start < sep && !bytes[scheme_start].is_ascii_alphabetic() {
            scheme_start += 1;
        }
        if scheme_start == sep {
            continue;
        }
        let scheme = input[scheme_start..sep].to_ascii_lowercase();
        let is_url_end =
            |ch: char| ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | '`' | ')' | ']' | '}');
        if DATABASE_SCHEMES.iter().any(|d| scheme.ends_with(d)) {
            // The whole URL is the value; the next search starts after it (0.3.7 behaviour,
            // linear because the offset jumps to `end`).
            let mut end = sep + 3;
            for (idx, ch) in input[sep + 3..].char_indices() {
                if is_url_end(ch) {
                    break;
                }
                end = sep + 3 + idx + ch.len_utf8();
            }
            let url = &input[scheme_start..end];
            if url.len() >= 16 && url_has_password(url) {
                push_finding(
                    out,
                    "database-url",
                    scheme_start,
                    end,
                    url.to_string(),
                    SecretConfidence::High,
                    options,
                );
            }
            offset = end.max(offset);
            continue;
        }
        // Only the authority is read. It cannot contain `/`, so the authorities of successive
        // `://` hits are disjoint and the total work is linear.
        let authority_start = sep + 3;
        let authority_len = input[authority_start..]
            .find(|ch: char| is_url_end(ch) || matches!(ch, '/' | '?' | '#'))
            .unwrap_or(input.len() - authority_start);
        let authority = &input[authority_start..authority_start + authority_len];
        let Some(at) = authority.rfind('@') else {
            continue;
        };
        let userinfo = &authority[..at];
        if let Some(colon) = userinfo.find(':') {
            let password = &userinfo[colon + 1..];
            let probe = format!("x://u:{password}@h");
            if password.len() >= 4 && url_has_password(&probe) {
                let start = authority_start + colon + 1;
                push_finding(
                    out,
                    "url-credential",
                    start,
                    start + password.len(),
                    password.to_string(),
                    SecretConfidence::High,
                    options,
                );
            }
        } else if looks_high_entropy(userinfo)
            && userinfo.bytes().any(|b| b.is_ascii_digit())
            && userinfo.bytes().any(|b| b.is_ascii_alphabetic())
        {
            // `https://<opaque token>@host`: a known prefix is found by the prefix rules; this
            // covers tokens with no prefix.
            push_finding(
                out,
                "url-credential",
                authority_start,
                authority_start + at,
                userinfo.to_string(),
                SecretConfidence::Medium,
                options,
            );
        }
    }
}

fn is_assignment_separator(c: char) -> bool {
    c == '=' || c == ':' || c.is_whitespace()
}

/// Longest value an assignment rule will take. Real secrets are far shorter; the cap keeps a
/// pathological value from being rescanned per keyword hit (D20).
const MAX_ASSIGNMENT_VALUE_BYTES: usize = 4096;

/// Keyword assignment rules: key (matched case-insensitively), kind, confidence.
const ASSIGNMENT_KEYS: &[(&str, &str, SecretConfidence)] = &[
    ("api_key", "api-key", SecretConfidence::High),
    ("apikey", "api-key", SecretConfidence::High),
    ("api_secret", "api-secret", SecretConfidence::High),
    ("token", "token-value", SecretConfidence::Medium),
    ("password", "password", SecretConfidence::High),
    ("passwd", "password", SecretConfidence::High),
    ("passphrase", "password", SecretConfidence::High),
    ("pwd", "password", SecretConfidence::High),
    ("client_secret", "client-secret", SecretConfidence::High),
    ("client_token", "client-token", SecretConfidence::High),
    ("access_token", "oauth-access-token", SecretConfidence::High),
    (
        "refresh_token",
        "oauth-refresh-token",
        SecretConfidence::High,
    ),
    ("id_token", "oauth-id-token", SecretConfidence::Medium),
    (
        "secret_access_key",
        "aws-secret-access-key",
        SecretConfidence::High,
    ),
    (
        "aws_secret_access_key",
        "aws-secret-access-key",
        SecretConfidence::High,
    ),
    ("database_url", "database-url", SecretConfidence::High),
    ("db_url", "database-url", SecretConfidence::High),
    ("connection_string", "database-url", SecretConfidence::High),
    ("private_key", "private-key", SecretConfidence::High),
    ("webhook_secret", "webhook-secret", SecretConfidence::High),
    ("gemini_api_key", "gemini-api-key", SecretConfidence::High),
    (
        "antigravity_api_key",
        "antigravity-api-key",
        SecretConfidence::High,
    ),
    ("google_api_key", "google-api-key", SecretConfidence::High),
    ("gcp_api_key", "gcp-api-key", SecretConfidence::High),
];

static ASSIGNMENT_AUTOMATON: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(ASSIGNMENT_KEYS.iter().map(|k| k.0))
        .expect("aho-corasick")
});

/// Per-key scan state. Keyword hits for one key arrive in increasing order, so the separator
/// search is a two-pointer (D20): the first separator at or after a hit is the one already found
/// or lies beyond `sep_scanned`, and every byte is examined at most once per key.
#[derive(Default)]
struct KeyState {
    /// Hits starting before this are inside a value already taken (or rejected).
    offset: usize,
    next_sep: Option<usize>,
    sep_scanned: usize,
    delims: DelimCache,
}

/// All assignment keys in one case-insensitive Aho-Corasick pass, with the same results as one
/// `find` loop per key ([`scan_assignment_per_key`], kept as the test reference). 24 passes and a
/// lowercase copy of the input cost about a quarter of the worst-case budget.
fn scan_assignment(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let mut states: Vec<KeyState> = ASSIGNMENT_KEYS
        .iter()
        .map(|_| KeyState::default())
        .collect();
    // Findings are bucketed per key and appended in key order, as the per-key loop did.
    let mut buckets: Vec<Vec<SecretFinding>> = ASSIGNMENT_KEYS.iter().map(|_| Vec::new()).collect();
    for m in ASSIGNMENT_AUTOMATON.find_overlapping_iter(input) {
        let k = m.pattern().as_usize();
        if m.start() < states[k].offset {
            continue;
        }
        let (key, kind, confidence) = ASSIGNMENT_KEYS[k];
        states[k].offset = assignment_hit(
            input,
            m.start(),
            key,
            kind,
            confidence,
            &mut states[k],
            &mut buckets[k],
            options,
        );
    }
    for bucket in buckets {
        out.extend(bucket);
    }
}

/// The 0.3.7-shaped per-key scan, kept as the reference [`scan_assignment`] is tested against.
#[cfg(test)]
fn scan_assignment_per_key(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let lower = input.to_ascii_lowercase();
    for &(key, kind, confidence) in ASSIGNMENT_KEYS {
        let mut st = KeyState::default();
        while let Some(pos) = lower[st.offset..].find(key) {
            let kstart = st.offset + pos;
            st.offset = assignment_hit(input, kstart, key, kind, confidence, &mut st, out, options);
        }
    }
}

/// One keyword hit at `kstart`. Returns the offset the next hit for this key must start at.
#[allow(clippy::too_many_arguments)]
fn assignment_hit(
    input: &str,
    kstart: usize,
    key: &str,
    kind: &'static str,
    confidence: SecretConfidence,
    st: &mut KeyState,
    out: &mut Vec<SecretFinding>,
    options: ScanOptions,
) -> usize {
    let after_key = kstart + key.len();
    if st.next_sep.is_none_or(|sep| sep < after_key) {
        let from = st.sep_scanned.max(after_key);
        st.next_sep = input[from..]
            .char_indices()
            .find(|(_, c)| is_assignment_separator(*c))
            .map(|(i, _)| from + i);
        st.sep_scanned = st.next_sep.unwrap_or(input.len());
    }
    // Between the key and its separator only identifier continuation, quotes and `]` may
    // appear (`API_KEY_PROD=`, `"api_key": `), so `${DB_PASSWORD}@db:5432` is not an
    // assignment to `password`. The gap is at most 256 bytes, so this stays linear.
    let sep = st
        .next_sep
        .filter(|sep| sep - after_key <= MAX_ASSIGNMENT_SEPARATOR_BYTES)
        .filter(|sep| {
            input.as_bytes()[after_key..*sep].iter().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'"' | b'\'' | b']')
            })
        });
    let mut consumed_to = after_key;
    let password_class = kind == "password";
    // `pwd` is also a shell command and `$PWD`/`OLDPWD` hold paths: it needs a left
    // word boundary and an explicit `=`/`:` (ODBC `Pwd=...;`).
    let short_key = key == "pwd";
    if short_key && kstart > 0 && input.as_bytes()[kstart - 1].is_ascii_alphabetic() {
        return after_key;
    }
    if let Some(sep) = sep {
        // At most one opening quote: `password : ''` is an empty value, not the start
        // of a quoted capture that runs into the next string (class I).
        let mut start = sep;
        let mut quoted = false;
        while start < input.len() {
            let ch = input.as_bytes()[start] as char;
            if ch.is_ascii_whitespace() || matches!(ch, '=' | ':') {
                start += 1;
            } else if matches!(ch, '"' | '\'') && !quoted {
                quoted = true;
                start += 1;
            } else {
                break;
            }
        }
        let explicit = input.as_bytes()[sep..start]
            .iter()
            .any(|b| matches!(b, b'=' | b':'));
        // An assignment's value is on its own line: `KEY=` followed by a newline is an
        // empty value, not the next line (v3 false-positive class A).
        let crosses_line = input.as_bytes()[sep..start].contains(&b'\n');
        let limit = window_end(input, start, MAX_ASSIGNMENT_VALUE_BYTES);
        let mut end = start;
        for (idx, ch) in input[start..limit].char_indices() {
            if is_token_char(ch) {
                end = start + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        let mut span = (start, end);
        let mut code = is_code_expression(input, start, end);
        // A call or index right after the token (`getPassword(user)`, `os.environ[...]`) is
        // code. Otherwise a password value is judged whole: the token run stops at the first
        // symbol, so judging it alone would read `dummyP@ss99` as the camelCase name `dummyP`
        // (hostile review).
        let call = matches!(input.as_bytes().get(end), Some(b'(' | b'['));
        if password_class
            && explicit
            && !call
            && let Some(wide) = password_value_span(input, start, end, &mut st.delims)
        {
            span = wide;
            code = is_code_expression(input, span.0, span.1);
        }
        let (start, end) = span;
        let is_url_without_password = |v: &str| v.contains("://") && !url_has_password(v);
        let skip_short_key =
            short_key && (!explicit || input[start..end].starts_with(['/', '~', '.', '\\']));
        // Without `=`/`:` the keyword is usually prose (`refresh token lifetime`,
        // `password reset`): the value must look like a secret (class H).
        let prose_word = !explicit && !looks_secret_like(&input[start..end]);
        // A command-line flag is the next argument, not a value (class C).
        let is_flag = input[start..end].starts_with("--");
        // Class F (`vercel env add DATABASE_URL production`) is covered by class H: a
        // value after a bare keyword must look like a secret. `name=` before a quote is
        // the next HTML attribute (`password" autocomplete="...`).
        let key_text = &input[kstart..after_key];
        let gap = &input.as_bytes()[after_key..sep];
        // The keyword inside a larger word: a file name or identifier before a space
        // (`...-password-and-mfa.docx next`), a camelCase continuation
        // (`forceChangePasswordNextSignIn`, `passwordHash`), or a plural, which names a
        // collection or a count (`cacheReadInputTokens`) (classes J, K, N).
        let inside_word = (!explicit && !gap.iter().all(|b| matches!(b, b'"' | b'\'')))
            || (key_text.bytes().any(|b| b.is_ascii_lowercase())
                && gap.first().is_some_and(u8::is_ascii_uppercase))
            || (gap.first() == Some(&b's')
                && gap.get(1).is_none_or(|b| !b.is_ascii_alphanumeric()));
        // Non-password fields hold random credentials: a plain word or a number is a
        // name, a namespace or a count (classes J, L).
        let value_text = &input[start..end];
        let word_or_number = !password_class
            && (!looks_secret_like(value_text) || value_text.bytes().all(|b| b.is_ascii_digit()));
        let attribute_name = !explicit
            && input[start..end].ends_with('=')
            && matches!(input.as_bytes().get(end), Some(b'"' | b'\''));
        if end > start
            && end - start >= 8
            && !code
            && !crosses_line
            && !prose_word
            && !is_flag
            && !inside_word
            && !word_or_number
            && !attribute_name
            && !skip_short_key
            && !is_url_without_password(&input[start..end])
        {
            let value = input[start..end].trim_matches(['"', '\'']).to_string();
            push_finding(out, kind, start, end, value, confidence, options);
            // Skip keyword hits inside the value just taken, so a value is never
            // rescanned per hit.
            consumed_to = end;
        } else if inside_word || word_or_number || prose_word {
            // A value rejected as a word, a number or part of a larger word is skipped
            // too: a keyword inside it would take a suffix of the same run, which is
            // no more secret-like, and re-reading the run per hit is quadratic (D20).
            consumed_to = end;
        }
    }
    consumed_to.max(after_key)
}

/// A value that could be a credential rather than a word: letters and digits together, or a
/// long mixed-case high-entropy run. Used only where no `=`/`:` marks an assignment.
fn looks_secret_like(value: &str) -> bool {
    let b = value.as_bytes();
    let digit = b.iter().any(u8::is_ascii_digit);
    let alpha = b.iter().any(u8::is_ascii_alphabetic);
    let mixed = b.iter().any(u8::is_ascii_uppercase) && b.iter().any(u8::is_ascii_lowercase);
    (digit && alpha) || (b.len() >= 20 && mixed && shannon_entropy(value) >= 3.5)
}

/// Longest quoted password taken whole. A closing quote further away than this is not
/// treated as the end of a value (prose with an apostrophe, a stray quote).
const MAX_QUOTED_PASSWORD_BYTES: usize = 256;

/// Cached "next delimiter at or after a position" searches for [`password_value_span`].
/// Keyword hits arrive in increasing order, so each cache only moves forward and every byte is
/// examined at most once per delimiter class (the separator search in [`scan_assignment`] uses
/// the same two-pointer bound, D20).
#[derive(Default)]
struct DelimCache {
    /// (searched up to, next match) per class: unquoted delimiters, `"`/newline, `'`/newline.
    classes: [(usize, Option<usize>); 3],
}

impl DelimCache {
    fn next(&mut self, bytes: &[u8], from: usize, class: usize) -> Option<usize> {
        let is_delim = |b: u8| match class {
            0 => {
                b.is_ascii_whitespace()
                    || matches!(
                        b,
                        b'"' | b'\'' | b'`' | b';' | b'&' | b',' | b')' | b']' | b'}' | b'<' | b'>'
                    )
            }
            1 => matches!(b, b'"' | b'\n' | b'\r'),
            _ => matches!(b, b'\'' | b'\n' | b'\r'),
        };
        let (scanned, next) = &mut self.classes[class];
        if next.is_none_or(|n| n < from) {
            let at = (*scanned).max(from);
            *next = bytes[at..]
                .iter()
                .position(|b| is_delim(*b))
                .map(|i| at + i);
            *scanned = next.unwrap_or(bytes.len());
        }
        *next
    }
}

/// The full password value at `start` after an explicit `=`/`:` (teardown C). A quoted value
/// runs to its closing quote (one line, at most 256 bytes, a backslash-escaped quote does not
/// close it); an unquoted one runs to whitespace or a delimiter, not to the first symbol, so
/// `Summer2024!xyz` is sealed whole. `None` keeps the token-character span.
fn password_value_span(
    input: &str,
    start: usize,
    token_end: usize,
    cache: &mut DelimCache,
) -> Option<(usize, usize)> {
    let bytes = input.as_bytes();
    let quote = start
        .checked_sub(1)
        .map(|i| bytes[i])
        .filter(|b| matches!(b, b'"' | b'\''));
    let limit = start + MAX_QUOTED_PASSWORD_BYTES;
    if let Some(q) = quote {
        let class = if q == b'"' { 1 } else { 2 };
        let mut from = start;
        loop {
            let at = cache.next(bytes, from, class)?;
            if at > limit || bytes[at] != q {
                return None;
            }
            // A quote preceded by an odd run of backslashes is escaped. The run is bounded by
            // the 256-byte value limit.
            let run = bytes[start..at]
                .iter()
                .rev()
                .take_while(|b| **b == b'\\')
                .count();
            if run % 2 == 0 {
                // An escaped newline (`\\n` inside a JSON-encoded transcript) ends a line: a
                // quoted value never spans one (class I).
                if input[start..at].contains("\\n") {
                    return None;
                }
                return Some((start, at));
            }
            from = at + 1;
        }
    }
    // Unquoted: code (`getPassword(user)`, `os.environ[...]`) was already rejected by the
    // caller on the token span; extend over everything up to a delimiter.
    let mut end = cache.next(bytes, token_end, 0).unwrap_or(bytes.len());
    if end > limit {
        return None;
    }
    // A JSON escape (`\\n`, `\\r`, `\\t`, `\\"`) ends the value inside an encoded transcript.
    if let Some(cut) = input[token_end..end]
        .match_indices('\\')
        .find(|(i, _)| {
            matches!(
                bytes.get(token_end + i + 1),
                Some(b'n' | b'r' | b't' | b'"')
            )
        })
        .map(|(i, _)| token_end + i)
    {
        end = cut;
    }
    // The delimiters are ASCII, so `end` is a char boundary.
    Some((start, end.max(token_end)))
}

fn scan_generic_entropy(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && !is_token_char(bytes[i] as char) {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_token_char(bytes[i] as char) {
            i += 1;
        }
        let end = i;
        if end > start {
            let value = &input[start..end];
            if looks_high_entropy(value)
                && !value.starts_with("lockrail://")
                && value.chars().any(|c| c.is_ascii_digit())
                && value.chars().any(|c| c.is_ascii_alphabetic())
                && context_suggests_secret(input, start)
            {
                push_finding(
                    out,
                    "high-entropy-token",
                    start,
                    end,
                    value.to_string(),
                    SecretConfidence::Low,
                    options,
                );
            }
        }
    }
}

/// Resolve overlapping findings by priority, not position (D22); see [`resolve_cluster`].
/// `O(n log n)` in the worst case and linear when findings do not overlap, keeping D20's bound.
fn normalize_findings(mut out: Vec<SecretFinding>) -> Vec<SecretFinding> {
    // Split into clusters of transitively overlapping findings (sorted by start, a cluster ends
    // where the next start reaches the running max end). Almost every finding is a cluster of
    // one, so the common case is a sort and a linear pass.
    out.sort_unstable_by_key(|f| (f.start, f.end));
    let mut result = Vec::with_capacity(out.len());
    let mut cluster: Vec<SecretFinding> = Vec::new();
    let mut cluster_end = 0usize;
    for finding in out {
        if !cluster.is_empty() && finding.start >= cluster_end {
            resolve_cluster(&mut cluster, &mut result);
        }
        cluster_end = if cluster.is_empty() {
            finding.end
        } else {
            cluster_end.max(finding.end)
        };
        cluster.push(finding);
    }
    resolve_cluster(&mut cluster, &mut result);
    result
}

/// Priority within one overlap cluster (D22): a finding that will be sealed beats one that
/// will not, then higher confidence, then the longer span, then the earlier start. A
/// lower-priority finding overlapping an accepted one is dropped, so a report-only match can
/// never shadow a real secret. Accepted spans are disjoint, so the overlap check only looks at
/// the nearest accepted neighbours.
fn resolve_cluster(cluster: &mut Vec<SecretFinding>, result: &mut Vec<SecretFinding>) {
    if cluster.len() <= 1 {
        result.append(cluster);
        return;
    }
    cluster.sort_by(|a, b| {
        b.should_seal
            .cmp(&a.should_seal)
            .then(b.confidence.cmp(&a.confidence))
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(a.start.cmp(&b.start))
    });
    let mut accepted: std::collections::BTreeMap<usize, SecretFinding> =
        std::collections::BTreeMap::new();
    for finding in cluster.drain(..) {
        let overlaps_before = accepted
            .range(..=finding.start)
            .next_back()
            .is_some_and(|(_, prev)| prev.end > finding.start);
        let overlaps_after = accepted
            .range(finding.start..)
            .next()
            .is_some_and(|(start, _)| *start < finding.end);
        if !overlaps_before && !overlaps_after {
            accepted.insert(finding.start, finding);
        }
    }
    result.extend(accepted.into_values());
}

pub fn scan_text(input: &str, options: ScanOptions) -> Vec<SecretFinding> {
    scan_text_depth(input, options, true)
}

/// `decode_base64` is false inside a decoded base64 run, so decoding is depth 1.
fn scan_text_depth(input: &str, options: ScanOptions, decode_base64: bool) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    scan_prefix_rules(input, &mut out, options);
    scan_bearer(input, &mut out, options);
    scan_jwt(input, &mut out, options);
    scan_private_key_blocks(input, &mut out, options);
    scan_urls(input, &mut out, options);
    scan_assignment(input, &mut out, options);
    scan_legacy_openai(input, &mut out, options);
    scan_telegram(input, &mut out, options);
    scan_entra_secrets(input, &mut out, options);
    scan_notion_legacy(input, &mut out, options);
    scan_basic_auth(input, &mut out, options);
    scan_twilio(input, &mut out, options);
    scan_azure_keys(input, &mut out, options);
    let runs = alphabet_runs(input);
    scan_aws_secret_near_id(input, &runs, &mut out, options);
    scan_generic_entropy(input, &mut out, options);
    if decode_base64 {
        scan_base64_wrapped(input, &runs, &mut out, options);
        scan_escaped(input, &mut out, options);
    }
    let mut out = normalize_findings(out);
    // Dense inputs repeat values: reuse the previous finding's derived fields when the value is
    // equal, comparing in place (no per-finding clones for unique values).
    for i in 0..out.len() {
        if i > 0 && out[i].value == out[i - 1].value {
            let (fp, preview) = (out[i - 1].fingerprint.clone(), out[i - 1].preview.clone());
            out[i].fingerprint = fp;
            out[i].preview = preview;
        } else {
            out[i].fingerprint = fingerprint(&out[i].value);
            out[i].preview = redacted_preview(&out[i].value);
        }
    }
    out
}

/// An assignment whose right-hand side is code, not a literal: a call or index follows the
/// value (`get_token()`, `os.environ["KEY"]`), or the value is a known configuration lookup.
fn is_code_expression(input: &str, start: usize, end: usize) -> bool {
    if matches!(input.as_bytes().get(end), Some(b'(' | b'[')) {
        return true;
    }
    let value = input[start..end].trim_matches(['"', '\'']);
    if looks_like_reference(value)
        || is_mask(value)
        || is_placeholder_word(value)
        || is_template_value(value)
    {
        return true;
    }
    [
        "process.env",
        "os.environ",
        "os.getenv",
        "System.getenv",
        "ENV.fetch",
        "env.",
        "config.",
        "settings.",
        "secrets.",
        "${",
        "$(",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
        || (value.starts_with('$')
            && value[1..]
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
}

/// A template slot, not a literal: `<your password>`, `{{ db_password }}`, `{% ... %}`,
/// `%(pw)s`, `#{pw}`.
fn is_template_value(value: &str) -> bool {
    (value.starts_with('<') && value.ends_with('>'))
        || ["{{", "{%", "%(", "#{"]
            .iter()
            .any(|p| value.starts_with(p))
}

/// A variable or attribute reference rather than a literal: no digits, and dotted
/// (`settings.token`), camelCase (`userPassword`) or an environment variable name
/// (`API_KEY_VALUE`). All-lowercase words are not treated as references, so a lowercase
/// passphrase is still sealed.
fn looks_like_reference(value: &str) -> bool {
    if value.is_empty() || value.bytes().any(|b| b.is_ascii_digit()) {
        return false;
    }
    let identifier = value
        .bytes()
        .all(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'.');
    if !identifier {
        return false;
    }
    let dotted = value.contains('.') && !value.starts_with('.') && !value.ends_with('.');
    let camel = value
        .as_bytes()
        .windows(2)
        .any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase());
    let env_name =
        value.contains('_') && value.bytes().all(|b| b.is_ascii_uppercase() || b == b'_');
    dotted || camel || env_name
}

static PLACEHOLDER_MARKERS: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([
            "your_",
            "your-",
            "yourapi",
            "your api",
            "your ",
            "insert_",
            "insert-",
            "replace_",
            "replace-",
            "replaceme",
            "changeme",
            "change_me",
            "placeholder",
            "redacted",
            "dummy",
            "example",
            "todo",
            "fixme",
            "xxxx",
            "****",
            "...",
        ])
        .expect("aho-corasick")
});

/// Conventional placeholder text in place of a value: a marker at the start (after `<`, `[`,
/// `{`, `*` or spaces), a marker directly followed by `here`, or a `_here`/`-here` ending.
/// One automaton pass and no allocation, because this runs for every finding.
/// A mask: nothing but mask characters (`********`, `xxxxxxxx`, `••••••`, `[...]`). Checked on
/// whole values only; a segment such as the `XXXX-XXXX` tail of 0.3.7's
/// `xoxb-LOCKRAILTEST-XXXX...` fixture is not a mask of the whole value.
fn is_mask(value: &str) -> bool {
    const MASK: &[char] = &[
        '*', '.', '#', '-', 'x', 'X', ' ', '<', '>', '[', ']', '{', '}', '•', '·',
    ];
    !value.is_empty() && value.chars().all(|c| MASK.contains(&c))
}

fn is_placeholder_word(value: &str) -> bool {
    let lead = value.len() - value.trim_start_matches(['<', '[', '{', '*', ' ']).len();
    let trimmed_end = value.trim_end_matches(['>', ']', '}', '*', ' ']);
    if trimmed_end.len() >= 5 {
        let tail = &trimmed_end.as_bytes()[trimmed_end.len() - 5..];
        if matches!(tail[0], b'_' | b'-') && tail[1..].eq_ignore_ascii_case(b"here") {
            return true;
        }
    }
    // One automaton pass: a marker at the (trimmed) start, or a marker followed by `here`.
    let bytes = value.as_bytes();
    PLACEHOLDER_MARKERS.find_iter(value).any(|m| {
        let followed_by_here = bytes
            .get(m.end()..m.end() + 4)
            .is_some_and(|w| w.eq_ignore_ascii_case(b"here"));
        // A word marker at the start counts only as a whole word (`example_key`, `EXAMPLE`),
        // not glued to more text (`todoist-Pa55w0rd!`, `dummyP@ss99`, `Example#2024!pw`).
        // Markers that end in a separator (`your_`, `your-`) delimit themselves.
        let self_delimited = matches!(bytes[m.end() - 1], b'_' | b'-' | b' ');
        let whole_word = self_delimited
            || bytes.get(m.end()).is_none_or(|b| {
                matches!(
                    b,
                    b'_' | b'-' | b'.' | b' ' | b':' | b'>' | b']' | b'}' | b'*'
                )
            });
        (m.start() == lead && whole_word) || followed_by_here
    })
}

/// An alphanumeric run of at least 20 characters with letters and digits and Shannon entropy of
/// at least 3.5 bits: generated key material, not a placeholder word or a mask.
fn has_random_run(value: &str) -> bool {
    value
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|r| r.len() >= 20)
        .any(|r| {
            r.bytes().any(|b| b.is_ascii_digit())
                && r.bytes().any(|b| b.is_ascii_alphabetic())
                && shannon_entropy(r) >= 3.5
        })
}

/// Documented example and placeholder values are not secrets (PLAN.md section 3.2 allowlist).
/// AWS documentation values carry `EXAMPLE`; placeholders are a known prefix followed only by
/// `x`, `*`, `.`, `<`, `>` or `0`.
fn is_allowlisted(value: &str) -> bool {
    // Lockrail's own handles are already safe; sealing them again nests handles (class G).
    if value.starts_with("lockrail://") {
        return true;
    }
    // AWS documentation values end their key in `EXAMPLE` / `EXAMPLEKEY`, inside one run
    // (`AKIAIOSFODNN7EXAMPLE`); a separate `:EXAMPLE` suffix is not that.
    // Checked bytewise: this runs for every finding (50k per MiB in the worst case).
    if value.ends_with("EXAMPLE") || value.ends_with("EXAMPLEKEY") {
        let run = value
            .bytes()
            .rev()
            .take_while(u8::is_ascii_alphanumeric)
            .count();
        if run >= 16 {
            return true;
        }
    }
    // A long random run is a real key whatever surrounds it: a placeholder-looking suffix
    // (`........`, `:EXAMPLE`, `-your_key`, `_todo_here`) must not exempt it (security review
    // finding 4). Checked only for values that look like placeholders, so the common case
    // pays nothing.
    looks_placeholder(value) && !has_random_run(value)
}

/// The placeholder and mask rules (classes B and D, PLAN.md section 3.2).
fn looks_placeholder(value: &str) -> bool {
    // `windows` instead of `str::contains`: building a two-way searcher per short value cost
    // more than the comparison itself.
    if value.as_bytes().windows(7).any(|w| w == b"EXAMPLE")
        || is_mask(value)
        || is_placeholder_word(value)
    {
        return true;
    }
    // A prefix with no body (`sk-proj-`) or an elided one (`sk-ant-api03-...`) (class D).
    // Only a prefix-shaped value (letters, digits and separators) counts as a bare prefix;
    // `Hunter2!xyz9_` is a password that happens to end in `_` (hostile review).
    let prefix_shaped = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if value.len() <= 16
        && prefix_shaped
        && (value.ends_with(['-', '_']) || value.ends_with("...") || value.ends_with('…'))
    {
        return true;
    }
    // Placeholder words after the prefix segments (`xoxb-your-bot-token`,
    // `sk-ant-api03-REPLACE_ME`), checked on each of the first three segment boundaries.
    let mut rest = value;
    for _ in 0..3 {
        let Some((_, tail)) = rest.split_once(['-', '_']) else {
            break;
        };
        // Word markers only: a tail of `X`s is not a placeholder here (0.3.7 treats
        // `xoxb-LOCKRAILTEST-XXXX-XXXX` as a real fixture).
        let has_word = tail
            .bytes()
            .any(|b| b.is_ascii_alphabetic() && !matches!(b, b'x' | b'X'));
        if has_word && is_placeholder_word(tail) {
            return true;
        }
        rest = tail;
    }
    // A mask filling the body: a trailing run of at least 8 `x`/`X`/`*`/`.` that is at least
    // half the value (an AWS key id prefix followed by 16 `X`, `sk-ant-api03-XXXX...`). Random
    // keys do not end in eight repeated mask characters; fixtures such as `...-XXXX` are still
    // sealed (class B).
    let mask = value
        .bytes()
        .rev()
        .take_while(|b| matches!(b, b'x' | b'X' | b'*' | b'.'))
        .count();
    if mask >= 8 && mask * 2 >= value.len() {
        return true;
    }
    // A placeholder is a known prefix (one or two segments, e.g. `ghp_`, `sk-proj-`) followed
    // only by lowercase `x`, `*`, `.`, `<` or `>`. Uppercase `X` is not a placeholder marker:
    // fixtures such as `xoxb-...-XXXX` are treated as real.
    let is_placeholder = |body: &str| {
        body.len() >= 8
            && body
                .chars()
                .all(|c| matches!(c, 'x' | '*' | '.' | '<' | '>'))
    };
    let after_first = value.split_once(['-', '_']).map(|(_, rest)| rest);
    let after_second = after_first.and_then(|rest| rest.split_once(['-', '_']).map(|(_, r)| r));
    after_first.is_some_and(is_placeholder) || after_second.is_some_and(is_placeholder)
}

/// Prefix rules: prefix, kind, minimum token length, confidence. Matched in one Aho-Corasick
/// pass instead of one pass per rule (36 passes cost ~20 ms per MiB).
const PREFIX_RULES: &[(&str, &str, usize, SecretConfidence)] = &[
    ("sk-proj-", "openai-key", 18, SecretConfidence::High),
    ("sk-svcacct-", "openai-key", 27, SecretConfidence::High),
    ("sk-admin-", "openai-key", 25, SecretConfidence::High),
    ("sk-ant-", "anthropic-key", 18, SecretConfidence::High),
    ("ghp_", "github-token", 20, SecretConfidence::High),
    ("github_pat_", "github-token", 24, SecretConfidence::High),
    ("glpat-", "gitlab-token", 16, SecretConfidence::High),
    ("xoxb-", "slack-bot-token", 16, SecretConfidence::High),
    ("xoxp-", "slack-user-token", 16, SecretConfidence::High),
    ("xapp-", "slack-app-token", 21, SecretConfidence::High),
    ("xoxa-", "slack-token", 21, SecretConfidence::High),
    ("xoxr-", "slack-token", 21, SecretConfidence::High),
    ("xoxe-", "slack-token", 21, SecretConfidence::High),
    ("sk_live_", "stripe-key", 16, SecretConfidence::High),
    ("sk_test_", "stripe-key", 16, SecretConfidence::High),
    ("rk_live_", "stripe-key", 24, SecretConfidence::High),
    ("rk_test_", "stripe-key", 24, SecretConfidence::High),
    ("AKIA", "aws-access-key-id", 20, SecretConfidence::High),
    ("ASIA", "aws-session-key-id", 20, SecretConfidence::High),
    ("AIza", "google-api-key", 20, SecretConfidence::High),
    ("cfp_", "cloudflare-token", 16, SecretConfidence::High),
    ("vercel_", "vercel-token", 16, SecretConfidence::High),
    ("ntl_", "netlify-token", 16, SecretConfidence::High),
    ("sbp_", "supabase-token", 16, SecretConfidence::High),
    // GitHub token variants (Enterprise, OAuth, server-to-server).
    ("ghs_", "github-app-token", 20, SecretConfidence::High),
    ("ghu_", "github-user-token", 20, SecretConfidence::High),
    ("gho_", "github-oauth-token", 20, SecretConfidence::High),
    ("ghr_", "github-refresh-token", 20, SecretConfidence::High),
    ("npm_", "npm-token", 24, SecretConfidence::High),
    ("pypi-", "pypi-token", 24, SecretConfidence::High),
    ("hf_", "huggingface-token", 20, SecretConfidence::High),
    (
        "whsec_",
        "stripe-webhook-secret",
        16,
        SecretConfidence::High,
    ),
    ("dp.pt.", "doppler-token", 16, SecretConfidence::High),
    ("hvs.", "vault-service-token", 20, SecretConfidence::High),
    ("hvb.", "vault-batch-token", 20, SecretConfidence::High),
    // SendGrid is Medium: the `SG.` prefix is common in other contexts.
    ("SG.", "sendgrid-key", 32, SecretConfidence::Medium),
    // Formats from the scanner teardown (competitors/C-secret-scanners.md, cross-checked against
    // gitleaks, Betterleaks and Kingfisher rule data). Minimum lengths sit at the documented
    // body length so identifiers sharing a prefix (`phx_click`, `xai-sdk`) never qualify.
    ("gsk_", "groq-key", 56, SecretConfidence::High),
    ("sk-or-v1-", "openrouter-key", 73, SecretConfidence::High),
    ("xai-", "xai-key", 74, SecretConfidence::High),
    ("vcp_", "vercel-token", 60, SecretConfidence::High),
    ("vci_", "vercel-token", 60, SecretConfidence::High),
    ("vca_", "vercel-token", 60, SecretConfidence::High),
    ("vcr_", "vercel-token", 60, SecretConfidence::High),
    ("vck_", "vercel-token", 60, SecretConfidence::High),
    ("cfut_", "cloudflare-token", 53, SecretConfidence::High),
    ("cfat_", "cloudflare-token", 53, SecretConfidence::High),
    ("cfk_", "cloudflare-token", 52, SecretConfidence::High),
    ("nfp_", "netlify-token", 40, SecretConfidence::High),
    ("dckr_pat_", "docker-hub-token", 36, SecretConfidence::High),
    ("dckr_oat_", "docker-hub-token", 36, SecretConfidence::High),
    ("lin_api_", "linear-api-key", 48, SecretConfidence::High),
    ("ntn_", "notion-token", 50, SecretConfidence::High),
    ("figd_", "figma-token", 45, SecretConfidence::High),
    ("sntryu_", "sentry-token", 71, SecretConfidence::High),
    ("sntrys_", "sentry-token", 60, SecretConfidence::High),
    ("phx_", "posthog-key", 51, SecretConfidence::High),
    (
        "sb_secret_",
        "supabase-secret-key",
        41,
        SecretConfidence::High,
    ),
    ("napi_", "neon-api-key", 69, SecretConfidence::High),
    ("glrt-", "gitlab-token", 25, SecretConfidence::High),
    ("gldt-", "gitlab-token", 25, SecretConfidence::High),
    ("glptt-", "gitlab-token", 46, SecretConfidence::High),
    ("glcbt-", "gitlab-token", 25, SecretConfidence::High),
    ("gloas-", "gitlab-token", 25, SecretConfidence::High),
    ("ya29.", "google-oauth-token", 60, SecretConfidence::High),
    ("AQ.Ab8RN6", "gemini-api-key", 50, SecretConfidence::High),
    // Webhook URLs: the path is the credential. Matched from the host so the scheme stays.
    (
        "hooks.slack.com/services/",
        "slack-webhook",
        50,
        SecretConfidence::High,
    ),
    (
        "hooks.slack.com/workflows/",
        "slack-webhook",
        50,
        SecretConfidence::High,
    ),
    (
        "discord.com/api/webhooks/",
        "discord-webhook",
        60,
        SecretConfidence::High,
    ),
    (
        "discordapp.com/api/webhooks/",
        "discord-webhook",
        63,
        SecretConfidence::High,
    ),
];

static PREFIX_AUTOMATON: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::new(PREFIX_RULES.iter().map(|r| r.0)).expect("aho-corasick")
});

/// True when the byte before `start` continues a token (alphanumeric or `+ / - _`). A URL
/// authority start (`://`) is a boundary, so `https://<token>@host` and webhook hosts match
/// (teardown C: `/` before the prefix hid `https://ghp_...@github.com`).
fn prefix_inside_token(input: &str, start: usize) -> bool {
    start > 0
        && !input[..start].ends_with("://")
        && input
            .as_bytes()
            .get(start - 1)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
}

/// Same semantics as calling [`scan_prefixed`] once per rule: every occurrence of every
/// prefix, the token extended over token characters, and a rule's own occurrences inside a
/// token it already matched skipped.
fn scan_prefix_rules(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let mut skip_until = [0usize; 128];
    debug_assert!(PREFIX_RULES.len() <= skip_until.len());
    for m in PREFIX_AUTOMATON.find_overlapping_iter(input) {
        let rule = m.pattern().as_usize();
        let start = m.start();
        if start < skip_until[rule] {
            continue;
        }
        // A key starts at a token boundary. Inside base64 or an identifier (`...Xhf_...`,
        // `...+AKIA...`) a prefix is a coincidence, and sealing it corrupts encrypted blobs.
        if prefix_inside_token(input, start) {
            continue;
        }
        let (prefix, kind, min_len, confidence) = PREFIX_RULES[rule];
        let mut end = start + prefix.len();
        for (idx, ch) in input[end..].char_indices() {
            if is_token_char(ch) {
                end = start + prefix.len() + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        skip_until[rule] = end.max(start + prefix.len());
        if end - start >= min_len {
            push_finding(
                out,
                kind,
                start,
                end,
                input[start..end].to_string(),
                confidence,
                options,
            );
        }
    }
}

/// All detector patterns are ASCII by design. Unicode mode would make `\b` unusable by the
/// fast DFA engines whenever the input holds non-ASCII text (measured 250 ms per MiB of
/// multibyte input), so patterns compile with Unicode off.
fn ascii_regex(pattern: &str) -> Result<Regex, regex::Error> {
    regex::RegexBuilder::new(pattern).unicode(false).build()
}

static LEGACY_OPENAI: LazyLock<Regex> =
    LazyLock::new(|| ascii_regex(r"\b(sk-[A-Za-z0-9]{48})\b").expect("regex"));

/// Legacy OpenAI keys: `sk-` followed by exactly 48 alphanumerics.
fn scan_legacy_openai(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    for m in LEGACY_OPENAI.find_iter(input) {
        push_finding(
            out,
            "openai-key",
            m.start(),
            m.end(),
            m.as_str().to_string(),
            SecretConfidence::High,
            options,
        );
    }
}

static HEX32: LazyLock<Regex> =
    LazyLock::new(|| ascii_regex(r"\b((?:SK|AC)?[0-9a-fA-F]{32})\b").expect("regex"));
static TWILIO_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| ascii_regex(r"(?i)twilio|auth[_\- ]?token|authtoken").expect("regex"));

/// Twilio: `SK` + 32 hex (API key SID, sealed), `AC` + 32 hex (account SID, sealed in
/// protection mode), and a bare 32-hex auth token when Twilio context or an account SID is within
/// 256 bytes. Context positions are collected in one pass; each token does a binary search.
fn scan_twilio(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let tokens: Vec<(usize, usize)> = HEX32
        .find_iter(input)
        .map(|m| (m.start(), m.end()))
        .collect();
    if tokens.is_empty() {
        return;
    }
    let mut anchors: Vec<usize> = TWILIO_CONTEXT.find_iter(input).map(|m| m.start()).collect();
    for (start, _) in &tokens {
        if input[*start..].starts_with("AC") {
            anchors.push(*start);
        }
    }
    anchors.sort_unstable();
    for (start, end) in tokens {
        let value = &input[start..end];
        if value.starts_with("SK") {
            push_finding(
                out,
                "twilio-api-key",
                start,
                end,
                value.to_string(),
                SecretConfidence::High,
                options,
            );
        } else if value.starts_with("AC") {
            push_finding(
                out,
                "twilio-account-sid",
                start,
                end,
                value.to_string(),
                SecretConfidence::Medium,
                options,
            );
        } else if near(&anchors, start, 256) && value.bytes().any(|b| b.is_ascii_digit()) {
            push_finding(
                out,
                "twilio-auth-token",
                start,
                end,
                value.to_string(),
                SecretConfidence::High,
                options,
            );
        }
    }
}

/// True when some anchor lies within `radius` bytes of `pos` (anchors sorted).
fn near(anchors: &[usize], pos: usize, radius: usize) -> bool {
    let i = anchors.partition_point(|a| *a < pos.saturating_sub(radius));
    anchors.get(i).is_some_and(|a| *a <= pos + radius)
}

static AZURE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:AccountKey|SharedAccessKey|PrimaryKey|SecondaryKey)=([A-Za-z0-9+/]{40,100}={0,2})",
    )
    .expect("regex")
});

/// Azure storage and Service Bus keys inside connection strings.
fn scan_azure_keys(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    for caps in AZURE_KEY.captures_iter(input) {
        let m = caps.get(1).expect("group");
        push_finding(
            out,
            "azure-storage-key",
            m.start(),
            m.end(),
            m.as_str().to_string(),
            SecretConfidence::High,
            options,
        );
    }
}

/// A bare 40-character AWS secret within 256 bytes of an access key id, with no variable name
/// to give it away. Both lists come from one pass each; the pairing is a binary search.
fn scan_aws_secret_near_id(
    input: &str,
    runs: &[(usize, usize, usize)],
    out: &mut Vec<SecretFinding>,
    options: ScanOptions,
) {
    // Key ids were already found by the `AKIA`/`ASIA` prefix rules (allowlisted ones dropped).
    let mut ids: Vec<usize> = out
        .iter()
        .filter(|f| f.kind == "aws-access-key-id" || f.kind == "aws-session-key-id")
        .map(|f| f.start)
        .collect();
    ids.sort_unstable();
    if ids.is_empty() {
        return;
    }
    // Maximal runs of the secret alphabet; exactly 40 characters, not followed by `=`.
    for &(start, end, padded) in runs {
        if end - start != 40 || padded != end {
            continue;
        }
        let value = &input[start..end];
        let mixed = value.bytes().any(|b| b.is_ascii_lowercase())
            && value
                .bytes()
                .any(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
        if mixed && near(&ids, start, 256) && shannon_entropy(value) >= 4.0 {
            push_finding(
                out,
                "aws-secret-access-key",
                start,
                end,
                value.to_string(),
                SecretConfidence::High,
                options,
            );
        }
    }
}

fn is_webish_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
}

/// Telegram bot tokens: `<5-16 digits>:A<34 of [A-Za-z0-9_-]>` with word boundaries.
fn scan_telegram(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let bytes = input.as_bytes();
    let mut offset = 0;
    while let Some(pos) = input[offset..].find(":A") {
        let colon = offset + pos;
        offset = colon + 2;
        let mut start = colon;
        while start > 0 && colon - start < 16 && bytes[start - 1].is_ascii_digit() {
            start -= 1;
        }
        let digits = colon - start;
        if !(5..=16).contains(&digits) || (start > 0 && is_webish_token_byte(bytes[start - 1])) {
            continue;
        }
        let body_end = colon + 2 + 34;
        if body_end > bytes.len()
            || !bytes[colon + 2..body_end]
                .iter()
                .all(|b| is_webish_token_byte(*b))
            || bytes
                .get(body_end)
                .is_some_and(|b| is_webish_token_byte(*b))
        {
            continue;
        }
        push_finding(
            out,
            "telegram-bot-token",
            start,
            body_end,
            input[start..body_end].to_string(),
            SecretConfidence::High,
            options,
        );
        offset = body_end;
    }
}

fn is_entra_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'~' | b'.' | b'-')
}

/// Microsoft Entra (Azure AD) client secrets: three characters, a digit, `Q~`, then 31-34
/// characters of `[A-Za-z0-9_~.-]` (gitleaks `azure-ad-client-secret`).
fn scan_entra_secrets(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let bytes = input.as_bytes();
    let mut offset = 0;
    while let Some(pos) = input[offset..].find("Q~") {
        let q = offset + pos;
        offset = q + 2;
        if q < 4 || !bytes[q - 1].is_ascii_digit() {
            continue;
        }
        let start = q - 4;
        if !bytes[start..q - 1].iter().all(|b| is_entra_byte(*b))
            || (start > 0 && is_entra_byte(bytes[start - 1]))
        {
            continue;
        }
        let mut end = q + 2;
        while end < bytes.len() && end - (q + 2) < 35 && is_entra_byte(bytes[end]) {
            end += 1;
        }
        let body = end - (q + 2);
        if !(31..=34).contains(&body) || bytes.get(end).is_some_and(|b| is_entra_byte(*b)) {
            continue;
        }
        push_finding(
            out,
            "azure-client-secret",
            start,
            end,
            input[start..end].to_string(),
            SecretConfidence::High,
            options,
        );
        offset = end;
    }
}

/// Notion internal integration secrets: `secret_` + exactly 43 alphanumerics. Kept apart from
/// the prefix rules because `secret_` also starts ordinary identifiers; the strict class and
/// length rule those out.
fn scan_notion_legacy(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let bytes = input.as_bytes();
    let mut offset = 0;
    while let Some(pos) = input[offset..].find("secret_") {
        let start = offset + pos;
        offset = start + 7;
        if start > 0 && is_webish_token_byte(bytes[start - 1]) {
            continue;
        }
        let body_end = start + 7 + 43;
        if body_end > bytes.len()
            || !bytes[start + 7..body_end]
                .iter()
                .all(|b| b.is_ascii_alphanumeric())
            || bytes
                .get(body_end)
                .is_some_and(|b| is_webish_token_byte(*b))
        {
            continue;
        }
        let body = &input[start + 7..body_end];
        if !(body.bytes().any(|b| b.is_ascii_digit())
            && body.bytes().any(|b| b.is_ascii_uppercase())
            && body.bytes().any(|b| b.is_ascii_lowercase()))
        {
            continue;
        }
        push_finding(
            out,
            "notion-token",
            start,
            body_end,
            input[start..body_end].to_string(),
            SecretConfidence::Medium,
            options,
        );
        offset = body_end;
    }
}

/// Base64 that decodes to printable `user:password` with both sides present.
fn decodes_to_user_pass(b64: &str) -> bool {
    use base64ct::{Base64, Encoding};
    if b64.len() < 8 || b64.len() > 1024 {
        return false;
    }
    let Ok(bytes) = Base64::decode_vec(b64) else {
        return false;
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return false;
    };
    if text.chars().any(|c| c.is_control()) {
        return false;
    }
    text.split_once(':')
        .is_some_and(|(u, p)| !u.is_empty() && p.len() >= 4 && !p.starts_with('$'))
}

fn base64_run_end(input: &str, start: usize) -> usize {
    let bytes = input.as_bytes();
    let mut end = start;
    while end < bytes.len()
        && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'+' | b'/'))
    {
        end += 1;
    }
    let mut padded = end;
    while padded < bytes.len() && padded < end + 2 && bytes[padded] == b'=' {
        padded += 1;
    }
    padded
}

/// HTTP Basic credentials: `Basic <base64 user:pass>` (header), Docker `"auth": "<base64>"`
/// entries, and `curl -u user:pass` / `--user user:pass` (teardown C top-15 #8).
static BASIC_AUTH_MARKERS: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(["basic ", "\"auth\"", " -u", " --user ", " --user="])
        .expect("aho-corasick")
});

fn scan_basic_auth(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let bytes = input.as_bytes();
    let push_b64 = |out: &mut Vec<SecretFinding>, start: usize| {
        let end = base64_run_end(input, start);
        if decodes_to_user_pass(&input[start..end]) {
            push_finding(
                out,
                "basic-auth",
                start,
                end,
                input[start..end].to_string(),
                SecretConfidence::High,
                options,
            );
        }
    };
    // One case-insensitive pass over the input, no lowercase copy (worst-case budget, D20).
    for m in BASIC_AUTH_MARKERS.find_iter(input) {
        let after = m.end();
        match m.pattern().as_usize() {
            0 => push_b64(out, after),
            1 => {
                let mut i = after;
                while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b':') {
                    i += 1;
                }
                if bytes.get(i) == Some(&b'"') {
                    push_b64(out, i + 1);
                }
            }
            p => {
                // `-u` is case-sensitive (`-U` is a different curl flag), and ` -u` must be
                // followed by a space or glued to its value (`-uuser:pass`).
                if p == 2 && &input[m.start()..after] != " -u" {
                    continue;
                }
                let mut start = after;
                if p == 2 && bytes.get(start) == Some(&b' ') {
                    start += 1;
                }
                if start >= bytes.len() || bytes[start].is_ascii_whitespace() {
                    continue;
                }
                let quote = Some(bytes[start]).filter(|b| matches!(b, b'"' | b'\''));
                let vstart = start + usize::from(quote.is_some());
                let mut vend = vstart;
                while vend < bytes.len()
                    && !bytes[vend].is_ascii_whitespace()
                    && Some(bytes[vend]) != quote
                {
                    vend += 1;
                }
                let value = &input[vstart..vend];
                let Some((user, password)) = value.split_once(':') else {
                    continue;
                };
                if user.is_empty()
                    || password.len() < 4
                    || password.starts_with(['$', '<', '{', '%'])
                    || is_placeholder_word(password)
                {
                    continue;
                }
                let pstart = vstart + user.len() + 1;
                push_finding(
                    out,
                    "basic-auth",
                    pstart,
                    vend,
                    password.to_string(),
                    SecretConfidence::High,
                    options,
                );
            }
        }
    }
}

/// Maximal runs of the base64 alphabet `[A-Za-z0-9+/]`, each with up to two trailing `=`, in
/// one byte loop. Shared by the base64 and bare-AWS-secret detectors, which used to run a
/// regex pass each over the whole input.
fn alphabet_runs(input: &str) -> Vec<(usize, usize, usize)> {
    let bytes = input.as_bytes();
    let is_alpha = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    let mut runs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !is_alpha(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_alpha(bytes[i]) {
            i += 1;
        }
        let end = i;
        let mut padded = end;
        while padded < bytes.len() && padded < end + 2 && bytes[padded] == b'=' {
            padded += 1;
        }
        if end - start >= 24 {
            runs.push((start, end, padded));
        }
    }
    runs
}
const MAX_BASE64_RUN: usize = 16 * 1024;

/// Cheap prefilter for decoded text (base64, hex, escapes): only text holding one of these
/// markers is re-scanned with the full detector set. Built from [`PREFIX_RULES`] plus the
/// structural detectors' keywords, so a new prefix rule can never be missing from it.
static DECODED_HINTS: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    let structural = [
        "sk-",
        "sk_",
        "-----begin",
        "eyj",
        "://",
        "bearer",
        "basic",
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "key",
        "auth",
        "credential",
        "accountkey",
        "twilio",
        "q~",
        ":a",
    ];
    aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(PREFIX_RULES.iter().map(|r| r.0).chain(structural))
        .expect("aho-corasick")
});

/// Text decoded from escapes, with a compact map back to the original: one entry per escape
/// (bytes between escapes map one to one), so memory is proportional to the escapes.
struct Unescaped {
    text: String,
    /// Original offset of decoded byte 0.
    base: usize,
    /// Per escape: (decoded start, decoded len, original start, original len), increasing.
    escapes: Vec<(usize, usize, usize, usize)>,
}

impl Unescaped {
    /// Original offset of decoded start position `d`; a position inside a decoded escape maps
    /// to the escape's start.
    fn map_start(&self, d: usize) -> usize {
        let i = self.escapes.partition_point(|e| e.0 <= d);
        match i.checked_sub(1).map(|i| self.escapes[i]) {
            None => self.base + d,
            Some((ds, dl, os, _)) if d < ds + dl => os,
            Some((ds, dl, os, ol)) => os + ol + (d - ds - dl),
        }
    }

    /// Original offset of decoded exclusive end `e`; an end inside a decoded escape maps to the
    /// escape's end.
    fn map_end(&self, e: usize) -> usize {
        let i = self.escapes.partition_point(|x| x.0 < e);
        match i.checked_sub(1).map(|i| self.escapes[i]) {
            None => self.base + e,
            Some((ds, dl, os, ol)) if e <= ds + dl => os + ol,
            Some((ds, dl, os, ol)) => os + ol + (e - ds - dl),
        }
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The escape at `i`, if any: `(decoded char, escape length)`. Percent and `\x` escapes are
/// decoded for ASCII only (a multibyte percent sequence is left as it is); `\uXXXX` for any
/// scalar value outside the surrogate range; `\/` to `/`.
fn escape_at(bytes: &[u8], i: usize) -> Option<(char, usize)> {
    let h = |j: usize| bytes.get(j).copied().and_then(hex_val);
    match bytes[i] {
        b'%' => {
            let v = h(i + 1)? * 16 + h(i + 2)?;
            (v < 0x80).then_some((v as char, 3))
        }
        b'\\' => match bytes.get(i + 1)? {
            b'/' => Some(('/', 2)),
            b'x' => {
                let v = h(i + 2)? * 16 + h(i + 3)?;
                (v < 0x80).then_some((v as char, 4))
            }
            b'u' => {
                let v = (u32::from(h(i + 2)?) << 12)
                    | (u32::from(h(i + 3)?) << 8)
                    | (u32::from(h(i + 4)?) << 4)
                    | u32::from(h(i + 5)?);
                char::from_u32(v).map(|c| (c, 6))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Decode `input[from..to]` (char boundaries), recording where each escape came from.
fn unescape(input: &str, from: usize, to: usize) -> Unescaped {
    let bytes = input.as_bytes();
    let mut text = String::with_capacity(to - from);
    let mut escapes = Vec::new();
    let mut i = from;
    let mut plain = from;
    while i < to {
        match escape_at(bytes, i).filter(|(_, len)| i + len <= to) {
            Some((c, len)) => {
                text.push_str(&input[plain..i]);
                let d = text.len();
                text.push(c);
                escapes.push((d, text.len() - d, i, len));
                i += len;
                plain = i;
            }
            None => i += 1,
        }
    }
    text.push_str(&input[plain..to]);
    Unescaped {
        text,
        base: from,
        escapes,
    }
}

/// Context kept around an escape when decoding: enough for a detector's keyword or a paired
/// key id (the AWS rule pairs within 256 bytes).
const ESCAPE_WINDOW: usize = 320;

/// Secrets hidden behind percent, `\uXXXX`, `\x` or `\/` escapes (teardown C: `%5F`,
/// `\u002d` and a JSON-escaped `\/` each defeated detection). Windows around escapes are
/// decoded once with an offset map, re-scanned only when the decoded text holds a hint, and a
/// finding whose decoded span covers an escape is mapped back onto the original text, so the
/// escaped span itself is sealed. Decoding is depth 1 and windows are merged, so every byte is
/// decoded at most once.
fn scan_escaped(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let bytes = input.as_bytes();
    let mut windows: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while let Some(pos) = bytes[i..].iter().position(|b| matches!(b, b'%' | b'\\')) {
        let at = i + pos;
        i = at + 1;
        let Some((_, len)) = escape_at(bytes, at) else {
            continue;
        };
        let from = input.floor_char_boundary(at.saturating_sub(ESCAPE_WINDOW));
        let to = input.ceil_char_boundary((at + len + ESCAPE_WINDOW).min(bytes.len()));
        match windows.last_mut() {
            Some(last) if from <= last.1 => last.1 = last.1.max(to),
            _ => windows.push((from, to)),
        }
        i = at + len;
    }
    for (from, to) in windows {
        let decoded = unescape(input, from, to);
        if !DECODED_HINTS.is_match(&decoded.text) {
            continue;
        }
        for f in scan_text_depth(&decoded.text, options, false) {
            let (start, end) = (decoded.map_start(f.start), decoded.map_end(f.end));
            // Only findings that needed decoding: the original span differs in length.
            if end - start == f.end - f.start {
                continue;
            }
            push_finding(
                out,
                f.kind,
                start,
                end,
                input[start..end].to_string(),
                f.confidence,
                options,
            );
        }
    }
}

/// Hex-encoded text: an even-length run of hex digits, at least 40, decoding to printable
/// ASCII. Hashes and ids decode to binary and are skipped.
fn decode_hex_text(run: &str) -> Option<String> {
    if run.len() < 40 || run.len() % 2 == 1 || !run.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = run
        .as_bytes()
        .chunks(2)
        .map(|p| hex_val(p[0]).unwrap_or(0) * 16 + hex_val(p[1]).unwrap_or(0))
        .collect();
    bytes
        .iter()
        .all(|b| b.is_ascii_graphic() || *b == b' ')
        .then(|| String::from_utf8(bytes).ok())
        .flatten()
}

/// Decode base64 runs once (depth 1, text only, at most 16 KiB each) and re-scan the decoded
/// text. A run whose decoding holds a sealable secret is sealed as `base64-wrapped`.
fn scan_base64_wrapped(
    input: &str,
    runs: &[(usize, usize, usize)],
    out: &mut Vec<SecretFinding>,
    options: ScanOptions,
) {
    use base64ct::{Base64, Base64Unpadded, Encoding};
    let mut combined = String::new();
    // (decoded start, decoded end, run start, run end incl. padding, encoding)
    let mut segments: Vec<(usize, usize, usize, usize, &'static str)> = Vec::new();
    for &(start, _, padded) in runs {
        let run = &input[start..padded];
        // A neighbouring `-`, `_` or `.` means base64url or a JWT segment, not a base64 blob.
        let before = input[..start].chars().next_back();
        let after = input[padded..].chars().next();
        if matches!(before, Some('-' | '_' | '.')) || matches!(after, Some('-' | '_' | '.')) {
            continue;
        }
        if run.len() > MAX_BASE64_RUN {
            continue;
        }
        let (text, encoding) = if let Some(text) = decode_hex_text(run) {
            (text, "hex")
        } else {
            if run.len() % 4 == 1 {
                continue;
            }
            let decoded = Base64::decode_vec(run)
                .or_else(|_| Base64Unpadded::decode_vec(run.trim_end_matches('=')));
            let Ok(bytes) = decoded else { continue };
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            (text, "base64")
        };
        let printable = text
            .chars()
            .filter(|c| !c.is_control() || c.is_whitespace())
            .count();
        if printable * 100 < text.chars().count() * 95 {
            continue;
        }
        if !DECODED_HINTS.is_match(&text) {
            continue;
        }
        let seg_start = combined.len();
        combined.push_str(&text);
        segments.push((seg_start, combined.len(), start, padded, encoding));
        combined.push_str("\n\n");
    }
    if segments.is_empty() {
        return;
    }
    // One rescan of every candidate's decoded text, joined by blank lines (security review:
    // one rescan per short run cost 31 ms per MiB of runs decoding to `token=`). A finding
    // belongs to every segment it overlaps; context rules may now pair values across adjacent
    // decoded runs, which can only seal more.
    let mut sealed_kind: Vec<Option<std::borrow::Cow<'static, str>>> = vec![None; segments.len()];
    for f in scan_text_depth(&combined, options, false)
        .iter()
        .filter(|f| f.should_seal)
    {
        let first = segments.partition_point(|s| s.1 <= f.start);
        for (i, seg) in segments.iter().enumerate().skip(first) {
            if seg.0 >= f.end {
                break;
            }
            if sealed_kind[i].is_none() {
                sealed_kind[i] = Some(format!("{}-{}", seg.4, f.kind).into());
            }
        }
    }
    for (seg, kind) in segments.iter().zip(sealed_kind) {
        if let Some(kind) = kind {
            push_finding(
                out,
                kind,
                seg.2,
                seg.3,
                input[seg.2..seg.3].to_string(),
                SecretConfidence::High,
                options,
            );
        }
    }
}

pub fn replace_with_handles(input: &str, findings: &[SecretFinding]) -> String {
    let mut out = String::new();
    let mut cursor = 0;
    for finding in findings {
        out.push_str(&input[cursor..finding.start]);
        out.push_str(&format!(
            "lockrail://secret/{}/{}",
            finding.kind, finding.fingerprint
        ));
        cursor = finding.end;
    }
    out.push_str(&input[cursor..]);
    out
}

pub fn seal_text(input: &str, options: SealOptions) -> SealResult {
    let findings = scan_text(
        input,
        ScanOptions {
            aggressive: options.aggressive,
            protection_mode: options.protection_mode,
        },
    );
    let sealed: Vec<_> = findings
        .iter()
        .filter(|finding| finding.should_seal)
        .cloned()
        .collect();
    SealResult {
        safe_text: replace_with_handles(input, &sealed),
        findings,
    }
}

pub fn redact_for_display(input: &str) -> String {
    let result = seal_text(
        input,
        SealOptions {
            aggressive: true,
            protection_mode: true,
        },
    );
    result.safe_text
}

pub fn redact_for_logs(input: &str) -> String {
    redact_for_display(input)
}

pub fn detect_secrets(input: &str) -> Vec<SecretFinding> {
    scan_text(input, ScanOptions::default())
}

pub fn scrub(input: &str) -> SealResult {
    seal_text(input, SealOptions::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for D2: a multibyte char that straddles the 48-byte context window start used
    /// to panic in `context_suggests_secret` (and abort the relay/proxy under panic = "abort").
    #[test]
    fn multibyte_char_at_context_window_edge_does_not_panic() {
        // Synthetic high-entropy token built at runtime so secret scanners do not flag a literal.
        let token = ["aB3dE5fG", "7hJ9kL1m", "N3pQ5rS7", "tU9vW1xY"].concat();
        for gap in 20..60 {
            // `é` is 2 bytes; vary the gap between it and the token so the 48-byte window edge
            // lands on every offset, including the middle of the multibyte char.
            let input = format!("xxxxxxé api key{} {}", "y".repeat(gap), token);
            let findings = scan_text(
                &input,
                ScanOptions {
                    aggressive: true,
                    ..ScanOptions::default()
                },
            );
            // The keyword sits within the 48-byte context window only while the gap is small.
            if gap <= 40 {
                assert!(findings.iter().any(|f| f.value == token), "gap={gap}");
            }
        }
        for emoji_pad in 0..8 {
            let input = format!(
                "{}{} secret {}",
                "🔐".repeat(emoji_pad),
                "z".repeat(41),
                token
            );
            let _ = scan_text(
                &input,
                ScanOptions {
                    aggressive: true,
                    ..ScanOptions::default()
                },
            );
        }
    }

    /// D20: inputs that made the scanner quadratic (measured 3.9 s and 570 ms for 256 KiB in a
    /// release build at `5f09d38`). Strict bound in release, loose bound in debug builds.
    #[test]
    fn worst_case_inputs_scan_in_linear_time() {
        let bound = if cfg!(debug_assertions) {
            std::time::Duration::from_millis(1500)
        } else {
            std::time::Duration::from_millis(10)
        };
        let cases = [
            ("token-no-sep", "token".repeat(256 * 1024 / 5)),
            ("begin-no-end", "-----BEGIN ".repeat(256 * 1024 / 11)),
            ("password-no-sep", "password".repeat(256 * 1024 / 8)),
            (
                "token-value-chain",
                format!("token={}", "token:".repeat(256 * 1024 / 6)),
            ),
        ];
        for (name, input) in cases {
            // Minimum of three runs: the bound is about algorithmic cost, not about whatever
            // else the test runner schedules on the same cores (the 1e6 fuzz runs in parallel).
            let took = (0..3)
                .map(|_| {
                    let t = std::time::Instant::now();
                    let _ = scan_text(&input, ScanOptions::default());
                    t.elapsed()
                })
                .min()
                .expect("three runs");
            assert!(took < bound, "{name}: {took:?} >= {bound:?}");
        }
    }

    /// GATE 1: random UTF-8 never panics the scanner (D2 class). Seeded and deterministic, so a
    /// failure reproduces. Inputs mix scanner keywords, separators, PEM markers and multibyte
    /// characters to reach the slicing paths far more often than uniform random text would.
    #[test]
    fn random_utf8_never_panics() {
        let iterations = if cfg!(debug_assertions) {
            100_000
        } else {
            1_000_000
        };
        let pieces: &[&str] = &[
            "a",
            "Z",
            "0",
            "9",
            "_",
            "-",
            "=",
            ":",
            " ",
            "\n",
            "\t",
            "\"",
            "'",
            "/",
            "+",
            ".",
            "é",
            "ß",
            "€",
            "𝔘",
            "🔐",
            "\u{200b}",
            "\u{0301}",
            "api",
            "key",
            "token",
            "secret",
            "password",
            "bearer ",
            "sk-proj-",
            "sk-ant-",
            "ghp_",
            "AKIA",
            "eyJ",
            "xoxb-",
            "-----BEGIN ",
            "-----END ",
            "PRIVATE KEY-----",
            "postgres://",
            "u:p@h",
            "lockrail://",
        ];
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..iterations {
            let len = (next() % 40) as usize;
            let mut input = String::new();
            for _ in 0..len {
                input.push_str(pieces[(next() % pieces.len() as u64) as usize]);
            }
            let aggressive = next() % 2 == 0;
            let _ = scan_text(
                &input,
                ScanOptions {
                    aggressive,
                    ..ScanOptions::default()
                },
            );
            let _ = seal_text(&input, SealOptions::default());
        }
    }

    #[test]
    fn pem_block_still_detected_after_bounding() {
        let body = "A".repeat(3000);
        let input =
            format!("x\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\ny");
        let findings = scan_text(&input, ScanOptions::default());
        assert!(findings.iter().any(|f| f.kind == "private-key-block"));
    }

    #[test]
    fn seals_known_secret_types() {
        let input =
            "Use sk-proj-abcdefghijklmnopqrstuvwxyz123456 and ghp_abcdefghijklmnopqrstuvwxyz123456";
        let sealed = seal_text(input, SealOptions::default());
        assert_eq!(sealed.findings.len(), 2);
        assert!(
            !sealed
                .safe_text
                .contains("sk-proj-abcdefghijklmnopqrstuvwxyz123456")
        );
        assert!(sealed.safe_text.contains("lockrail://secret/openai-key/"));
        assert!(sealed.safe_text.contains("lockrail://secret/github-token/"));
    }

    #[test]
    fn low_confidence_needs_aggressive_mode() {
        let input = "secret = abcdEFGH1234567890abcdEFGH1234567890";
        let scan = scan_text(input, ScanOptions::default());
        assert!(scan.iter().any(|f| f.confidence == SecretConfidence::Low));
        let sealed = seal_text(input, SealOptions::default());
        assert!(
            sealed
                .safe_text
                .contains("abcdEFGH1234567890abcdEFGH1234567890")
        );
        let aggressive = seal_text(
            input,
            SealOptions {
                aggressive: true,
                protection_mode: true,
            },
        );
        assert!(
            !aggressive
                .safe_text
                .contains("abcdEFGH1234567890abcdEFGH1234567890")
        );
    }

    #[test]
    fn redacts_private_key_and_jwt() {
        let input = "jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk key -----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----";
        let redacted = redact_for_logs(input);
        assert!(!redacted.contains("PRIVATE KEY"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    #[test]
    fn debug_output_redacts_secret_values() {
        let input = "Use sk-proj-abcdefghijklmnopqrstuvwxyz123456";
        let sealed = seal_text(input, SealOptions::default());
        let debug = format!("{sealed:?}");
        assert!(!debug.contains("sk-proj-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn detects_provider_and_generic_secret_samples() {
        // Phase 3C: the AWS documentation values (`...EXAMPLE`) are allowlisted now, so this
        // test uses synthetic AWS values built at runtime (see `aws_documentation_values_are_allowlisted`).
        let aws_id = ["AKIA", "Q7ZK3M9B2N4P6R8T"].concat();
        let aws_secret = ["w8Jr2LtNx", "Fq4/Kz7MdPb+", "Rc9YhVs3Gk1", "TmQe5Ua8"].concat();
        let input = format!(
            "{}{}{}aws_id={aws_id}\naws_secret_access_key={aws_secret}\n{}{}",
            "openai=sk-proj-abcdefghijklmnopqrstuvwxyz123456\n",
            "github=ghp_abcdefghijklmnopqrstuvwxyz123456\n",
            "slack=xoxb-LOCKRAILTEST-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX\n",
            "pem=-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----\n",
            "token = abcdEFGH1234567890abcdEFGH1234567890\n"
        );
        let input = input.as_str();

        let findings = scan_text(
            input,
            ScanOptions {
                aggressive: true,
                protection_mode: true,
            },
        );
        let kinds = findings
            .iter()
            .map(|finding| finding.kind.as_ref())
            .collect::<Vec<_>>();
        assert!(kinds.contains(&"openai-key"));
        assert!(kinds.contains(&"github-token"));
        assert!(kinds.contains(&"slack-bot-token"));
        assert!(kinds.contains(&"aws-access-key-id"));
        assert!(kinds.contains(&"aws-secret-access-key"));
        assert!(kinds.contains(&"private-key-block"));

        let jwt_findings = scan_text(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            ScanOptions {
                aggressive: true,
                protection_mode: true,
            },
        );
        assert!(jwt_findings.iter().any(|finding| finding.kind == "jwt"));

        let generic_findings = scan_text(
            "secret = abcdEFGH1234567890abcdEFGH1234567890",
            ScanOptions {
                aggressive: true,
                protection_mode: true,
            },
        );
        assert!(
            generic_findings
                .iter()
                .any(|finding| finding.kind == "high-entropy-token")
        );
    }

    #[test]
    fn report_only_match_never_shadows_a_sealing_finding() {
        // D22: `is_token_char` accepts '=', so the low-confidence entropy scanner can match
        // `OPENAI_API_KEY=sk-proj-...` as one span starting before the real key. When context
        // (an earlier "token"/"secret"/"key") satisfies it, the old overlap rule kept that earlier
        // report-only span and dropped the high-confidence key, so the raw key was not sealed.
        let key = ["sk-proj-", "aB3dE5fG7hJ9kL1m", "N3pQ5rS7tU9vW1xY"].concat();
        let options = SealOptions {
            aggressive: false,
            protection_mode: true,
        };
        for input in [
            format!("GITHUB_TOKEN=x\nOPENAI_API_KEY={key}"),
            format!("# secrets\nOPENAI_API_KEY={key}"),
            format!("my api key is OPENAI_KEY={key}"),
            format!("OPENAI_API_KEY={key}"),
        ] {
            let sealed = seal_text(&input, options);
            assert!(
                !sealed.safe_text.contains(&key),
                "raw key survived sealing of {input:?}"
            );
            assert!(
                sealed
                    .findings
                    .iter()
                    .any(|f| f.kind == "openai-key" && f.should_seal),
                "openai-key finding missing for {input:?}"
            );
        }
    }

    #[test]
    fn aws_documentation_values_are_allowlisted() {
        let input = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
        let sealed = seal_text(input, SealOptions::default());
        assert_eq!(sealed.safe_text, input, "documentation values were sealed");
        assert!(sealed.findings.is_empty());
    }

    #[test]
    fn new_secret_formats_are_sealed() {
        let legacy = [
            "sk-",
            "T3BlbkFJ",
            "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0",
        ]
        .concat();
        let twilio_sk = ["SK", "0123456789abcdef0123456789abcdef"].concat();
        let twilio_ac = ["AC", "fedcba9876543210fedcba9876543210"].concat();
        let twilio_token = ["9f8e7d6c5b4a", "39281706f5e4d3c2b1a0"].concat();
        let azure = [
            "AccountKey=",
            "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG9mcmVkcGx1Z3h5enp5",
            "Ymxhcmdsb3JwMTIzNDU2Nzg5MA==",
        ]
        .concat();
        let aws_id = ["ASIA", "Z9Y8X7W6V5U4T3S2"].concat();
        let aws_secret = ["k3Jd8Lq2Pz", "Xw7/Nc4Hv9Bm+", "T1rY6sGf0aE", "uQ5oWi"].concat();
        let slack_app = ["xapp-", "1-A0B1C2D3E4F-1234567890123-abcdef0123456789"].concat();
        let rk = ["rk_live_", "51HqLyjWDarjtT1zdp7dc", "Abc123Def456Ghi789"].concat();
        let cases = [
            format!("export OPENAI_KEY={legacy}"),
            format!("twilio: sid {twilio_ac} token {twilio_token} api {twilio_sk}"),
            format!(
                "DefaultEndpointsProtocol=https;AccountName=acct;{azure};EndpointSuffix=core.windows.net"
            ),
            format!("creds {aws_id} {aws_secret}"),
            format!("slack {slack_app}"),
            format!("stripe {rk}"),
        ];
        let secrets = [
            &legacy,
            &twilio_sk,
            &twilio_ac,
            &twilio_token,
            &aws_id,
            &aws_secret,
            &slack_app,
            &rk,
        ];
        for input in &cases {
            let sealed = seal_text(input, SealOptions::default());
            for secret in secrets {
                assert!(
                    !sealed.safe_text.contains(secret.as_str()),
                    "{secret} left in {input}"
                );
            }
            assert!(
                !sealed.safe_text.contains("Zm9vYmFyYmF6"),
                "azure key left in {input}"
            );
        }
    }

    #[test]
    fn base64_wrapped_secret_is_sealed_once_deep() {
        use base64ct::{Base64, Encoding};
        let secret = ["ghp_", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0Ed9Cb8"].concat();
        let wrapped = Base64::encode_string(format!("GITHUB_TOKEN={secret}").as_bytes());
        let manifest = format!("apiVersion: v1\nkind: Secret\ndata:\n  token: {wrapped}\n");
        let sealed = seal_text(&manifest, SealOptions::default());
        assert!(
            !sealed.safe_text.contains(&wrapped),
            "base64-wrapped secret survived"
        );
        assert!(
            sealed
                .findings
                .iter()
                .any(|f| f.kind == "base64-github-token")
        );
        // Ordinary base64 text is left alone.
        let benign = Base64::encode_string(b"hello world, this is ordinary configuration text");
        let sealed = seal_text(&format!("data: {benign}"), SealOptions::default());
        assert!(sealed.findings.is_empty(), "{:?}", sealed.findings);
    }

    #[test]
    fn placeholders_are_not_sealed() {
        for input in [
            "OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx",
            "token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ] {
            let sealed = seal_text(input, SealOptions::default());
            assert_eq!(sealed.safe_text, input);
        }
    }

    #[test]
    fn redacted_preview_matches_the_0_3_7_rule() {
        fn old(value: &str) -> String {
            let chars: Vec<char> = value.chars().collect();
            match chars.len() {
                0 => String::new(),
                1..=8 => "***".to_string(),
                len => format!(
                    "{}***{}",
                    chars[..4].iter().collect::<String>(),
                    chars[len - 4..].iter().collect::<String>()
                ),
            }
        }
        for v in [
            "",
            "a",
            "abcd",
            "abcde",
            "abcdefgh",
            "abcdefghi",
            "é漢字🙂abcdé漢字🙂",
            "sk-proj-abcdefghij",
            "é漢字🙂é漢字🙂é",
        ] {
            assert_eq!(redacted_preview(v), old(v), "{v:?}");
        }
    }

    #[test]
    fn prefix_automaton_matches_per_rule_scanning() {
        // Synthetic, built at runtime so no literal matches a secret-scanner rule.
        let aws_id = ["AKIA", "Q7ZK3M9B2N4P6R8T"].concat();
        // Random inputs dense in prefixes and token characters; the single Aho-Corasick pass
        // must produce exactly the findings of one `scan_prefixed` call per rule.
        let pieces: Vec<&str> = PREFIX_RULES
            .iter()
            .map(|r| r.0)
            .chain([
                "a",
                "Z",
                "9",
                "_",
                "-",
                ".",
                " ",
                "\n",
                "é",
                "=",
                aws_id.as_str(),
            ])
            .collect();
        let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
        let options = ScanOptions {
            aggressive: true,
            protection_mode: true,
        };
        for _ in 0..20_000 {
            let mut input = String::new();
            for _ in 0..(seed % 24) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                input.push_str(pieces[(seed % pieces.len() as u64) as usize]);
            }
            let mut fast = Vec::new();
            scan_prefix_rules(&input, &mut fast, options);
            let mut slow = Vec::new();
            for (prefix, kind, min_len, confidence) in PREFIX_RULES {
                scan_prefixed(
                    &input,
                    prefix,
                    kind,
                    *min_len,
                    *confidence,
                    &mut slow,
                    options,
                );
            }
            let key = |f: &SecretFinding| (f.start, f.end, f.kind.to_string());
            let mut a: Vec<_> = fast.iter().map(key).collect();
            let mut b: Vec<_> = slow.iter().map(key).collect();
            a.sort();
            b.sort();
            assert_eq!(a, b, "input {input:?}");
        }
    }

    #[test]
    fn code_on_the_right_of_an_assignment_is_not_a_secret() {
        for input in [
            "api_key = os.environ[\"API_KEY\"]",
            "token = get_token()",
            "password = config.db_password",
            "API_KEY=$OPENAI_API_KEY",
            "client_secret: ${CLIENT_SECRET}",
            "const token = process.env.GITHUB_TOKEN;",
        ] {
            let sealed = seal_text(input, SealOptions::default());
            assert_eq!(sealed.safe_text, input, "sealed code in {input:?}");
        }
        // A literal is still sealed.
        let literal = seal_text("password = Hunter2Hunter2!", SealOptions::default());
        assert!(!literal.safe_text.contains("Hunter2Hunter2"));
    }

    /// Deterministic mixed-case alphanumerics, built at runtime (no literal matches a rule).
    fn mix(n: usize) -> String {
        let a = b"aZ3kQ9mX7pL2vB8nR4tY6wE1sD5fG0hJ";
        (0..n).map(|i| a[(i * 7 + 3) % a.len()] as char).collect()
    }

    fn hexs(n: usize) -> String {
        let a = b"0123456789abcdef";
        (0..n).map(|i| a[(i * 5 + 1) % 16] as char).collect()
    }

    fn sealed(input: &str) -> String {
        seal_text(input, SealOptions::default()).safe_text
    }

    /// Teardown C (competitors/C-secret-scanners.md): keyword rules stopped at the first symbol,
    /// so `Summer2024!xyz` sealed only `Summer2024`, and quoted values with spaces or `@#$`
    /// sealed nothing.
    #[test]
    fn password_values_are_captured_whole() {
        let cases: [(&str, &str); 6] = [
            (
                "password = \"correct horse battery staple\"",
                "correct horse battery staple",
            ),
            ("\"password\": \"p@ss#w0rd$Secret9\"", "p@ss#w0rd$Secret9"),
            ("  password: Xk9!q@Z#7rTm", "Xk9!q@Z#7rTm"),
            ("DB_PASSWORD=Summer2024!xyz", "Summer2024!xyz"),
            ("password = 'ab\\'cd1234efgh'", "cd1234efgh"),
            ("Server=db;Uid=app;Pwd=Tr0ub4dor&3x;", "Tr0ub4dor"),
        ];
        for (input, secret) in cases {
            let out = sealed(input);
            assert!(!out.contains(secret), "{secret:?} left in {out:?}");
            assert!(out.contains("lockrail://secret/password/"), "{out:?}");
        }
        // The quotes stay; only the value is replaced.
        let out = sealed("password = \"correct horse battery staple\"");
        assert!(out.starts_with("password = \"lockrail://") && out.ends_with('"'));
        // `!xyz` is not left behind after the handle.
        assert!(!sealed("DB_PASSWORD=Summer2024!xyz").ends_with("!xyz"));
    }

    #[test]
    fn password_lookalikes_are_not_sealed() {
        for input in [
            "password: string;",
            "password: ${DB_PASS}",
            "password = \"<your password>\"",
            "password: \"{{ db_password }}\"",
            "password = getPassword(user)",
            "password: Optional[str] = None",
            "password is required here",
            "Password: ********",
            "password: [REDACTED]",
            "export OLDPWD=/Users/someone/projects/app",
            "cd /tmp && pwd && ls",
            "passwordless: true",
        ] {
            assert_eq!(sealed(input), input, "sealed {input:?}");
        }
    }

    /// Teardown C: only database and queue schemes were checked for `user:pass@`.
    #[test]
    fn url_credentials_of_any_scheme_are_sealed() {
        let pw = mix(16);
        let gh = ["gh", "p_"].concat() + &mix(36);
        let opaque = mix(40);
        for (input, secret) in [
            (
                format!("curl https://admin:{pw}@internal.example.net/api"),
                pw.clone(),
            ),
            (format!("ftp://deploy:{pw}@files.internal.net/"), pw.clone()),
            (
                format!("SMTP_URL=smtps://mailer:{pw}@smtp.internal.net:465"),
                pw.clone(),
            ),
            (format!("git clone https://{gh}@github.com/o/r.git"), gh),
            (
                format!("remote = https://{opaque}@git.example.com/o/r"),
                opaque,
            ),
        ] {
            let out = sealed(&input);
            assert!(!out.contains(&secret), "{secret} left in {out}");
        }
        // Only the password is replaced in a non-database URL, so the host stays readable.
        let out = sealed(&format!("curl https://admin:{pw}@internal.example.net/api"));
        assert!(out.contains("https://admin:lockrail://secret/url-credential/"));
        assert!(out.ends_with("@internal.example.net/api"), "{out}");
        // Database URLs keep the 0.3.7 behaviour: the whole URL is one handle.
        let db = format!("postgres://app:{pw}@db.internal:5432/app");
        let found = scan_text(&db, ScanOptions::default());
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].kind.as_ref(), found[0].start),
            ("database-url", 0)
        );
        for benign in [
            "see https://user:password@example.com for the format",
            "https://example.com:8443/path?q=1",
            "ssh://git@github.com/o/r.git",
            "https://user:${PASS}@host.example/x",
            "mailto:someone@example.com",
            "https://docs.example.com/@scope/package",
        ] {
            assert_eq!(sealed(benign), benign, "sealed {benign:?}");
        }
    }

    /// Teardown C top-15 formats. Values are synthetic and built at runtime.
    #[test]
    fn provider_formats_from_the_teardown_are_sealed() {
        let cases: Vec<(&str, String)> = vec![
            ("groq-key", ["gs", "k_"].concat() + &mix(52)),
            ("openrouter-key", ["sk-or", "-v1-"].concat() + &hexs(64)),
            ("xai-key", ["xa", "i-"].concat() + &mix(80)),
            ("vercel-token", ["vc", "p_"].concat() + &mix(56)),
            ("vercel-token", ["vc", "i_"].concat() + &mix(56)),
            (
                "cloudflare-token",
                ["cf", "ut_"].concat() + &mix(40) + &hexs(8),
            ),
            (
                "cloudflare-token",
                ["cf", "k_"].concat() + &mix(40) + &hexs(8),
            ),
            ("netlify-token", ["nf", "p_"].concat() + &mix(36)),
            ("docker-hub-token", ["dckr", "_pat_"].concat() + &mix(27)),
            ("linear-api-key", ["lin", "_api_"].concat() + &mix(40)),
            ("notion-token", ["nt", "n_"].concat() + &mix(46)),
            ("figma-token", ["fig", "d_"].concat() + &mix(40)),
            ("sentry-token", ["sntr", "yu_"].concat() + &hexs(64)),
            ("posthog-key", ["ph", "x_"].concat() + &mix(47)),
            (
                "supabase-secret-key",
                ["sb_se", "cret_"].concat() + &mix(31),
            ),
            ("neon-api-key", ["na", "pi_"].concat() + &mix(64)),
            ("gitlab-token", ["gl", "rt-"].concat() + &mix(20)),
            ("gitlab-token", ["gl", "dt-"].concat() + &mix(20)),
            ("gitlab-token", ["gl", "ptt-"].concat() + &hexs(40)),
            ("google-oauth-token", ["ya", "29."].concat() + &mix(120)),
            ("gemini-api-key", ["AQ.", "Ab8RN6"].concat() + &mix(44)),
            (
                "slack-webhook",
                format!(
                    "https://hooks.{}/services/T{}/B{}/{}",
                    "slack.com",
                    "A".repeat(8),
                    "B".repeat(8),
                    mix(24)
                ),
            ),
            (
                "discord-webhook",
                format!(
                    "https://{}/api/webhooks/{}/{}",
                    "discord.com",
                    "1".repeat(18),
                    mix(68)
                ),
            ),
            (
                "telegram-bot-token",
                format!("{}:{}", "1".repeat(9), ["A", "A"].concat() + &mix(33)),
            ),
            ("azure-client-secret", format!("abc8{}{}", "Q~", mix(34))),
            ("notion-token", ["sec", "ret_"].concat() + &mix(43)),
        ];
        for (kind, value) in cases {
            let input = format!("got {value} here");
            let found = scan_text(&input, ScanOptions::default());
            assert!(
                found.iter().any(|f| f.kind == kind && f.should_seal),
                "{kind} not found in {input}: {found:?}"
            );
            let tail = &value[value.len() - 12..];
            assert!(!sealed(&input).contains(tail), "{kind} tail left");
        }
    }

    #[test]
    fn new_prefixes_do_not_fire_on_identifiers() {
        for input in [
            "phx_click phx_value_id phx_submit",
            "uses the xai-sdk and vca_config",
            "ntn_test sb_secret_ref napi_version lin_api_url",
            "secret_key_base_for_development_environment_only_x",
            // A version-like `ya29.` decoy, built at runtime so scanners do not read it as a token.
            &["Duration ", "ya", "29.5 seconds"].concat(),
            "time 10:30:AM and 123456789:AB",
        ] {
            assert_eq!(sealed(input), input, "sealed {input:?}");
        }
    }

    #[test]
    fn basic_auth_and_docker_auths_are_sealed() {
        use base64ct::{Base64, Encoding};
        let pair = Base64::encode_string(format!("deploy:{}", mix(14)).as_bytes());
        for input in [
            format!("Authorization: Basic {pair}"),
            format!("{{\"auths\":{{\"ghcr.io\":{{\"auth\":\"{pair}\"}}}}}}"),
        ] {
            let out = sealed(&input);
            assert!(!out.contains(&pair), "{out}");
            assert!(out.contains("lockrail://secret/basic-auth/"), "{out}");
        }
        let pw = mix(14);
        let out = sealed(&format!("curl -u deploy:{pw} https://api.example.net"));
        assert!(!out.contains(&pw), "{out}");
        // Base64 that is not `user:pass` is left alone.
        let not_pair = Base64::encode_string(b"just some ordinary words here");
        let input = format!("Authorization: Basic {not_pair}");
        assert_eq!(sealed(&input), input);
        assert_eq!(sealed("curl -u $USER:$PASS x"), "curl -u $USER:$PASS x");
    }

    /// Teardown C: percent, `\u` and `\/` escapes and hex encoding each hid a secret.
    #[test]
    fn escaped_and_hex_encoded_secrets_are_sealed() {
        let gh = ["gh", "p_"].concat() + &mix(36);
        let percent = gh.replace('_', "%5F");
        let out = sealed(&format!("url?token={percent}&x=1"));
        assert!(!out.contains(&percent[8..]), "{out}");
        let unicode = format!("\"key\": \"sk\\u002dproj-{}\"", mix(40));
        let out = sealed(&unicode);
        assert!(!out.contains(&mix(40)), "{out}");
        let aws_id = ["AKIA", "Q7ZK3M9B2N4P6R8T"].concat();
        let (a, b) = (mix(19), mix(20));
        let json = format!("{{\"AccessKeyId\":\"{aws_id}\",\"SecretAccessKey\":\"{a}\\/{b}\"}}");
        let out = sealed(&json);
        assert!(!out.contains(&a) && !out.contains(&b), "{out}");
        let hex: String = gh.bytes().map(|b| format!("{b:02x}")).collect();
        let out = sealed(&format!("blob {hex}"));
        assert!(!out.contains(&hex), "{out}");
        // Findings map back to the original text: the escaped span itself is replaced.
        let found = scan_text(&format!("url?token={percent}&x=1"), ScanOptions::default());
        assert!(found.iter().any(|f| f.value == percent), "{found:?}");
        // Ordinary escapes and hashes are left alone.
        for benign in [
            "https://example.com/search?q=hello%20world&lang=en".to_string(),
            "{\"path\":\"a\\/b\\/c\",\"name\":\"caf\\u00e9\"}".to_string(),
            format!("sha256 {}", hexs(64)),
            "commit 9fceb02d0ae598e95dc970b74767f19372d61af8".to_string(),
        ] {
            assert_eq!(sealed(&benign), benign, "sealed {benign:?}");
        }
    }

    /// False-positive classes found on the spent v3 corpus (11 of 11 were these three): a value
    /// search that crossed a newline, an all-uppercase-`X` mask, and a CLI flag as the value.
    #[test]
    fn placeholder_and_layout_false_positive_classes() {
        for input in [
            "ANTHROPIC_API_KEY=\nGITHUB_TOKEN=<token>\n",
            "  - name: OPENAI_API_KEY\n    valueFrom:\n      secretKeyRef:\n",
            "SLACK_BOT_TOKEN=xoxb-your-token-here\nSENDGRID_API_KEY=SG.xxxxx\n",
            &["AWS_ACCESS_KEY_ID=", "AKIA", "XXXXXXXXXXXXXXXX"].concat(),
            &["KEY=", "sk-ant-", "api03-", &"X".repeat(24)].concat(),
            "deploy --key YOUR_API_KEY --region <region>",
        ] {
            assert_eq!(sealed(input), input, "sealed {input:?}");
        }
        // Still sealed: a value on the same line, a real key with a few X's, a value after `=`.
        let real = ["sk-ant-", "api03-", &mix(40), "XXXX"].concat();
        assert!(!sealed(&format!("KEY={real}")).contains(&mix(40)));
        let pw = mix(16);
        assert!(!sealed(&format!("API_KEY = {pw}\nNEXT=1")).contains(&pw));
        assert!(!sealed(&format!("token: {pw}")).contains(&pw));
    }

    /// Classes from the spent v1/v2 corpora: placeholder words after a prefix (D), PEM blocks
    /// with no key material (E), an env var name followed by a command argument or an HTML
    /// attribute name (F), and Lockrail's own handles sealed again (G).
    #[test]
    fn second_round_false_positive_classes() {
        let pem = |label: &str, body: &str| {
            format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----")
        };
        for input in [
            ["SLACK_BOT_TOKEN=", "xoxb-", "your-bot-token"].concat(),
            ["ANTHROPIC_API_KEY=", "sk-ant-", "api03-REPLACE_ME"].concat(),
            ["ANTHROPIC_API_KEY=", "sk-ant-", "api03-..."].concat(),
            ["OPENAI_API_KEY=", "sk-proj-"].concat(),
            pem("PRIVATE KEY", "..."),
            pem("RSA PRIVATE KEY", "<your key here>"),
            pem("PRIVATE KEY", "[redacted 1704 bytes]"),
            "vercel env add DATABASE_URL production".to_string(),
            "vercel env rm NPM_TOKEN production".to_string(),
            "docker run -e OPENAI_API_KEY -e GITHUB_TOKEN app:latest".to_string(),
            "<input type=\"password\" name=\"password\" autocomplete=\"current-password\">"
                .to_string(),
            "Authorization: Bearer lockrail://secret/stripe-key/h_74f6497a".to_string(),
            "token = lockrail://secret/npm-token/h_f571d42a0b1c2d3e".to_string(),
        ] {
            assert_eq!(sealed(&input), input, "sealed {input:?}");
        }
        // Still sealed: a real PEM body, a lowercase `token <value>`, a real Slack token.
        let body = mix(64);
        assert!(!sealed(&pem("PRIVATE KEY", &body)).contains(&body));
        let v = mix(24);
        assert!(!sealed(&format!("token {v}")).contains(&v));
        let slack = ["xoxb-", "1234567890-", &mix(24)].concat();
        assert!(!sealed(&format!("SLACK_BOT_TOKEN={slack}")).contains(&mix(24)));
    }

    /// Real-transcript classes (sweep of local AI transcripts, values seen only as shapes): prose
    /// after `token`/`password` with no `=`/`:` (H), and an empty quoted value that started a
    /// quoted capture running into the following code (I).
    #[test]
    fn prose_and_empty_quoted_values_are_not_secrets() {
        for input in [
            "Set the refresh token lifetime to 30 minutes",
            "an attacker can brute-force valid passwords here",
            "MCP, agents, caching, token counting and streaming",
            "Reset staff password functionality",
            "the CSRF token mechanism",
            "const pw = typeof body.password === 'string' ? body.password : '';\n  if (!pw) {\n    return Response.json({ error: 'missing' });",
            "{\"cmd\":\"x = body.password : '';\\n  if (!x) { return 'nope' }\"}",
        ] {
            assert_eq!(sealed(input), input, "sealed {input:?}");
        }
        // Still sealed: a secret-shaped value after a bare keyword, and explicit assignments.
        let v = mix(24);
        assert!(!sealed(&format!("token {v}")).contains(&v));
        assert!(!sealed("password Hunter2Hunter2!").contains("Hunter2Hunter2"));
        assert!(!sealed("password: requirements1").contains("requirements1"));
        assert!(!sealed("password = 'correct horse battery'").contains("correct horse"));
    }

    /// Second sweep round: counts and plurals (J), the keyword inside a file name or identifier
    /// (K, N), word values for token/key fields (L), and JSON escapes ending an unquoted value.
    #[test]
    fn identifiers_counts_and_words_are_not_secrets() {
        for input in [
            "{\"thinkingTokens\":35961,\"cacheReadInputTokens\":81234567}",
            "token: 12345678",
            "see KM-IS-STD-01-password-and-mfa-standard.docx KM-IS-STD-02-access-review.docx",
            "src/lib/server/tool-lifecycle/ack-token.ts: 12 matches",
            "const TOKEN_KEY = 'auth:token:';",
            "forceChangePasswordNextSignIn := msgraph.Bool(true)",
            "const passwordHash = await hash(input)",
            "api_key: placeholdervalue",
        ] {
            assert_eq!(sealed(input), input, "sealed {input:?}");
        }
        // An unquoted value stops at a JSON escape (`\n`) instead of running on.
        let out = sealed("{\"cmd\":\"DB_PASSWORD=Summer2024!xyz\\nNEXT=1\"}");
        assert!(!out.contains("Summer2024"), "{out}");
        assert!(out.contains("\\nNEXT=1"), "{out}");
        // Still sealed.
        let v = mix(24);
        assert!(!sealed(&format!("access_token: {v}")).contains(&v));
        assert!(
            !sealed("password: 12345678").contains("12345678"),
            "numeric passwords"
        );
        assert!(!sealed(&format!("GITHUB_TOKEN {v}")).contains(&v));
        assert!(!sealed(&format!("const apiKey = \"{v}\";")).contains(&v));
    }

    /// Security review finding 4: a placeholder-looking suffix on a real token exempted it.
    #[test]
    fn placeholder_suffix_does_not_exempt_a_real_token() {
        let real = ["gh", "p_"].concat() + &mix(36);
        for suffix in [
            ".".repeat(40),
            ":EXAMPLE".to_string(),
            "-your_key".to_string(),
            "_todo_here".to_string(),
        ] {
            let input = format!("out {real}{suffix} end");
            assert!(
                !sealed(&input).contains(&mix(36)),
                "{suffix:?} exempted a real token"
            );
        }
        // Documented AWS example values stay allowlisted.
        let doc = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
        assert_eq!(sealed(&format!("id {doc}")), format!("id {doc}"));
    }

    #[test]
    fn assignment_automaton_matches_per_key_scanning() {
        let value = mix(20);
        let pieces: Vec<String> = ASSIGNMENT_KEYS
            .iter()
            .map(|k| k.0.to_string())
            .chain(ASSIGNMENT_KEYS.iter().map(|k| k.0.to_ascii_uppercase()))
            .chain(
                [
                    "=", ": ", " ", "\"", "'", "\n", "_", "-", "Pass", "s", "x9", "é", "--", "$",
                    "(", "\\n", ";", "&", "word", "12345678",
                ]
                .map(String::from),
            )
            .chain([
                value.clone(),
                format!("\"{value}\""),
                "Summer2024!xyz".to_string(),
            ])
            .collect();
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..20_000 {
            let mut input = String::new();
            for _ in 0..(seed % 20) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                input.push_str(&pieces[(seed % pieces.len() as u64) as usize]);
            }
            let options = ScanOptions::default();
            let mut fast = Vec::new();
            scan_assignment(&input, &mut fast, options);
            let mut slow = Vec::new();
            scan_assignment_per_key(&input, &mut slow, options);
            let key = |f: &SecretFinding| (f.start, f.end, f.kind.to_string(), f.value.clone());
            let a: Vec<_> = fast.iter().map(key).collect();
            let b: Vec<_> = slow.iter().map(key).collect();
            assert_eq!(a, b, "input {input:?}");
        }
        // A small alphabet, so keys inside earlier values (`token=token=<value>`), repeated
        // keys and the skip rule are exercised on most inputs, not by chance.
        let small: Vec<String> = [
            "token", "TOKEN", "password", "pwd", "api_key", "=", ": ", " ", "\"",
        ]
        .map(String::from)
        .into_iter()
        .chain([value, "ab!9".to_string()])
        .collect();
        for _ in 0..20_000 {
            let mut input = String::new();
            for _ in 0..(seed % 12) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                input.push_str(&small[(seed % small.len() as u64) as usize]);
            }
            let options = ScanOptions::default();
            let mut fast = Vec::new();
            scan_assignment(&input, &mut fast, options);
            let mut slow = Vec::new();
            scan_assignment_per_key(&input, &mut slow, options);
            let key = |f: &SecretFinding| (f.start, f.end, f.kind.to_string(), f.value.clone());
            let a: Vec<_> = fast.iter().map(key).collect();
            let b: Vec<_> = slow.iter().map(key).collect();
            assert_eq!(a, b, "input {input:?}");
        }
    }

    /// Hostile review: real passwords were exempted by placeholder rules meant for `example_key`
    /// and `sk-proj-`: a trailing `_`, or a placeholder word glued to more text.
    #[test]
    fn real_passwords_that_start_like_placeholder_words_are_sealed() {
        for pw in [
            ["Hunter2", "!xyz9_"].concat(),
            ["dummy", "P@ss99"].concat(),
            ["todo", "ist-Pa55w0rd!"].concat(),
            ["Example", "#2024!pw"].concat(),
        ] {
            let out = sealed(&format!("DB_PASSWORD={pw}"));
            assert!(!out.contains(&pw), "{pw} left in {out}");
        }
        for placeholder in [
            "DB_PASSWORD=example_password",
            "API_KEY=your-api-key-here",
            "TOKEN=dummy_token_value",
            "OPENAI_API_KEY=sk-proj-",
        ] {
            assert_eq!(sealed(placeholder), placeholder, "sealed {placeholder}");
        }
    }

    #[test]
    fn prefixes_inside_base64_are_not_secrets() {
        let blob = [
            "gAAAAABz9Kq",
            "hf_",
            "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1",
            "AKIA",
            "Q7ZK3M9B2N4P6R8T",
            "xyz",
        ]
        .concat();
        let sealed = seal_text(&blob, SealOptions::default());
        assert_eq!(sealed.safe_text, blob, "{:?}", sealed.findings);
        let real = ["token: ", "hf_", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1"].concat();
        assert!(
            !seal_text(&real, SealOptions::default())
                .safe_text
                .contains("hf_Zx9")
        );
    }
}
